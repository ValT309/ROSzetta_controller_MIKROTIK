"""Persistent admin-only management tasks; called under the existing queue advisory lock."""
from datetime import datetime, timezone, timedelta
from typing import Literal, Any
import ipaddress
import re
import time
import ssl
import socket
import hashlib
import hmac
from fastapi import APIRouter, Depends, HTTPException, Body
from pydantic import BaseModel, Field
from sqlalchemy import Integer, String, DateTime, JSON, Text, select, text
from sqlalchemy.orm import Mapped, mapped_column, Session
from ..core.db import Base, SessionLocal, get_db, engine
from ..api.deps import require_role, get_current_user
from ..models.device import Device
from ..models.user import User
from .vault import vault_service
from .routeros import management as mg
from . import account_jobs as accounts
from . import time_management as tm

router = APIRouter(prefix='/stage2')
admin = require_role('admin')
CONNECTION_ACTIONS = {'connection-check','connection-save'}
SECRET_ACTIONS = accounts.ACTIONS | CONNECTION_ACTIONS
ACL_ACTIONS = {'acl-allow-ssh':'ssh','acl-allow-api':'api','acl-allow-tls':'api-ssl'}
READ = {'connection-check','rights','services','ssh-scan','tls-scan','sftp','audit','ssl-status','group-preview','group-list','user-groups','time-audit'}
APPROVAL = {'rights-apply':'rights','ssh-trust':'ssh-scan','tls-switch':'tls-scan','group-apply':'group-preview'}

class Blocked(ValueError):
    """A fixed precondition failure before any remote write."""

class Unconfirmed(ValueError):
    """Fixed diagnostic after a possibly applied operation; never raw API errors."""

class ManagementJob(Base):
    __tablename__ = 'device_management_jobs_v2'
    id: Mapped[int] = mapped_column(primary_key=True)
    owner: Mapped[int] = mapped_column(Integer)
    action: Mapped[str] = mapped_column(String(24))
    state: Mapped[str] = mapped_column(String(20),index=True)
    created: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String(64))
    entries: Mapped[list] = mapped_column(JSON)

class AccountJobSecret(Base):
    # Kept outside history and API response; removed when job becomes terminal.
    __tablename__ = 'device_account_job_secrets_v086'
    job_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token: Mapped[str] = mapped_column(Text)
    expires: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class SSLStatus(Base):
    __tablename__ = 'device_ssl_status_v21'
    device_id: Mapped[int] = mapped_column(Integer,primary_key=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),index=True)
    data: Mapped[dict] = mapped_column(JSON)


class Request(BaseModel):
    action: Literal['rights','services','ssh','ssh-scan','ssh-trust','sftp','audit','rights-apply','tls-prepare','tls-scan','tls-switch','ssl-status','group-preview','group-apply','group-list','tls-repair','time-audit','ntp-apply','tls-renew','acl-allow-ssh','acl-allow-api','acl-allow-tls']
    ids: list[int] = Field(min_length=1,max_length=200)
    source: str = Field(default='10.110.0.109/32',max_length=64)
    preview_job: int | None = None
    confirmed: bool = False
    ntp_servers: list[str] = Field(default_factory=list,max_length=4)
    time_zone: str = Field(default='',max_length=80)
    group_name: str = Field(default='',max_length=32)
    group_mode: Literal['create','upsert','add','remove','replace','delete','move'] = 'create'
    group_user: str = Field(default='',max_length=32)
    group_policies: list[str] = Field(default_factory=list,max_length=17)


def policy_tokens(raw):
    return sorted({str(p).strip() for p in (raw if isinstance(raw,(list,tuple)) else str(raw).split(',')) if str(p).strip()})


def account_snapshot(api, username):
    users = list(api.path('user'))
    accounts = [r for r in users if r.get('name') == username]
    if len(accounts)!=1: raise Blocked('Локальная учётная запись не найдена')
    a=accounts[0]; group=a.get('group')
    groups=[r for r in api.path('user','group') if r.get('name')==group]
    if len(groups)!=1 or groups[0].get('policy') is None or not groups[0].get('.id'):
        raise Blocked('Группа не определена')
    g=groups[0]; policies=policy_tokens(g['policy'])
    # Group membership may also be assigned via RADIUS. Fail closed on unknown AAA.
    try:
        aaa=list(api.path('user','aaa'))
        local_only=len(aaa)==1 and str(aaa[0].get('use-radius','')).lower() in ('false','no','0')
    except Exception:
        local_only=False
    return dict(username=username,group=group,group_id=g['.id'],policies=policies,
                missing=[p for p in ('ssh','ftp') if p not in policies],
                base_missing=[p for p in ('read','write','api') if p not in policies],
                disabled=mg.truth(a.get('disabled')), address=str(a.get('address') or ''), local_only=local_only,
                members=sorted(str(r.get('name')) for r in users if r.get('group')==group))


def desired_policies(s,source=None):
    if s['disabled'] or s['base_missing'] or s['group'] in ('full','read','write'):
        raise Blocked('Встроенная группа, отключённая запись или отсутствуют базовые права; требуется ручная проверка')
    if not s['local_only']:
        raise Blocked('RADIUS включён или не удалось подтвердить AAA; изменение группы только вручную')
    # Restrict automatic grants to dedicated single-member local groups; RADIUS/shared groups require manual review.
    if s['members'] != [s['username']]:
        raise Blocked('Группа общая: права других пользователей автоматически не меняются')
    try:
        allowed=[ipaddress.ip_network(a.strip(),strict=False) for a in s['address'].split(',') if a.strip()]
    except ValueError:
        raise Blocked('Не удалось разобрать ограничение адресов пользователя')
    if not allowed or any(n.prefixlen==0 for n in allowed):
        raise Blocked('Учётная запись без ограничения адресов; требуется ручная проверка')
    if source:
        ip=ipaddress.ip_network(source,strict=True).network_address
        if not any(ip.version==n.version and ip in n for n in allowed):
            raise Blocked('IP контроллера не входит в разрешённые адреса пользователя')
    # RouterOS expresses disabled flags as !policy on print; set only positive allowed flags.
    return sorted({p for p in s['policies'] if not p.startswith('!')} | set(s['missing']))


def apply_rights(api, username, expected, source=None):
    current=account_snapshot(api,username)
    if current!=expected: raise Blocked('Права или состав группы изменились; повторите проверку')
    desired=desired_policies(current,source)
    if current['missing']:
        try:
            list(api.path('user','group')('set',**{'.id':current['group_id'],'policy':','.join(desired)}))
        except Exception as exc:
            raise Unconfirmed('Не удалось подтвердить запись прав группы; проверьте policy и фактические разрешения') from exc
    after=account_snapshot(api,username)
    # RouterOS may represent absent permissions as explicit negations.
    if {p for p in after['policies'] if not p.startswith('!')}!={p for p in desired if not p.startswith('!')} or after['group_id']!=current['group_id'] or after['members']!=current['members'] or after['address']!=current['address'] or after['disabled']!=current['disabled']:
        raise Unconfirmed('Изменение прав не подтверждено; проверьте группу вручную')
    return after


def same_endpoint(e,d):
    return (e['host'],e['username'],e['port'],e['tls'],e['pin'])==(d.host,d.username,d.port,d.use_tls,d.tls_fingerprint)


def out(j):
    return dict(id=j.id,action=j.action,state=j.state,created=j.created,source=j.source,entries=[{k:v for k,v in e.items() if k!='credential_revision'} for e in j.entries])

@router.get('/jobs')
def jobs(db:Session=Depends(get_db),user:User=Depends(admin)):
    return [out(j) for j in db.query(ManagementJob).order_by(ManagementJob.id.desc()).limit(50)]

def preparation_entry(job, device_id):
    return next((e for e in job.entries if e['id']==device_id), None)


def preparation_active(job, entry):
    return bool(entry and (entry['state']=='running' or
                (entry['state']=='pending' and job.state in ('queued','running'))))


def active_preparations(db):
    return db.query(ManagementJob).filter(ManagementJob.action.in_(['tls-prepare','tls-repair','tls-renew']),
        ManagementJob.state.in_(['queued','running','stopped'])).order_by(ManagementJob.id.desc())


@router.get('/tls-preparation/{device_id}')
def tls_preparation_status(device_id:int,db:Session=Depends(get_db),user:User=Depends(require_role('admin','operator'))):
    if not db.get(Device,device_id): raise HTTPException(404,'Устройство не найдено')
    def summary(job, entry):
        return dict(id=job.id,state=entry['state'],job_state=job.state,
                    active=preparation_active(job,entry),detail=entry.get('detail',''))
    for job in active_preparations(db).yield_per(50):
        entry=preparation_entry(job,device_id)
        if preparation_active(job,entry): return summary(job,entry)
    for job in db.query(ManagementJob).filter(ManagementJob.action.in_(['tls-prepare','tls-repair','tls-renew'])).order_by(ManagementJob.id.desc()).yield_per(50):
        entry=preparation_entry(job,device_id)
        if entry: return summary(job,entry)
    return None


@router.get('/ssl-status')
def ssl_statuses(db:Session=Depends(get_db),user:User=Depends(get_current_user)):
    devices={d.id:d for d in db.query(Device).all()}
    result={}
    for row in db.query(SSLStatus).all():
        d=devices.get(row.device_id)
        if not d: continue
        data=dict(row.data); checked=row.checked_at.replace(tzinfo=timezone.utc) if row.checked_at.tzinfo is None else row.checked_at
        if data.get('endpoint')!=[d.host,d.port,d.use_tls,d.tls_fingerprint] or datetime.now(timezone.utc)-checked>timedelta(hours=24):
            data['status']='unknown';data['detail']='Сведения устарели или подключение изменилось'
        data.pop('endpoint',None);data.pop('notified',None);data.pop('notified_fp',None)
        result[str(row.device_id)]={**data,'checked_at':checked.isoformat()}
    return result


@router.post('/jobs')
def create(p:Request,db:Session=Depends(get_db),user:User=Depends(admin)):
    if engine.dialect.name!='postgresql': raise HTTPException(409,'Очередь требует PostgreSQL')
    if p.action not in READ and not p.confirmed: raise HTTPException(422,'Подтвердите изменение')
    try:
        ip=ipaddress.ip_network(p.source,strict=True)
        if ip.version!=4 or ip.prefixlen!=32 or ip.network_address.is_unspecified: raise ValueError()
    except ValueError: raise HTTPException(422,'Укажите IPv4 контроллера /32')
    ids=list(dict.fromkeys(p.ids)); devices={d.id:d for d in db.query(Device).filter(Device.id.in_(ids)).all()}
    if len(devices)!=len(ids): raise HTTPException(404,'Устройство не найдено')
    if p.action=='tls-renew' and len(ids)!=1: raise HTTPException(422,'Перевыпуск выполняется индивидуально')
    if p.action=='ntp-apply':
        db.execute(text('SELECT pg_advisory_xact_lock(7460931)'))
        for active in db.query(ManagementJob).filter(ManagementJob.action=='ntp-apply',ManagementJob.state.in_(['queued','running','stopped'])):
            if any(e['id'] in ids and (e['state']=='running' or (active.state in ('queued','running') and e['state']=='pending')) for e in active.entries):
                raise HTTPException(409,'Для устройства уже выполняется настройка NTP')
    if p.action in ('tls-prepare','tls-repair','tls-renew'):
        # Serialize enqueue checks across web workers; separate from the worker lock.
        if db.get_bind().dialect.name=='postgresql':
            db.execute(text('SELECT pg_advisory_xact_lock(7460931)'))
        # Prevent duplicate submissions from the device card and mass operations.
        for active in active_preparations(db).yield_per(50):
            if any(preparation_active(active,preparation_entry(active,i)) for i in ids):
                raise HTTPException(409,'Для выбранного устройства уже выполняется подготовка TLS; обновите состояние очереди')
    previews={}
    if p.action in APPROVAL:
        prev=db.get(ManagementJob,p.preview_job) if p.preview_job else None
        if not prev or prev.action!=APPROVAL[p.action] or prev.state not in ('done','failed','stopped','interrupted'):
            raise HTTPException(409,'Сначала выполните соответствующую проверку')
        previews={e['id']:e for e in prev.entries if e['state']=='done' and e.get('result')}
    spec = group_spec(p.group_name,p.group_policies,p.group_mode,p.group_user) if p.action=='group-preview' else None
    if p.action=='ntp-apply':
        try: spec=tm.validate(p.ntp_servers,p.time_zone)
        except tm.TimeBlocked as exc: raise HTTPException(422,str(exc)) from exc
    entries=[]
    for i in ids:
        d=devices[i]; e=dict(id=i,name=d.identity or d.name,host=d.host,username=d.username,port=d.port,tls=d.use_tls,pin=d.tls_fingerprint,state='pending')
        if p.action in APPROVAL:
            prior=previews.get(i)
            if not prior or not same_endpoint(prior,d) or not prior['result'].get('eligible'):
                raise HTTPException(409,'Устройство не готово к подтверждению; повторите проверку')
            e['expected']=prior['result']
        if spec is not None: e['expected']=spec
        entries.append(e)
    j=ManagementJob(owner=user.id,action=p.action,state='queued',created=datetime.now(timezone.utc),source=str(ip),entries=entries)
    db.add(j);db.commit();db.refresh(j);return out(j)

def clear_account_secret(db, job_id):
    secret = db.get(AccountJobSecret, job_id)
    if secret is not None:
        db.delete(secret)


def expire_account_secrets(db):
    now = datetime.now(timezone.utc)
    for secret in db.query(AccountJobSecret).all():
        j = db.get(ManagementJob, secret.job_id)
        expiry = secret.expires.replace(tzinfo=timezone.utc) if secret.expires.tzinfo is None else secret.expires
        if not j or j.state not in ('queued','running'):
            db.delete(secret)
        elif expiry <= now:
            j.entries = [dict(e, state='failed', detail='Срок хранения пароля истёк; запустите новую задачу с новым вводом пароля') if e['state']=='pending' else e for e in j.entries]
            j.state = 'failed'
            db.delete(secret)


@router.post('/user-jobs')
def create_account_job(body: Any=Body(...), db:Session=Depends(get_db), user:User=Depends(admin)):
    if engine.dialect.name!='postgresql': raise HTTPException(409,'Очередь требует PostgreSQL')
    try:
        action,ids,spec,password,allow_plain=accounts.normalize_request(body)
    except accounts.AccountBlocked as exc:
        raise HTTPException(422,str(exc)) from None
    devices={d.id:d for d in db.query(Device).filter(Device.id.in_(ids)).all()}
    if len(devices)!=len(ids): raise HTTPException(404,'Устройство не найдено')
    if password and any(not d.use_tls for d in devices.values()) and not allow_plain:
        raise HTTPException(422,'Подтвердите передачу пароля по обычному API без TLS')
    db.execute(text('SELECT pg_advisory_xact_lock(7460931)'))
    # The client supplies an idempotency key for ambiguous HTTP responses.
    request_id=body.get('request_id')
    if not isinstance(request_id,str) or not re.fullmatch(r'[A-Za-z0-9-]{16,64}',request_id):
        raise HTTPException(422,'Не указан идентификатор запроса; обновите страницу')
    for old in db.query(ManagementJob).filter(ManagementJob.owner==user.id,ManagementJob.action.in_(accounts.ACTIONS)).order_by(ManagementJob.id.desc()).limit(200):
        if old.entries and old.entries[0].get('request_id')==request_id:
            if old.action!=action or {e['id'] for e in old.entries}!=set(ids) or old.entries[0].get('account')!=spec:
                raise HTTPException(409,'Идентификатор запроса уже использован')
            return out(old)
    retry=body.get('retry_job')
    if retry is not None:
        previous=db.get(ManagementJob,retry) if type(retry) is int else None
        if not previous or previous.action!=action or previous.state in ('queued','running') or any(e['state']=='running' for e in previous.entries):
            raise HTTPException(409,'Исходная задача ещё не завершена или не найдена')
        permitted={e['id'] for e in previous.entries if e['id'] in devices and e['state'] in ('failed','pending') and e.get('account')==spec and same_endpoint(e,devices[e['id']])}
        if not set(ids)<=permitted: raise HTTPException(409,'Повтор возможен только для непроверенных или неисполненных строк с прежними параметрами подключения')
    for old in db.query(ManagementJob).filter(ManagementJob.action.in_(accounts.ACTIONS),ManagementJob.state.in_(['queued','running','stopped'])):
        if any(e['id'] in devices and (e['state']=='running' or (old.state in ('queued','running') and e['state']=='pending')) and (action=='user-groups' or old.action=='user-groups' or e.get('account',{}).get('username')==spec.get('username')) for e in old.entries):
            raise HTTPException(409,'Для выбранных устройств уже выполняется операция с этим пользователем или группами; откройте центр задач')
    token=vault_service.encrypt_secret(password) if password else None
    now=datetime.now(timezone.utc)
    entries=[dict(id=d.id,name=d.identity or d.name,host=d.host,username=d.username,port=d.port,tls=d.use_tls,pin=d.tls_fingerprint,state='pending',account=spec,request_id=request_id,allow_plain=allow_plain) for d in (devices[i] for i in ids)]
    j=ManagementJob(owner=user.id,action=action,state='queued',created=now,source='',entries=entries)
    db.add(j); db.flush()
    if token: db.add(AccountJobSecret(job_id=j.id,token=token,expires=now+timedelta(hours=24)))
    db.commit();db.refresh(j)
    return out(j)


def execute_account_job(db,d,user,action,entry,job_id):
    from ..api.v1 import devices as v
    from .routeros.client import routeros_session
    from ..models.device_management import DeviceManagementEvent
    if d.use_tls and not d.tls_fingerprint: raise Blocked('TLS без закреплённого отпечатка')
    password=''
    if action in ('user-add','user-password'):
        if not d.use_tls and not entry.get('allow_plain'): raise Blocked('Передача пароля без TLS не подтверждена')
        secret=db.get(AccountJobSecret,job_id)
        if not secret: raise Blocked('Пароль недоступен; создайте новую задачу')
        expiry=secret.expires.replace(tzinfo=timezone.utc) if secret.expires.tzinfo is None else secret.expires
        if expiry <= datetime.now(timezone.utc): raise Blocked('Срок хранения пароля истёк; введите его повторно')
        try: password=vault_service.decrypt_secret_v2(secret.token)
        except Exception: raise Blocked('Пароль задачи недоступен; введите его повторно') from None
    try:
        creds=v._creds(d)
        with routeros_session(creds) as api:
            matches=bool(password and entry['account'].get('username')==d.username and hmac.compare_digest(password.encode('utf-8'),creds.password.encode('utf-8')))
            result=accounts.user_operation(api,action,d.username,entry['account'],password,matches)
    except accounts.AccountBlocked as exc: raise Blocked(str(exc)) from None
    except accounts.AccountUnconfirmed as exc: raise Unconfirmed(str(exc)) from None
    except Exception: raise Blocked('Не удалось подключиться или прочитать пользователей/группы; проверьте доступ и права API') from None
    finally: password=''
    if action!='user-groups' and result.get('account_status')!='skipped':
        db.add(DeviceManagementEvent(device_id=d.id,actor=user.email,action=action,detail=f"{entry['account']['username']}: {result['detail']}"));db.commit()
    return result


class ConnectionRequest(BaseModel):
    ids: list[int] = Field(min_length=1,max_length=200)
    username: str = Field(min_length=1,max_length=32)
    password: str = Field(min_length=1,max_length=128)
    transport: Literal['keep','api','api-ssl'] = 'keep'
    apply: bool = False
    confirmed: bool = False
    allow_plain: bool = False
    request_id: str = Field(min_length=16,max_length=64)


def connection_target(d, transport):
    if transport=='keep': port,tls=d.port,d.use_tls
    elif transport=='api-ssl': port,tls=(d.port if d.use_tls else 8729),True
    else: port,tls=(d.port if not d.use_tls else 8728),False
    if (d.use_tls or d.tls_fingerprint) and (not tls or port!=d.port):
        raise Blocked('Защищённое подключение нельзя заменить обычным API')
    if tls and (not d.use_tls or not d.tls_fingerprint):
        raise Blocked('Сначала независимо сверьте TLS-отпечаток и переключите устройство через мастер API-SSL')
    return port,tls


@router.post('/connection-jobs')
def create_connection_job(body:Any=Body(...),db:Session=Depends(get_db),user:User=Depends(admin)):
    # Do not echo Pydantic input values in a validation error containing a password.
    try: p=ConnectionRequest.model_validate(body)
    except Exception: raise HTTPException(422,'Недопустимые параметры подключения') from None
    if engine.dialect.name!='postgresql': raise HTTPException(409,'Очередь требует PostgreSQL')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,32}',p.username) or any(ord(c)<32 for c in p.password) or not re.fullmatch(r'[A-Za-z0-9-]{16,64}',p.request_id): raise HTTPException(422,'Недопустимые параметры подключения')
    if p.apply and not p.confirmed: raise HTTPException(422,'Подтвердите сохранение подключения')
    ids=list(dict.fromkeys(p.ids)); devices={d.id:d for d in db.query(Device).filter(Device.id.in_(ids)).all()}
    if len(devices)!=len(ids): raise HTTPException(404,'Устройство не найдено')
    spec=dict(username=p.username,transport=p.transport,allow_plain=p.allow_plain)
    action='connection-save' if p.apply else 'connection-check'
    db.execute(text('SELECT pg_advisory_xact_lock(7460931)'))
    for old in db.query(ManagementJob).filter(ManagementJob.action.in_(CONNECTION_ACTIONS),ManagementJob.owner==user.id).order_by(ManagementJob.id.desc()).limit(200):
        if old.entries and old.entries[0].get('request_id')==p.request_id:
            if old.action!=action or {e['id'] for e in old.entries}!=set(ids) or old.entries[0].get('connection')!=spec: raise HTTPException(409,'Идентификатор запроса уже использован')
            return out(old)
    for old in db.query(ManagementJob).filter(ManagementJob.action.in_(CONNECTION_ACTIONS),ManagementJob.state.in_(['queued','running','stopped'])):
        if any(e['id'] in ids and (e['state']=='running' or (old.state in ('queued','running') and e['state']=='pending')) for e in old.entries): raise HTTPException(409,'Устройство уже участвует в смене подключения')
    # Reject an unapproved plaintext password before queuing, including mixed selections.
    if not p.allow_plain and any((not d.use_tls and p.transport=='keep') or p.transport=='api' for d in devices.values()): raise HTTPException(422,'Подтвердите передачу пароля по обычному API')
    token=vault_service.encrypt_secret(p.password); now=datetime.now(timezone.utc)
    entries=[dict(id=d.id,name=d.identity or d.name,host=d.host,username=d.username,port=d.port,tls=d.use_tls,pin=d.tls_fingerprint,state='pending',connection=spec,request_id=p.request_id,credential_revision=hashlib.sha256(d.password_enc.encode()).hexdigest()) for d in (devices[i] for i in ids)]
    j=ManagementJob(owner=user.id,action=action,state='queued',created=now,source='',entries=entries)
    db.add(j);db.flush();db.add(AccountJobSecret(job_id=j.id,token=token,expires=now+timedelta(hours=24)));db.commit();db.refresh(j)
    return out(j)


def execute_connection_job(db,d,user,action,entry,job_id):
    from .routeros.client import RouterOSCredentials, routeros_session
    from ..core.security import encrypt_secret
    from ..models.device_management import DeviceManagementEvent
    if entry.get('credential_revision')!=hashlib.sha256(d.password_enc.encode()).hexdigest(): raise Blocked('Учётные данные изменились после постановки в очередь; повторите проверку')
    spec=entry['connection']; port,tls=connection_target(d,spec['transport'])
    if not tls and not spec['allow_plain']: raise Blocked('Передача пароля без TLS не подтверждена')
    if tls:
        try: fp,_=peer_certificate(d.host,port)
        except Exception: raise Blocked('TLS недоступен или сертификат вне срока действия') from None
        if not hmac.compare_digest(fp,d.tls_fingerprint): raise Blocked('Отпечаток TLS изменился; прежнее подключение сохранено')
    secret=db.get(AccountJobSecret,job_id)
    if not secret: raise Blocked('Пароль задачи недоступен; создайте новую задачу')
    expiry=secret.expires.replace(tzinfo=timezone.utc) if secret.expires.tzinfo is None else secret.expires
    if expiry<=datetime.now(timezone.utc): raise Blocked('Срок хранения пароля истёк')
    try:
        pwd=vault_service.decrypt_secret_v2(secret.token)
        creds=RouterOSCredentials(host=d.host,username=spec['username'],password=pwd,port=port,use_tls=tls,tls_fingerprint=d.tls_fingerprint if tls else None,timeout=10)
        with routeros_session(creds) as api:
            ident=list(api.path('system','identity')); resource=list(api.path('system','resource'))
            if not ident or not resource or (d.identity and ident[0].get('name')!=d.identity): raise ValueError()
        enc=encrypt_secret(pwd) if action=='connection-save' else None
    except Exception: raise Blocked('Вход или идентификация устройства не подтверждены; прежние параметры сохранены') from None
    if action=='connection-save':
        d.username=spec['username'];d.password_enc=enc;d.port=port;d.use_tls=tls;d.last_error=None
        db.add(DeviceManagementEvent(device_id=d.id,actor=user.email,action=action,detail=f'Подключение проверено: TCP {port}; TLS={tls}'))
        # Commit with the queue result in tick, not before.
    return dict(detail=f"TCP {port}; {'TLS' if tls else 'обычный API'}; вход подтверждён"+('; сохранено' if action=='connection-save' else '; без изменений'))


@router.post('/jobs/{job_id}/stop')
def stop(job_id:int,db:Session=Depends(get_db),user:User=Depends(admin)):
    j=db.execute(select(ManagementJob).where(ManagementJob.id==job_id).with_for_update()).scalar_one_or_none()
    if not j: raise HTTPException(404,'Очередь не найдена')
    if j.state in ('queued','running'):
        j.state='stopped'
        if j.action in SECRET_ACTIONS: clear_account_secret(db,j.id)
        db.commit()
    return out(j)


@router.post('/jobs/{job_id}/resume-tls')
def resume_tls(job_id:int,db:Session=Depends(get_db),user:User=Depends(admin)):
    prior=db.execute(select(ManagementJob).where(ManagementJob.id==job_id).with_for_update()).scalar_one_or_none()
    if not prior or prior.action!='tls-prepare' or prior.state not in ('interrupted','stopped','failed'):
        raise HTTPException(409,'Возобновление доступно только для завершённой или прерванной подготовки TLS')
    if any(e['state']=='running' for e in prior.entries):
        raise HTTPException(409,'Текущая операция ещё завершается; обновите очередь')
    pending=[e for e in prior.entries if e['state'] in ('pending','unknown','failed')]
    if not pending: raise HTTPException(409,'Нет оставшихся устройств')
    pending_ids={e['id'] for e in pending}
    for active in db.query(ManagementJob).filter(ManagementJob.state.in_(['queued','running'])).all():
        if any(e['id'] in pending_ids and e['state'] in ('pending','running') for e in active.entries):
            raise HTTPException(409,'Для этих устройств уже есть активная очередь')
    for e in pending:
        d=db.get(Device,e['id'])
        if not d or not same_endpoint(e,d): raise HTTPException(409,'Подключение изменилось; выберите устройства заново')
    return create(Request(action='tls-prepare',ids=[e['id'] for e in pending],source=prior.source,confirmed=True),db,user)


def fingerprint(row):
    value=str(row.get('fingerprint') or '').lower().replace(':','')
    return value if re.fullmatch('[0-9a-f]{64}',value) else None


def usage(row):
    return set(policy_tokens(row.get('key-usage','')))


def valid_cert(row):
    return bool(fingerprint(row) and mg.truth(row.get('private-key')) and not any(mg.truth(row.get(k)) for k in ('expired','revoked','invalid')))


def inventory(api):
    return list(api.path('certificate'))


def by_name(api,name):
    matches=[r for r in inventory(api) if r.get('name')==name]
    if len(matches)!=1 or not matches[0].get('.id'):
        raise Unconfirmed('Не удалось однозначно найти сертификат '+name)
    return matches[0]


def sign_cert(api,name,ca=None):
    row=by_name(api,name)
    if valid_cert(row): return row
    if fingerprint(row) or mg.truth(row.get('private-key')):
        raise Blocked('Сертификат '+name+' уже имеет ключ или подпись; требуется ручная проверка')
    args={'number':name,'name':name}
    if ca: args['ca']=ca
    try: list(api(cmd='/certificate/sign',**args))
    except Exception as exc:
        # A trap or timeout does not prove the write was not performed. Never retry here.
        try: row=by_name(api,name)
        except Exception: row={}
        if valid_cert(row): return row
        raise Unconfirmed('Подписание '+name+' не подтверждено; проверьте CA, права и Certificates') from exc
    for attempt in range(41):
        row=by_name(api,name)
        if valid_cert(row): return row
        if attempt<40: time.sleep(3)
    raise Unconfirmed('Подписание '+name+' не подтверждено за 120 с; API-SSL не изменён')


def add_certificate(api,name,**fields):
    try: list(api(cmd='/certificate/add',name=name,**fields))
    except Exception as exc: raise Unconfirmed('Создание шаблона '+name+' не подтверждено; проверьте Certificates') from exc
    return by_name(api,name)


def scope_options(api):
    # RouterOS 7.21+ supports service-specific trust stores. Older versions do not.
    if any('trust-store' in r for r in inventory(api)):return {'trust-store':'api'}
    try:
        version=str(list(api.path('system','resource'))[0].get('version',''))
        m=re.match(r'^(\d+)\.(\d+)',version)
        if m and tuple(map(int,m.groups()))>=(7,21): return {'trust-store':'api'}
    except Exception: pass
    return {}


def ensure_ca(api,name='roszetta-ca'):
    rows=[r for r in inventory(api) if r.get('name')==name]
    if not rows:
        row=add_certificate(api,name,**{'common-name':'ROSzetta-CA','key-size':'2048','days-valid':'3650','key-usage':'key-cert-sign,crl-sign','trusted':'no',**scope_options(api)})
    else: row=by_name(api,name)
    if not {'key-cert-sign','crl-sign'}<=usage(row) or row.get('common-name')!='ROSzetta-CA':
        raise Blocked('Имя roszetta-ca занято другим сертификатом; требуется ручная проверка')
    was_signed=valid_cert(row)
    row=sign_cert(api,name)
    if not mg.truth(row.get('authority')):
        raise Unconfirmed('Сертификат roszetta-ca не подтверждён как CA')
    # Only change the trust flag on a CA just created/signed by this operation,
    # not on existing signed CAs (including the manually configured device).
    # RouterOS may auto-trust a self-signed CA. Its private key is sufficient for signing;
    # the controller trusts only the leaf pin and never imports this root as a global CA.
    if not was_signed and mg.truth(row.get('trusted')):
        try:
            list(api.path('certificate')('set',**{'.id':row['.id'],'trusted':'no'}))
            if mg.truth(by_name(api,name).get('trusted')): raise ValueError('trust flag unchanged')
        except Exception as exc: raise Unconfirmed('Локальный CA создан, но ограничение доверия не подтверждено; проверьте Certificates') from exc
    return name


def check_tls_clients(api):
    """Detect visible API-SSL sessions; lack of a record is not proof of no consumers."""
    try:
        services=list(api.path('ip','service'))
        users=list(api.path('user','active'))
    except Exception as exc:
        raise Blocked('Не удалось проверить активные подключения; сертификат не назначен') from exc
    if any(r.get('name')=='api-ssl' and (mg.truth(r.get('dynamic')) or r.get('remote')) for r in services) or any(str(r.get('via','')).lower() in ('api-ssl','api_ssl','api-tls') for r in users):
        raise Blocked('Обнаружены активные API-SSL подключения; согласуйте окно обслуживания')


def prepare_tls(api, d, source, repair=False):
    row=mg.static_service(api,'api-ssl')
    old=dict(row)
    name=str(row.get('certificate') or '')
    repair_enabled = repair and not d.use_tls and not mg.truth(row.get('disabled')) and name in ('','none')
    if repair and not repair_enabled:
        raise Blocked('Исправление доступно только при обычном API и включённом API-SSL без сертификата; выполните диагностику')
    if repair_enabled:
        check_tls_clients(api)
    if not repair_enabled and (not mg.truth(row.get('disabled')) or d.use_tls):
        # Preserve the certificate and live TLS connection; on explicit preparation
        # via plain API, append controller /32 to an existing restricted ACL.
        if mg.truth(row.get('disabled')) or name in ('','none'):
            raise Blocked('API-SSL без сертификата или активное TLS-подключение. Если контроллер использует обычный API, а API-SSL включён без сертификата, выберите «Исправить API-SSL без сертификата» после проверки других клиентов.')
        cert=by_name(api,name)
        if not valid_cert(cert) or 'tls-server' not in usage(cert): raise Blocked('Назначенный сертификат не готов; API-SSL не изменён')
        if not d.use_tls:
            try: _,row=mg.append_service_source(api,'api-ssl',source)
            except Exception as exc: raise Unconfirmed('Не подтверждено добавление адреса контроллера в API-SSL; проверьте IP Services') from exc
        return name,int(row['port']),fingerprint(cert),old,row
    try:
        networks=[ipaddress.ip_network(a.strip(),strict=False) for a in str(row.get('address') or '').split(',') if a.strip()]
    except ValueError as exc: raise Blocked('Не удалось разобрать IP Services address') from exc
    if not repair_enabled and any(n.prefixlen==0 for n in networks): raise Blocked('API-SSL имеет адрес /0, требуется ручная проверка')
    if name in ('','none'):
        try: alt='IP:'+str(ipaddress.ip_address(d.host))
        except ValueError: alt='DNS:'+d.host
        if not re.fullmatch(r'(?:IP|DNS):[A-Za-z0-9.:-]+',alt): raise Blocked('Недопустимый адрес для сертификата')
        candidates=[r for r in inventory(api) if re.fullmatch(r'roszetta-api-[0-9a-f]{12}',str(r.get('name',''))) and r.get('common-name')==d.host and alt in policy_tokens(r.get('subject-alt-name','')) and 'tls-server' in usage(r) and 'key-cert-sign' not in usage(r)]
        ready=sorted((r for r in candidates if valid_cert(r)),key=lambda r:str(r['name']))
        templates=sorted((r for r in candidates if not fingerprint(r) and not mg.truth(r.get('private-key'))),key=lambda r:str(r['name']))
        if ready: name=ready[0]['name']
        else:
            ca=ensure_ca(api)
            if templates: name=templates[0]['name']
            else:
                name='roszetta-api-'+hashlib.sha256(d.host.encode()).hexdigest()[:12]
                if any(r.get('name')==name for r in inventory(api)): raise Blocked('Имя сертификата уже занято; проверьте Certificates')
                add_certificate(api,name,**{'common-name':d.host,'subject-alt-name':alt,'key-size':'2048','days-valid':'365','key-usage':'digital-signature,key-encipherment,tls-server','trusted':'no',**scope_options(api)})
            cert=sign_cert(api,name,ca)
            if cert.get('ca')!=ca: raise Unconfirmed('Центр подписи серверного сертификата не подтверждён')
            if mg.truth(cert.get('trusted')):
                try:
                    list(api.path('certificate')('set',**{'.id':cert['.id'],'trusted':'no'}))
                    if mg.truth(by_name(api,name).get('trusted')): raise ValueError('trust flag unchanged')
                except Exception as exc: raise Unconfirmed('Серверный сертификат подписан, но ограничение доверия не подтверждено') from exc
    cert=by_name(api,name)
    if not valid_cert(cert) or 'tls-server' not in usage(cert):
        raise Blocked('Серверный сертификат '+name+' не готов; API-SSL не изменён')
    if mg.static_service(api,'api-ssl')!=old:
        raise Unconfirmed('Параметры API-SSL изменились во время подготовки; проверьте устройство')
    try:
        if repair_enabled:
            check_tls_clients(api)
            # Do not change the current ACL or service port. A new certificate changes the TLS handshake.
            list(api.path('ip','service')('set', **{'.id':old['.id'],'certificate':name}))
            row=mg.static_service(api,'api-ssl')
            if row.get('certificate')!=name or mg.truth(row.get('disabled')) or str(row.get('address') or '')!=str(old.get('address') or '') or str(row.get('port'))!=str(old.get('port')):
                raise Unconfirmed('Назначение сертификата не подтверждено')
        else: row=mg.prepare_service(api,'api-ssl',source,name)
    except Exception as exc: raise Unconfirmed('Назначение сертификата '+name+' для API-SSL не подтверждено') from exc
    return name,int(row['port']),fingerprint(cert),old,row


def renew_expired_tls(api,d):
    # Only a known ROSzetta-managed expired leaf, while controller uses plain API.
    # Preserve original certificate, ACL, port and service state. No automatic TLS switch.
    if d.use_tls: raise Blocked('Перевыпуск при активном TLS контроллера запрещён; согласуйте независимый доступ')
    row=mg.static_service(api,'api-ssl'); old=dict(row)
    name=str(row.get('certificate') or '')
    if not re.fullmatch(r'roszetta-api-[0-9a-f]{12}',name): raise Blocked('Назначенный сертификат не управляется ROSzetta')
    cert=by_name(api,name)
    if not fingerprint(cert) or not mg.truth(cert.get('expired')): raise Blocked('Просроченность сертификата не подтверждена; сначала синхронизируйте время и проверьте сертификат')
    if cert.get('common-name')!=d.host or 'tls-server' not in usage(cert): raise Blocked('Сертификат не соответствует устройству')
    if not mg.truth(row.get('disabled')): check_tls_clients(api)
    suffix=hashlib.sha256((d.host+fingerprint(cert)).encode()).hexdigest()[:12]
    ca=ensure_ca(api,'roszetta-ca-'+suffix)
    new_name='roszetta-api-'+suffix
    try: alt='IP:'+str(ipaddress.ip_address(d.host))
    except ValueError: alt='DNS:'+d.host
    if not re.fullmatch(r'(?:IP|DNS):[A-Za-z0-9.:-]+',alt): raise Blocked('Недопустимый адрес для сертификата')
    existing=[r for r in inventory(api) if r.get('name')==new_name]
    if not existing: add_certificate(api,new_name,**{'common-name':d.host,'subject-alt-name':alt,'key-size':'2048','days-valid':'365','key-usage':'digital-signature,key-encipherment,tls-server','trusted':'no',**scope_options(api)})
    leaf=by_name(api,new_name)
    if leaf.get('common-name')!=d.host or alt not in policy_tokens(leaf.get('subject-alt-name','')) or 'tls-server' not in usage(leaf) or 'key-cert-sign' in usage(leaf): raise Blocked('Имя нового сертификата занято; требуется ручная проверка')
    leaf=sign_cert(api,new_name,ca)
    if leaf.get('ca')!=ca or not valid_cert(leaf): raise Unconfirmed('Новый сертификат не подтверждён')
    if mg.static_service(api,'api-ssl')!=old: raise Unconfirmed('Служба изменилась во время выпуска; сертификат не назначен')
    if not mg.truth(row.get('disabled')): check_tls_clients(api)
    try:
        list(api.path('ip','service')('set',**{'.id':old['.id'],'certificate':new_name}))
        row=mg.static_service(api,'api-ssl')
        if row.get('certificate')!=new_name or any(str(row.get(k) or '')!=str(old.get(k) or '') for k in ('address','port','disabled')): raise ValueError()
    except Exception as exc: raise Unconfirmed('Назначение нового сертификата не подтверждено; проверьте службу вручную') from exc
    return new_name,int(row['port']),fingerprint(leaf),old,row


def peer_certificate(host,port):
    """TLS handshake without credentials; fingerprint does not become trusted here."""
    from cryptography import x509
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
    with socket.create_connection((host,port),timeout=8) as sock:
        with ctx.wrap_socket(sock,server_hostname=host) as tls:
            der=tls.getpeercert(binary_form=True)
    if not der: raise Blocked('Сертификат TLS не получен')
    cert=x509.load_der_x509_certificate(der)
    now=datetime.now(timezone.utc)
    if now<cert.not_valid_before_utc: raise Blocked('Срок действия TLS ещё не наступил; проверьте время MikroTik и контроллера')
    if now>cert.not_valid_after_utc: raise Blocked('Срок действия TLS истёк; проверьте NTP и перевыпустите сертификат')
    return hashlib.sha256(der).hexdigest(),cert.not_valid_after_utc.isoformat()


def cert_summary(api):
    return [{k:r.get(k) for k in ('name','common-name','invalid-after','fingerprint','private-key','key-usage','expired','revoked')} for r in inventory(api) if 'tls-server' in usage(r) and valid_cert(r)]


def inventory_expiry(row):
    raw=str(row.get('expires-after') or '').strip().lower()
    # RouterOS prints 52w23h59m51s, or HH:MM:SS. Approximate UTC via remaining lifetime.
    parts=re.fullmatch(r'(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?',raw)
    if parts and raw:
        w,d,h,m,s=(int(x or 0) for x in parts.groups())
        return (datetime.now(timezone.utc)+timedelta(weeks=w,days=d,hours=h,minutes=m,seconds=s)).isoformat()
    clock=re.fullmatch(r'(?:(\d+)w)?(?:(\d+)d)?(\d+):(\d{2}):(\d{2})',raw)
    if clock:
        w,d,h,m,s=(int(x or 0) for x in clock.groups())
        return (datetime.now(timezone.utc)+timedelta(weeks=w,days=d,hours=h,minutes=m,seconds=s)).isoformat()
    return str(row.get('invalid-after') or '') or None


def inspect_ssl(d,api):
    row=mg.static_service(api,'api-ssl'); certs=inventory(api)
    name=str(row.get('certificate') or 'none'); enabled=not mg.truth(row.get('disabled'))
    assigned=next((c for c in certs if c.get('name')==name),None)
    candidates=[c for c in certs if 'tls-server' in usage(c) and valid_cert(c)]
    # An unrelated TLS certificate (VPN, HTTPS, etc.) is not API-SSL readiness.
    cert=assigned or next((c for c in candidates if c.get('common-name')==d.host and str(c.get('name','')).startswith('roszetta-api-')),None)
    data={'status':'none','name':None,'fingerprint':None,'expires':None,'enabled':enabled,'detail':'Подписанный серверный сертификат не найден'}
    if cert:
        data.update(name=cert.get('name'),fingerprint=fingerprint(cert),expires=inventory_expiry(cert),status='issued',detail='Сертификат выпущен; TLS не подтверждён')
        if not valid_cert(cert) or 'tls-server' not in usage(cert): data.update(status='error',detail='Назначенный сертификат недействителен или без ключа')
    elif any(str(c.get('name','')).startswith('roszetta-api-') for c in certs):
        related=[c for c in certs if str(c.get('name','')).startswith('roszetta-api-')]
        data.update(status='error' if any(fingerprint(c) for c in related) else 'attention',detail='Сертификат ROSzetta недействителен или найден неподписанный шаблон')
    if enabled:
        if not assigned or not valid_cert(assigned) or 'tls-server' not in usage(assigned): data.update(status='error',detail='API-SSL включён без пригодного назначенного сертификата')
        else:
            try:
                fp,expires=peer_certificate(d.host,int(row['port']))
                data.update(expires=expires)
                if fp!=fingerprint(assigned) or (d.use_tls and d.tls_fingerprint and d.tls_fingerprint!=fp):
                    data.update(status='error',detail='Отпечатки не совпадают')
                elif d.use_tls and d.tls_fingerprint==fp and d.port==int(row['port']):
                    data.update(status='secure',detail='API-SSL с закреплённым SHA-256 подтверждён')
                else: data.update(status='attention',detail='API-SSL доступен; требуется подтверждение отпечатка и переход')
            except Blocked as exc: data.update(status='error',detail=str(exc))
            except Exception: data.update(status='attention',detail='Сертификат назначен; TLS-порт не подтверждён')
    return data


def refresh_ssl(db,d):
    from ..api.v1 import devices as v
    from .routeros.client import routeros_session
    saved=db.get(SSLStatus,d.id)
    previous=dict(saved.data) if saved else {}
    endpoint=[d.host,d.port,d.use_tls,d.tls_fingerprint]
    try:
        # Do not send credentials over a legacy TLS session without a pin for this inventory.
        if d.use_tls and not d.tls_fingerprint: raise Blocked('TLS без закреплённого отпечатка; требуется проверка')
        with routeros_session(v.dc_replace(v._creds(d),timeout=8)) as api: data=inspect_ssl(d,api)
    except Exception:
        data={'status':'unknown','detail':'Не удалось подтвердить состояние по API','name':None,'expires':None,'fingerprint':None,'enabled':None}
    data['endpoint']=endpoint
    last_fp=previous.get('notified_fp',previous.get('fingerprint')) if previous.get('endpoint')==endpoint else None
    fp=data.get('fingerprint') or (last_fp if data.get('status')=='unknown' else None)
    data['notified_fp']=fp
    data['notified']=previous.get('notified',[]) if fp and fp==last_fp else []
    if not saved: saved=SSLStatus(device_id=d.id); db.add(saved)
    saved.checked_at=datetime.now(timezone.utc);saved.data=data;db.commit()
    warn_expiry(db,d,saved)
    return data


def update_cache_best_effort(db,d):
    try: refresh_ssl(db,d)
    except Exception: db.rollback()


def warn_expiry(db,d,saved):
    # Alert only on UTC peer expiry or a relative duration from the inventory.
    data=dict(saved.data); expiry=data.get('expires')
    if not expiry or data['status'] not in ('secure','attention','issued'): return
    try:
        date=datetime.fromisoformat(expiry)
        if date.tzinfo is None: return
        remaining=(date-datetime.now(timezone.utc)).total_seconds()/86400
        due=[n for n in (30,14,7,1) if 0<=remaining<=n and n not in data['notified']]
        if not due:return
        from .settings import get_settings_dict
        import httpx
        cfg=get_settings_dict(db).get('telegram',{})
        if not cfg.get('enabled') or not cfg.get('bot_token') or not cfg.get('chat_id'):return
        response=httpx.post('https://api.telegram.org/bot'+cfg['bot_token']+'/sendMessage',json={'chat_id':cfg['chat_id'],'text':f'ROSzetta: {d.identity or d.name}: срок сертификата API-SSL — менее {min(due)} дн.'},timeout=8)
        if response.status_code==200:
            data['notified']=sorted(set(data['notified']+due));saved.data=data;db.commit()
    except Exception:
        db.rollback()


def scan_due(db):
    if engine.dialect.name!='postgresql':return
    cutoff=datetime.now(timezone.utc)-timedelta(hours=6)
    rows=db.query(Device,SSLStatus).outerjoin(SSLStatus,Device.id==SSLStatus.device_id).order_by(SSLStatus.checked_at.asc().nullsfirst(),Device.id).all()
    for d,s in rows:
        if not s or s.data.get('endpoint')!=[d.host,d.port,d.use_tls,d.tls_fingerprint] or (s.checked_at.replace(tzinfo=timezone.utc) if s.checked_at.tzinfo is None else s.checked_at)<cutoff:
            refresh_ssl(db,d)
            break


GROUP_POLICIES = frozenset('local telnet ssh ftp reboot read write policy test winbox password web sniff sensitive api romon rest-api'.split())
SYSTEM_GROUPS = frozenset(('read','write','full'))
LOGIN_POLICIES = frozenset(('local','telnet','ssh','ftp','winbox','web','api','rest-api'))


def group_spec(name, policies, mode='create', username=''):
    name=name.strip()
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,32}',name) or name.lower() in SYSTEM_GROUPS:
        raise HTTPException(422,'Укажите имя пользовательской группы (1–32 символа: латиница, цифры, _ . -)')
    if mode not in ('create','upsert','add','remove','replace','delete','move'):
        raise HTTPException(422,'Неизвестная операция с группой')
    if mode in ('create','upsert','add','remove','replace') and (not policies or not set(policies)<=GROUP_POLICIES):
        raise HTTPException(422,'Выберите допустимые права группы')
    if mode=='move' and not re.fullmatch(r'[A-Za-z0-9_.-]{1,32}',username.strip()):
        raise HTTPException(422,'Укажите имя локального пользователя')
    return dict(name=name,policies=sorted(set(policies)) if mode in ('create','upsert','add','remove','replace') else [],mode=mode,username=username.strip() if mode=='move' else '')


def effective_policies(row):
    if row.get('policy') is None:
        raise Blocked('Не удалось прочитать права группы')
    tokens=set(policy_tokens(row['policy']))
    return sorted(v for v in tokens if not v.startswith('!') and '!'+v not in tokens)


def one_named(rows,name):
    matches=[r for r in rows if r.get('name')==name]
    if len(matches)>1:
        raise Blocked('Найдены неоднозначные записи')
    return matches[0] if matches else None


def group_members(users,name):
    return sorted(str(r['name']) for r in users if r.get('group')==name and r.get('name'))


def group_inventory(api, controller):
    groups=list(api.path('user','group'));users=list(api.path('user'))
    account=one_named(users,controller)
    active_group=account.get('group') if account else None
    return [dict(name=str(g['name']),policies=effective_policies(g),members=group_members(users,g['name']),protected=g['name'].lower() in SYSTEM_GROUPS or g['name']==active_group) for g in sorted(groups,key=lambda r:str(r.get('name',''))) if g.get('name')]


def group_context(api,controller):
    users=list(api.path('user'));groups=list(api.path('user','group'))
    current=one_named(users,controller)
    if not current or mg.truth(current.get('disabled')) or not current.get('group'):
        raise Blocked('Локальная учётная запись контроллера не подтверждена')
    active_group=one_named(groups,current['group'])
    if not active_group or not {'read','write','policy','api'}<=set(effective_policies(active_group)):
        raise Blocked('Недостаточно прав контроллера для управления группами')
    try: aaa=list(api.path('user','aaa'))
    except Exception: aaa=[]
    if len(aaa)!=1:
        raise Blocked('Не удалось подтвердить /user aaa; изменения групп заблокированы')
    radius=str(aaa[0].get('use-radius','')).strip().lower()
    if radius in ('true','yes','1'):
        raise Blocked('RADIUS включён (use-radius=yes); изменения групп требуют ручной проверки')
    if radius not in ('false','no','0'):
        raise Blocked('Не удалось определить use-radius; изменения групп заблокированы')
    return users,groups,current['group'],str(aaa[0].get('default-group') or '')


def group_plan(api,controller,spec):
    users,groups,current_group,default_group=group_context(api,controller)
    name=spec['name'];mode=spec['mode'];wanted=set(spec['policies'])
    if name.lower() in SYSTEM_GROUPS:
        raise Blocked(f'Встроенная системная группа {name} защищена')
    if mode not in ('create','add','upsert') and name==current_group:
        raise Blocked(f'Группа текущего подключения {name} защищена: удаление, замена и перенос запрещены')
    if name==default_group and mode!='create':
        raise Blocked(f'Группа AAA по умолчанию {name} защищена; изменения запрещены (RADIUS отключён)')
    group=one_named(groups,name)
    old=effective_policies(group) if group else []
    members=group_members(users,name)
    before=dict(group_id=str(group.get('.id') or '') if group else None,policies=old,members=members,controller_group=current_group,default_group=default_group)
    old_text=', '.join(old) or '—'; new_text=', '.join(sorted(wanted)) or '—'
    if mode=='create' or (mode=='upsert' and not group):
        if group:
            equal=set(old)==wanted
            return dict(spec=spec,group_before=before,group_after=sorted(wanted),eligible=False,attention=not equal,conflict=not equal,protected=name in (current_group,default_group) or name.lower() in SYSTEM_GROUPS,detail=f'{name}: '+('группа уже существует с такими правами' if equal else f'конфликт; существующие: {old_text}; запрошены: {new_text}'))
        if name==current_group or name==default_group or members:
            raise Blocked('Имя группы уже связано с действующими учётными записями или AAA')
        after=sorted(wanted);detail=f'{name}: создать группу; права: {new_text}'
    else:
        if not group or not group.get('.id'):
            raise Blocked('Группа не найдена или идентификатор не подтверждён')
        if set(old)-GROUP_POLICIES:
            raise Blocked('В группе есть неизвестные права; требуется ручная проверка')
        if mode=='delete':
            if members: raise Blocked('Группа используется: '+', '.join(members))
            after=None;detail=f'{name}: удалить пустую группу; прежние права: {old_text}'
        elif mode=='move':
            login=spec['username']; account=one_named(users,login)
            if not account or not account.get('.id') or not account.get('group'):
                raise Blocked('Локальный пользователь не найден')
            source=account['group']; source_row=one_named(groups,source)
            if login.lower()=='admin' or login==controller or source in ('full',current_group,default_group) or not source_row:
                raise Blocked('Учётная запись администратора, контроллера или защищённая группа; перенос запрещён')
            before.update(user_id=str(account['.id']),user_group=source,user_disabled=mg.truth(account.get('disabled')),source_policies=effective_policies(source_row),source_members=group_members(users,source))
            after=name
            if source==name:
                return dict(spec=spec,group_before=before,group_after=after,eligible=False,attention=False,detail=f'{login}: уже в группе {name}')
            if not mg.truth(account.get('disabled')) and ('read' not in old or not set(old)&LOGIN_POLICIES):
                raise Blocked('Целевая группа не имеет базовых прав входа и чтения')
            detail=f'{login}: {source} → {name}; права: {", ".join(before["source_policies"])} → {old_text}'
        else:
            target = set(old)|wanted if mode in ('add','upsert') else set(old)-wanted if mode=='remove' else wanted
            if not target or (members and ('read' not in target or not target&LOGIN_POLICIES)):
                raise Blocked('Нельзя оставить пустые права или лишить используемую группу всех способов входа/чтения')
            after=sorted(target)
            if after==old:
                return dict(spec=spec,group_before=before,group_after=after,eligible=False,attention=False,detail=f'{name}: без изменений — все запрошенные права присутствуют; RADIUS отключён')
            detail=f'{name}: добавить: {", ".join(sorted(set(after)-set(old))) or "нет"}; убрать: {", ".join(sorted(set(old)-set(after))) or "нет"}; участники: {", ".join(members) or "нет"}'
    return dict(spec=spec,group_before=before,group_after=after,eligible=True,attention=False,detail=detail)


def apply_group_plan(api,controller,expected):
    spec=expected['spec']; mode=spec['mode']; name=spec['name']
    actual=group_plan(api,controller,spec)
    if not actual['eligible']:
        if mode=='create' and not actual['attention']:
            return actual['detail']+'; без изменений'
        if mode in ('add','upsert') and not actual['attention'] and expected['group_before']['group_id'] is not None:
            previous=expected['group_before']; current=actual['group_before']
            if (actual['group_after']==expected['group_after']
                    and all(current.get(k)==previous.get(k) for k in ('group_id','members','controller_group','default_group'))):
                return actual['detail']
        raise Blocked('Предварительная проверка больше не актуальна; выполните её повторно')
    if actual['group_before']!=expected['group_before'] or actual['group_after']!=expected['group_after']:
        raise Blocked('Группа, права или участники изменились после проверки; повторите её')
    before=actual['group_before'];after=actual['group_after']; path=api.path('user','group')
    creating=mode=='create' or (mode=='upsert' and before['group_id'] is None)
    if creating:
        path.add(name=name,policy=','.join(after))
    elif mode=='delete':
        list(path('remove',**{'.id':before['group_id']}))
    elif mode=='move':
        list(api.path('user')('set',**{'.id':before['user_id'],'group':name}))
    else:
        old=set(before['policies']);target=set(after)
        # RouterOS set keeps omitted policies, so explicitly grant/revoke the delta.
        delta=sorted(target-old)+['!'+p for p in sorted(old-target)]
        list(path('set',**{'.id':before['group_id'],'policy':','.join(delta)}))
    # Read back after the write. An inconclusive write must interrupt the queue, not retry automatically.
    try:
        row=one_named(list(api.path('user','group')),name)
        if mode=='delete': ok=(row is None)
        elif mode=='move':
            account=one_named(list(api.path('user')),spec['username'])
            ok=bool(account and str(account.get('.id'))==before['user_id'] and account.get('group')==name)
        else:
            ok=bool(row and effective_policies(row)==after and (creating or str(row.get('.id'))==before['group_id']))
    except Exception: ok=False
    if not ok: raise Unconfirmed('Изменение группы не подтверждено; проверьте фактическое состояние')
    return actual['detail']+'; подтверждено'


class GroupTemplate(Base):
    __tablename__='device_group_templates_v93'
    id: Mapped[int]=mapped_column(primary_key=True)
    name: Mapped[str]=mapped_column(String(64),unique=True)
    group_name: Mapped[str]=mapped_column(String(32))
    policies: Mapped[list]=mapped_column(JSON)


class GroupTemplateRequest(BaseModel):
    name: str=Field(min_length=1,max_length=64)
    group_name: str=Field(min_length=1,max_length=32)
    policies: list[str]=Field(min_length=1,max_length=17)
    replace: bool=False


def template_out(t):
    return dict(id=t.id,name=t.name,group_name=t.group_name,policies=t.policies)


@router.get('/group-templates')
def list_group_templates(db:Session=Depends(get_db),user:User=Depends(admin)):
    return [template_out(t) for t in db.query(GroupTemplate).order_by(GroupTemplate.name).all()]


@router.post('/group-templates')
def save_group_template(body:GroupTemplateRequest,db:Session=Depends(get_db),user:User=Depends(admin)):
    from sqlalchemy.exc import IntegrityError
    title=body.name.strip()
    if not title or any(ord(c)<32 or ord(c)==127 for c in title): raise HTTPException(422,'Недопустимое имя шаблона')
    spec=group_spec(body.group_name,body.policies)
    row=db.execute(select(GroupTemplate).where(GroupTemplate.name==title).with_for_update()).scalar_one_or_none()
    if row and not body.replace: raise HTTPException(409,'Шаблон уже существует; подтвердите замену')
    if not row:
        row=GroupTemplate(name=title);db.add(row)
    row.group_name=spec['name'];row.policies=spec['policies']
    try: db.commit()
    except IntegrityError:
        db.rollback();raise HTTPException(409,'Шаблон уже существует; обновите список')
    db.refresh(row);return template_out(row)


@router.delete('/group-templates/{template_id}')
def delete_group_template(template_id:int,db:Session=Depends(get_db),user:User=Depends(admin)):
    row=db.get(GroupTemplate,template_id)
    if not row: raise HTTPException(404,'Шаблон не найден')
    db.delete(row);db.commit();return {'ok':True}


def execute(db,d,user,action,source,expected):
    from ..api.v1 import devices as v
    from .routeros.client import routeros_session
    from ..models.device_management import DeviceManagementEvent
    if d.use_tls and not d.tls_fingerprint and action!='tls-scan' and action!='tls-switch' and action!='ssl-status':
        raise Blocked('TLS без закреплённого отпечатка')
    if action in ('time-audit','ntp-apply'):
        try:
            with routeros_session(v._creds(d)) as api: result=tm.inspect(api) if action=='time-audit' else tm.configure(api,expected)
        except tm.TimeBlocked as exc: raise Blocked(str(exc)) from exc
        except tm.TimeUnconfirmed as exc: raise Unconfirmed(str(exc)) from exc
        if action=='ntp-apply':
            db.add(DeviceManagementEvent(device_id=d.id,actor=user.email,action=action,detail=result['detail']));db.commit()
        return result
    if action in ('group-list','group-preview','group-apply'):
        if d.use_tls and not d.tls_fingerprint: raise Blocked('TLS без закреплённого отпечатка')
        with routeros_session(v._creds(d)) as api:
            if action=='group-list':
                groups=group_inventory(api,d.username)
                detail=' | '.join(f"{g['name']}: {', '.join(g['policies']) or '—'}; участники: {', '.join(g['members']) or 'нет'}"+(' (защищена)' if g['protected'] else '') for g in groups)
                return dict(detail=detail or 'Группы не найдены',groups=groups)
            if action=='group-preview': return group_plan(api,d.username,expected)
            detail=apply_group_plan(api,d.username,expected)
        db.add(DeviceManagementEvent(device_id=d.id,actor=user.email,action='group-'+expected['spec']['mode'],detail=detail));db.commit()
        return dict(detail=detail)
    if action=='rights':
        with routeros_session(v._creds(d)) as api: s=account_snapshot(api,d.username)
        reason=''
        try: desired_policies(s,source); eligible=bool(s['missing'])
        except Blocked as exc: eligible=False; reason=str(exc)
        warning=bool(s['missing'] or s['base_missing'] or s['disabled'] or reason)
        return dict(detail=f"{s['username']} / {s['group']}; нет: {', '.join(s['missing']+s['base_missing']) or '—'}; участники: {', '.join(s['members'])}; адреса: {s['address'] or 'без ограничений'}"+('; '+reason if reason else ''),eligible=eligible,attention=warning,snapshot=s)
    if action=='rights-apply':
        before=expected['snapshot']
        with routeros_session(v._creds(d)) as api: after=apply_rights(api,d.username,before,source)
        detail=f"{before['group']}: {', '.join(before['policies'])} → {', '.join(after['policies'])}"
        db.add(DeviceManagementEvent(device_id=d.id,actor=user.email,action='rights-apply',detail=detail));db.commit()
        return dict(detail=detail)
    if action=='services':
        r=v.management_services(d.id,db,user)
        if not r['services']:
            raise Blocked('Нет данных о службах; проверьте доверие TLS и подключение')
        results=[]; attention=False
        for s in r['services']:
            disabled=mg.truth(s['disabled']); address=s.get('address')
            tcp=None; source_allowed=None
            try:
                nets=mg.service_networks(address)
                src=ipaddress.ip_network(source, strict=True)
                source_allowed=not nets or any(src.version==n.version and src.subnet_of(n) for n in nets)
            except (ValueError,TypeError): nets=None
            if not disabled:
                try:
                    with socket.create_connection((d.host,int(s['port'])),timeout=2): tcp=True
                except (OSError, ValueError, TypeError): tcp=False
                attention=attention or tcp is False or source_allowed is not True or not nets or any(n.prefixlen==0 for n in nets)
            results.append(dict(s,tcp_reachable=tcp,source_allowed=source_allowed))
        detail=' | '.join(f"{s['name']}: {'выкл.' if mg.truth(s['disabled']) else 'вкл.'} TCP {s['port']}; {s['address'] if s['address'] else 'нет данных' if s['address'] is None else 'без ограничений IP Services'}; {'TCP доступен' if s['tcp_reachable'] is True else 'TCP недоступен' if s['tcp_reachable'] is False else 'TCP не проверялся'}"+(' (IPv4 контроллера отсутствует в ACL)' if s['source_allowed'] is False else '') for s in results)
        return dict(detail=detail,attention=attention,services=results)
    if action in ACL_ACTIONS:
        name=ACL_ACTIONS[action]
        with routeros_session(v._creds(d)) as api:
            try: before=mg.static_service(api,name); nets=mg.service_networks(mg.service_address(before))
            except ValueError as exc: raise Blocked('Невозможно однозначно прочитать ограничения '+name+'; ничего не изменено') from exc
            if not nets or any(n.prefixlen==0 for n in nets):
                return dict(detail=f'{name}: нет ограничений IP Services; список не изменён. Проверьте Firewall и при необходимости настройте ограничение отдельно.',attention=True)
            try: old,row=mg.append_service_source(api,name,source)
            except Exception as exc: raise Unconfirmed('Добавление адреса контроллера не подтверждено; проверьте IP Services перед повтором') from exc
        a,b=mg.service_address(old),mg.service_address(row)
        detail=f'{name}: {a} → {b}; '+('адрес добавлен' if a!=b else 'адрес уже разрешён; без изменений')+'; порт, сертификат и состояние службы не изменены'
        db.add(DeviceManagementEvent(device_id=d.id,actor=user.email,action=action,detail=detail));db.commit()
        return dict(detail=detail)
    if action=='ssh':
        with routeros_session(v._creds(d)) as api:
            row=mg.static_service(api,'ssh')
        if not mg.truth(row.get('disabled')) and not row.get('address'):
            return dict(detail='SSH уже включён без ограничения IP Services; адреса не изменены, проверьте Firewall',attention=True)
        v.management_enable(d.id,v.EnableService(service='ssh',source=source),db,user)
        return dict(detail='SSH настроен; требуется проверка ключа')
    if action=='ssh-scan':
        r=v.scan_trust(d.id,db,user)
        return dict(detail=f"{r['algorithm']}: {r['observed']}"+(' — ключ изменился, только индивидуальная замена' if r['changed'] else ''),fingerprint=r['observed'],eligible=not r['changed'] and r['observed'] not in r['fingerprints'],attention=r['changed'] or r['observed'] not in r['fingerprints'])
    if action=='ssh-trust':
        v.confirm_trust(d.id,v.TrustRequest(fingerprint=expected['fingerprint'],replace=False),db,user)
        db.add(DeviceManagementEvent(device_id=d.id,actor=user.email,action='ssh-trust',detail=expected['fingerprint']));db.commit()
        return dict(detail='SSH-ключ закреплён')
    if action=='sftp': return v.management_sftp_check(d.id,db,user)
    if action=='audit':
        r=v.collect_security(d.id,db,user)
        return dict(detail=f"Аудит: {len(r['findings'])} замечаний",findings=r['findings'],attention=bool(r['findings']))
    if action=='ssl-status':
        data=refresh_ssl(db,d)
        return dict(detail=data['detail'],attention=data['status'] not in ('secure','issued'),ssl_status=data['status'])
    if action in ('tls-prepare','tls-repair','tls-renew'):
        # RSA signing can take longer on low-end MikroTik.
        with routeros_session(v.dc_replace(v._creds(d),timeout=90)) as api:
            try: tm.require_clock(api)
            except tm.TimeBlocked as exc: raise Blocked(str(exc)) from exc
            name,port,fp,old,row=renew_expired_tls(api,d) if action=='tls-renew' else prepare_tls(api,d,source,repair=True) if action=='tls-repair' else prepare_tls(api,d,source)
        detail=f"API-SSL TCP {port}; {old.get('certificate') or 'none'} → {name}; адреса {old.get('address') or '—'} → {row.get('address') or '—'}; SHA256 {fp}; прежний API сохранён"
        db.add(DeviceManagementEvent(device_id=d.id,actor=user.email,action=action,detail=detail));db.commit()
        update_cache_best_effort(db,d)
        return dict(detail=detail,attention=not mg.truth(row.get('disabled')) and not row.get('address'))
    if action=='tls-scan':
        if d.use_tls and not d.tls_fingerprint:
            fp,expires=peer_certificate(d.host,d.port)
            return dict(detail=f'TCP {d.port}; SHA256 {fp}; действует до {expires}; восстановление доверия — обязательна независимая сверка',fingerprint=fp,port=d.port,eligible=True,attention=False,awaiting_confirmation=True,recovery=True)
        # Compare fingerprints from the live handshake and RouterOS certificate inventory.
        with routeros_session(v._creds(d)) as api:
            row=mg.static_service(api,'api-ssl'); cert=[c for c in api.path('certificate') if c.get('name')==row.get('certificate')]
        if mg.truth(row.get('disabled')): raise Blocked('API-SSL отключён')
        port=int(row['port']); fp,expires=peer_certificate(d.host,port)
        if len(cert)!=1 or fingerprint(cert[0])!=fp:
            raise Blocked('Отпечатки TLS и сертификата в RouterOS не совпадают')
        return dict(detail=f'TCP {port}; SHA256 {fp}; действует до {expires}',fingerprint=fp,port=port,eligible=not d.use_tls or d.tls_fingerprint!=fp,attention=False,awaiting_confirmation=not d.use_tls or d.tls_fingerprint!=fp)
    if action=='tls-switch':
        fp,_=peer_certificate(d.host,expected['port'])
        if fp!=expected['fingerprint']: raise Blocked('TLS-отпечаток изменился; повторите проверку')
        v.management_tls_switch(d.id,v.TLSConfirmation(port=expected['port'],fingerprint=expected['fingerprint']),db,user)
        return dict(detail='API-SSL подтверждён; обычный API оставлен включённым')
    raise ValueError('Неизвестная операция')


def notify_time_audit(db, entries):
    """One summary at completion of an explicitly started time audit."""
    bad=[e for e in entries if e['state']!='done' or e.get('result',{}).get('attention')]
    if not bad: return
    try:
        from .settings import get_settings_dict
        import httpx
        cfg=get_settings_dict(db).get('telegram',{})
        if not cfg.get('enabled') or not cfg.get('bot_token') or not cfg.get('chat_id'): return
        names=', '.join(str(e['name']) for e in bad[:10])[:1200]
        suffix=f' (+{len(bad)-10})' if len(bad)>10 else ''
        httpx.post('https://api.telegram.org/bot'+cfg['bot_token']+'/sendMessage',json={'chat_id':cfg['chat_id'],'text':f'ROSzetta: аудит времени/NTP: {len(bad)} из {len(entries)} требуют внимания. {names}{suffix}'},timeout=8)
    except Exception:
        # Notification failure must not retry an already completed audit.
        return


def tick():
    """One device per tick, no automatic replay after interrupted write."""
    with SessionLocal() as db:
        for j in db.query(ManagementJob).filter(ManagementJob.state.in_(['running','stopped'])).all():
            if any(e['state']=='running' for e in j.entries):
                j.entries=[dict(e,state='unknown',detail='Операция прервана; проверьте фактическое состояние') if e['state']=='running' else e for e in j.entries]
                if j.state=='running': j.state='interrupted'
        expire_account_secrets(db)
        db.commit()
        if vault_service.is_initialized_cached() is not False and not vault_service.is_unlocked(): return
        j=db.execute(select(ManagementJob).where(ManagementJob.state=='queued').order_by(ManagementJob.id).limit(1).with_for_update()).scalar_one_or_none()
        if not j:
            scan_due(db)
            return
        user=db.get(User,j.owner)
        if not user or not user.is_active or user.role!='admin':
            j.state='failed'
            if j.action in SECRET_ACTIONS: clear_account_secret(db,j.id)
            db.commit();return
        entries=[dict(e) for e in j.entries]
        idx=next((i for i,e in enumerate(entries) if e['state']=='pending'),None)
        if idx is None:
            j.state='done'
            if j.action in SECRET_ACTIONS: clear_account_secret(db,j.id)
            db.commit();return
        e=entries[idx];e['state']='running';j.entries=entries;j.state='running';jid=j.id; action=j.action;source=j.source;db.commit()
        try:
            d=db.execute(select(Device).where(Device.id==e['id']).with_for_update()).scalar_one_or_none()
            if not d or not same_endpoint(e,d): raise Blocked('Параметры подключения изменились; повторите проверку')
            result=execute_connection_job(db,d,user,action,e,jid) if action in CONNECTION_ACTIONS else execute_account_job(db,d,user,action,e,jid) if action in accounts.ACTIONS else execute(db,d,user,action,source,e.get('expected'))
            e.update(state='done',detail=result['detail'],result=result)
        except Exception as exc:
            db.rollback()
            # Custom ValueErrors contain fixed diagnostics; never store raw RouterOS traps/credentials.
            detail=str(exc) if isinstance(exc,(Blocked,Unconfirmed)) else str(exc.detail) if isinstance(exc,HTTPException) and isinstance(exc.detail,str) else 'Операция не подтверждена; проверьте состояние и права на устройстве'
            e.update(state='failed' if action in READ or isinstance(exc,Blocked) else 'unknown',detail=detail)
            if action not in READ:
                from ..models.device_management import DeviceManagementEvent
                db.add(DeviceManagementEvent(device_id=e['id'],actor=user.email,action=action+'-unconfirmed',detail=detail));db.commit()
        j=db.execute(select(ManagementJob).where(ManagementJob.id==jid).with_for_update().execution_options(populate_existing=True)).scalar_one()
        j.entries=entries
        if j.state!='stopped':
            # On an ambiguous WRITE stop batch, never automatically replay or continue.
            j.state='interrupted' if e['state']=='unknown' else 'queued' if any(x['state']=='pending' for x in entries) else 'failed' if any(x['state']=='failed' for x in entries) else 'done'
        if action in SECRET_ACTIONS and j.state not in ('queued','running'): clear_account_secret(db,j.id)
        db.commit()
        if action=='time-audit' and j.state in ('done','failed'): notify_time_audit(db,entries)
