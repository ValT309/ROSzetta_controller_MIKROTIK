from datetime import datetime, timezone, timedelta
import re
import calendar
import io
import zipfile
from fastapi import Response
from sqlalchemy import String, Integer, DateTime, JSON, update, text
from sqlalchemy.orm import Mapped, mapped_column, Session
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException
from ..core.db import Base, SessionLocal, engine, get_db
from ..api.deps import require_role
from ..models.user import User
from ..models.device import Device
from ..models.backup import DeviceBackup
from ..models.firmware import Firmware
from ..models.firmware import Firmware
from ..models.firmware import Firmware
from ..services.firmware_check import get_state
from ..services.vault import vault_service
from . import firmware_scheduler as firmware

router = APIRouter()
roles = require_role('admin','operator')
LOCK = 197302818

def now(): return datetime.now(timezone.utc)
def utc(d): return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d.astimezone(timezone.utc)
def version(v):
    m = re.fullmatch(r'(\d+(?:\.\d+){1,2})(?:\s+\([^)]*\))?', str(v or '').strip())
    if not m: return None
    return tuple((list(map(int,m[1].split('.'))) + [0,0])[:3])
def availability(current, state):
    latest=state.get('version'); a,b=version(current),version(latest)
    try: fresh=timedelta(0)<=now()-utc(datetime.fromisoformat(state['last_check'])) < timedelta(hours=24)
    except (ValueError,KeyError,TypeError): fresh=False
    return {'current':current,'latest':latest,'status':('available' if b>a else 'current' if b==a else 'newer') if a and b and fresh and state.get('last_check_ok') is True else 'unknown'}

class Job(Base):
    __tablename__='device_manager_jobs'
    id: Mapped[int]=mapped_column(primary_key=True)
    owner: Mapped[int]=mapped_column(Integer,index=True)
    mode: Mapped[str]=mapped_column(String(20))
    state: Mapped[str]=mapped_column(String(20),index=True)
    channel: Mapped[str]=mapped_column(String(16))
    interval: Mapped[int]=mapped_column(Integer)
    due: Mapped[datetime]=mapped_column(DateTime(timezone=True),index=True)
    created: Mapped[datetime]=mapped_column(DateTime(timezone=True))
    entries: Mapped[list]=mapped_column(JSON)

class Schedule(Base):
    __tablename__='device_manager_schedules'
    id: Mapped[int]=mapped_column(primary_key=True)
    owner: Mapped[int]=mapped_column(Integer,index=True)
    mode: Mapped[str]=mapped_column(String(20))
    channel: Mapped[str]=mapped_column(String(16))
    interval: Mapped[int]=mapped_column(Integer)
    frequency: Mapped[str]=mapped_column(String(16))
    anchor_day: Mapped[int]=mapped_column(Integer)
    due: Mapped[datetime]=mapped_column(DateTime(timezone=True),index=True)
    enabled: Mapped[int]=mapped_column(Integer,default=1)
    entries: Mapped[list]=mapped_column(JSON)


def advance(d,frequency,anchor):
    d=utc(d)
    if frequency=='daily': return d+timedelta(days=1)
    if frequency=='weekly': return d+timedelta(days=7)
    y,m=d.year+(d.month==12),d.month%12+1
    return d.replace(year=y,month=m,day=min(anchor,calendar.monthrange(y,m)[1]))


def schedule_out(s):
    return dict(id=s.id,mode=s.mode,frequency=s.frequency,due=utc(s.due).isoformat(),enabled=bool(s.enabled),entries=s.entries)


class Request(BaseModel):
    ids: list[int]=Field(min_length=1,max_length=200)
    mode: str='backup'
    channel: str='long-term'
    interval: int=Field(default=60,ge=0,le=3600)
    scheduled: datetime | None=None
    frequency: str="once"
    error_policy: str="stop"
    retries: int=Field(default=2,ge=0,le=3)
    notify: bool=False
    expected_version: str | None=None
    firmware_source: str="internet"
    confirm_firmware: bool=False
    window_minutes: int=Field(default=120,ge=15,le=720)

def out(j):
    result = dict(id=j.id,mode=j.mode,state=j.state,channel=j.channel,interval=j.interval,due=utc(j.due).isoformat(),created=utc(j.created).isoformat(),entries=j.entries)
    if j.mode=='upgrade' and j.entries:
        result.update({k:j.entries[0].get(k) for k in ('expected_version','scheduled_at','deadline','firmware_source')})
    return result

def owned(db,user,id):
    j=db.get(Job,id)
    if not j or (j.owner!=user.id and user.role!='admin'): raise HTTPException(404,'Очередь не найдена')
    return j

@router.get('/catalog')
def catalog(db:Session=Depends(get_db),user:User=Depends(roles)):
    state=get_state(db)
    return {str(d.id):{c:availability(d.ros_version,state.get(c) or {}) for c in ('stable','long-term')} for d in db.query(Device).all()}

class PreflightRequest(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=50)
    expected_version: str
    channel: str = 'long-term'
    firmware_source: str = 'local'


@router.post('/firmware-preflight')
def firmware_preflight(p: PreflightRequest, db: Session = Depends(get_db), user: User = Depends(roles)):
    """Read-only device/package audit. Never sends install, reboot or package changes."""
    from ..api.v1.devices import _creds
    from .routeros.client import routeros_session
    if user.role != 'admin':
        raise HTTPException(403, 'Проверка обновления доступна администратору')
    if not firmware.valid_target(p.expected_version) or p.channel not in ('stable', 'long-term'):
        raise HTTPException(422, 'Укажите допустимую целевую версию и канал')
    if p.firmware_source not in ('local', 'internet'):
        raise HTTPException(422, 'Неизвестный источник обновления')
    ids = list(dict.fromkeys(p.ids))
    records = db.query(Firmware).filter(Firmware.version == p.expected_version).all() if p.firmware_source == 'local' else []
    devices = {d.id: d for d in db.query(Device).filter(Device.id.in_(ids)).all()}
    result = []
    for device_id in ids:
        d = devices.get(device_id)
        item = {'id': device_id, 'name': (d.identity or d.name) if d else str(device_id),
                'ready': False, 'architecture': None, 'current_version': None,
                'free_disk': None, 'packages': [], 'issues': []}
        result.append(item)
        if d is None:
            item['issues'].append('Устройство не найдено')
            continue
        try:
            expected = firmware.endpoint(d)
            firmware.verify_endpoint(d, {'endpoint': expected})
            creds = _creds(d)
            with routeros_session(creds) as api:
                snap = firmware.snapshot(api, expected)
                item.update(architecture=snap.architecture, current_version=snap.version,
                            free_disk=snap.free_disk)
                if firmware.numeric(p.expected_version) <= firmware.numeric(snap.version):
                    item['issues'].append('Целевая версия должна быть новее установленной')
                if p.firmware_source == 'local':
                    # Build a *diagnostic* manifest; validation errors do not hide missing packages.
                    import hashlib
                    matched = {}
                    for rec in records:
                        m = firmware.NPK_NAME.fullmatch(str(rec.name or '').lower())
                        if not m or m['version'] != p.expected_version or m['architecture'] != snap.architecture:
                            continue
                        if rec.channel not in (None, '', p.channel) or m['package'] not in snap.packages:
                            continue
                        matched.setdefault(m['package'], []).append(rec)
                    total = 0
                    for name in sorted(snap.packages):
                        candidates = matched.get(name, [])
                        if len(candidates) != 1:
                            state = 'missing' if not candidates else 'duplicate'
                        else:
                            rec = candidates[0]
                            valid = (isinstance(rec.content, bytes) and bool(rec.content)
                                     and rec.size == len(rec.content) and bool(rec.sha256)
                                     and hashlib.sha256(rec.content).hexdigest() == rec.sha256.lower())
                            state = 'ok' if valid else 'invalid'
                            if valid: total += rec.size
                        item['packages'].append({'name': name, 'state': state})
                        if state != 'ok':
                            reason = {'missing': 'отсутствует', 'duplicate': 'дубликаты', 'invalid': 'ошибка SHA256/размера'}[state]
                            item['issues'].append(f'{name}: {reason} для {p.expected_version}/{snap.architecture}')
                    if snap.free_disk < total + 4 * 1024 * 1024:
                        item['issues'].append('Недостаточно места с учётом резерва 4 MiB')
                else:
                    # An internet preflight is not an availability guarantee.
                    update_rows = list(api.path('system', 'package', 'update'))
                    if len(update_rows) != 1 or update_rows[0].get('channel') != p.channel:
                        item['issues'].append('Канал обновлений на MikroTik не совпадает')
                    dns = list(api.path('ip', 'dns'))
                    if not dns or not (dns[0].get('servers') or dns[0].get('dynamic-servers')):
                        item['issues'].append('DNS не настроен или недоступен; требуется проверка доступа в интернет')
                    item['issues'].append('Доступность целевой версии через интернет проверяется при запуске')
            item['ready'] = not item['issues']
        except firmware.FirmwareBlocked as exc:
            item['issues'].append(str(exc))
        except Exception:
            item['issues'].append('Не удалось проверить устройство (API, учётные данные или сеть)')
    from .routeros.firmware_push import local_enabled
    enabled = p.firmware_source != 'local' or local_enabled()
    return {'version': p.expected_version, 'source': p.firmware_source, 'devices': result,
            'installation_enabled': enabled, 'ready': enabled and all(x['ready'] for x in result)}


@router.get('/jobs')
def jobs(db:Session=Depends(get_db),user:User=Depends(roles)):
    q=db.query(Job)
    if user.role!='admin': q=q.filter(Job.owner==user.id)
    return [out(j) for j in q.order_by(Job.id.desc()).limit(50)]

@router.post('/jobs')
def create(p:Request,db:Session=Depends(get_db),user:User=Depends(roles)):
    if p.mode not in ('backup','check','plan','upgrade') or p.channel not in ('stable','long-term'): raise HTTPException(400,'Недопустимая операция')
    if p.scheduled and p.scheduled.tzinfo is None: raise HTTPException(400,'Укажите часовой пояс')
    if p.error_policy not in ("stop","skip","retry"): raise HTTPException(400,"Недопустимая политика ошибок")
    policy=dict(error_policy=p.error_policy if p.mode=="backup" else "stop", retries=p.retries if p.mode=="backup" else 0, notify=p.notify)
    due=max(now(),p.scheduled or now())
    ids=list(dict.fromkeys(p.ids)); ds={d.id:d for d in db.query(Device).filter(Device.id.in_(ids)).all()}
    if len(ds)!=len(ids): raise HTTPException(404,'Устройство не найдено')
    if p.mode=='upgrade':
        if p.firmware_source not in ('internet', 'local'):
            raise HTTPException(422,'Неизвестный источник обновления')
        if p.firmware_source == 'local':
            from .routeros.firmware_push import local_enabled
            if not local_enabled():
                raise HTTPException(503,'Локальный источник недоступен: включите настройку и доверенные SSH host keys')
            if not db.query(Firmware.id).filter(Firmware.version == p.expected_version).first():
                raise HTTPException(422,'В локальном репозитории нет этой версии')
        if user.role!='admin': raise HTTPException(403,'Плановое обновление RouterOS — только администратор')
        if not p.confirm_firmware or not firmware.valid_target(p.expected_version):
            raise HTTPException(422,'Укажите и подтвердите точную стабильную версию RouterOS 7')
        if p.frequency!='once' or p.interval<60:
            raise HTTPException(422,'Обновление только однократное, интервал не меньше 60 секунд')
        try:
            start, deadline=firmware.timing(p.scheduled,now(),p.window_minutes)
        except firmware.FirmwareBlocked as exc:
            raise HTTPException(422,str(exc)) from None
        if db.get_bind().dialect.name!='postgresql':
            raise HTTPException(503,'Серверная очередь требует PostgreSQL')
        # Serialize competing creation requests; never activate historical plans.
        db.execute(text('SELECT pg_advisory_xact_lock(:k)'),{'k':LOCK+1})
        for old in db.query(Job).filter(Job.mode=='upgrade',Job.state.in_(['queued','running','stopped'])).all():
            if old.state in ('queued','running') or any(e.get('state')=='running' for e in old.entries):
                raise HTTPException(409,'Уже есть активное задание обновления; сначала завершите или отмените его')
        entries=[]
        for i in ids:
            d=ds[i]
            entry=dict(id=i,name=d.identity or d.name,host=d.host,state='pending',**policy,
                       firmware_confirmed=True,expected_version=p.expected_version,firmware_source=p.firmware_source,
                       scheduled_at=start.isoformat(),deadline=deadline.isoformat(),endpoint=firmware.endpoint(d))
            try: firmware.verify_endpoint(d,entry)
            except firmware.FirmwareBlocked as exc:
                raise HTTPException(409,f'{d.identity or d.name}: {exc}') from None
            entries.append(entry)
        row=Job(owner=user.id,mode='upgrade',state='queued',channel=p.channel,interval=p.interval,due=start,created=now(),entries=entries)
        db.add(row);db.commit();db.refresh(row);return out(row)
    if p.frequency not in ('once','daily','weekly','monthly'): raise HTTPException(400,'Недопустимая периодичность')
    if p.frequency!='once':
        if p.mode=='plan' or not p.scheduled or p.scheduled<=now(): raise HTTPException(400,'Для повторения укажите будущую дату; только backup/check')
        row=Schedule(owner=user.id,mode=p.mode,channel=p.channel,interval=p.interval,frequency=p.frequency,anchor_day=utc(due).day,due=due,enabled=1,entries=[dict(id=i,name=ds[i].identity or ds[i].name,host=ds[i].host,**policy) for i in ids]);db.add(row);db.commit();db.refresh(row);return {'schedule':schedule_out(row)}
    j=Job(owner=user.id,mode=p.mode,state='planned' if p.mode=='plan' else 'queued',channel=p.channel,interval=p.interval,due=due,created=now(),entries=[dict(id=i,name=ds[i].identity or ds[i].name,host=ds[i].host,state='pending',**policy) for i in ids]); db.add(j);db.commit();db.refresh(j);return out(j)

@router.post('/jobs/{id}/stop')
def stop(id:int,db:Session=Depends(get_db),user:User=Depends(roles)):
    j=owned(db,user,id)
    if j.state in ('queued','running','planned'):
        db.execute(update(Job).where(Job.id==id,Job.state.in_(['queued','running','planned'])).values(state='stopped'));db.commit();db.refresh(j)
    return out(j)

@router.get('/schedules')
def schedules(db:Session=Depends(get_db),user:User=Depends(roles)):
    q=db.query(Schedule)
    if user.role!='admin': q=q.filter(Schedule.owner==user.id)
    return [schedule_out(s) for s in q.order_by(Schedule.due).limit(200)]

@router.post('/schedules/{id}/stop')
def stop_schedule(id:int,db:Session=Depends(get_db),user:User=Depends(roles)):
    s=db.get(Schedule,id)
    if not s or (s.owner!=user.id and user.role!='admin'): raise HTTPException(404,'Расписание не найдено')
    s.enabled=0;db.commit();return schedule_out(s)

@router.post('/jobs/{id}/retry')
def retry(id:int,db:Session=Depends(get_db),user:User=Depends(roles)):
    j=owned(db,user,id)
    if j.mode not in ('backup','check') or j.state not in ('failed','stopped') or any(e['state'] in ('running','unknown') for e in j.entries): raise HTTPException(409,'Нельзя повторить неподтверждённую операцию')
    entries=[dict(id=e['id'],name=e['name'],host=e['host'],state='pending',error_policy=e.get('error_policy','stop'),retries=e.get('retries',0),notify=e.get('notify',False)) for e in j.entries if e['state'] in ('failed','pending')]
    if not entries: raise HTTPException(409,'Нет заданий для повтора')
    row=Job(owner=user.id,mode=j.mode,state='queued',channel=j.channel,interval=j.interval,due=now(),created=now(),entries=entries);db.add(row);db.commit();db.refresh(row);return out(row)

@router.get('/jobs/{id}/archive')
def archive(id:int,db:Session=Depends(get_db),user:User=Depends(roles)):
    j=owned(db,user,id)
    if j.mode!='backup' or j.state not in ('done','failed','stopped','interrupted'): raise HTTPException(409,'Очередь не завершена')
    refs=[(e['id'],bid) for e in j.entries if e['state']=='done' for bid in e.get('backup_ids',[])]
    if not refs: raise HTTPException(404,'Нет сохранённых ссылок на копии')
    buf=io.BytesIO(); total=0
    with zipfile.ZipFile(buf,'w',zipfile.ZIP_DEFLATED) as z:
        for did,bid in refs:
            b=db.get(DeviceBackup,bid)
            if not b or b.device_id!=did: raise HTTPException(409,'Копия больше недоступна')
            total+=b.size
            if total>100*1024*1024: raise HTTPException(413,'Архив превышает 100 МБ')
            name=re.sub(r'[^A-Za-z0-9_.-]','_',b.filename)
            z.writestr(f'{did}/{bid}-{name}',b.content)
    return Response(buf.getvalue(),media_type='application/zip',headers={'Content-Disposition':f'attachment; filename="job-{id}.zip"','Cache-Control':'no-store'})


def enqueue_schedules(db):
    current=now()
    for s in db.query(Schedule).filter(Schedule.enabled==1,Schedule.due<=current).with_for_update().all():
        user=db.get(User,s.owner)
        if not user or not user.is_active or user.role not in ('admin','operator') or s.mode not in ('backup','check'):
            s.enabled=0;continue
        # Skip missed occurrences; never create a second active run of the same schedule.
        active=any(e.get('schedule_id')==s.id for j in db.query(Job).filter(Job.state.in_(['queued','running'])).all() for e in j.entries)
        if not active:
            db.add(Job(owner=s.owner,mode=s.mode,state='queued',channel=s.channel,interval=s.interval,due=current,created=current,entries=[dict(e,state='pending',schedule_id=s.id) for e in s.entries]))
        nxt=utc(s.due)
        while nxt<=current: nxt=advance(nxt,s.frequency,s.anchor_day)
        s.due=nxt
    db.commit()

_last_health_scan = None

def run_tick():
    global _last_health_scan
    # Production PostgreSQL session lock: one worker across processes. No SQLite execution.
    if engine.dialect.name!='postgresql': return
    with engine.connect() as lock:
        if not lock.execute(text('SELECT pg_try_advisory_lock(:k)'),{'k':LOCK}).scalar(): return
        try:
            from time import monotonic
            if _last_health_scan is None or monotonic()-_last_health_scan >= 3600:
                _last_health_scan = monotonic()
                try:
                    from .backup_health import warn_stale
                    with SessionLocal() as db: warn_stale(db)
                except Exception:
                    from loguru import logger
                    logger.warning('Backup health: scheduled scan not confirmed')
            work()
            from . import management_jobs
            management_jobs.tick()
        finally:
            try:
                lock.execute(text('SELECT pg_advisory_unlock(:k)'),{'k':LOCK});lock.commit()
            except Exception:
                lock.invalidate()
                raise

def error_detail(exc):
    # Never persist raw device errors: fetch traps can contain temporary credentials.
    if isinstance(exc, firmware.FirmwareBlocked): return str(exc), False
    if isinstance(exc, HTTPException):
        if exc.status_code==404: return 'Устройство или запись не найдены', False
        if exc.status_code in (401,403): return 'Недостаточно прав для операции', False
        if exc.status_code==502:
            msg=str(exc.detail).lower()
            if 'sftp pull:' in msg:
                if 'trusted host key' in msg: return 'SFTP PULL: требуется проверенный SSH host key в known_hosts', False
                if 'ssh connection' in msg: return 'SFTP PULL: проверьте SSH, учётные данные и ключ устройства', False
                return 'SFTP PULL: не удалось получить полную пару файлов; проверьте SSH/API', False
            if 'device mode:' in msg or 'not allowed by device-mode' in msg: return 'Device Mode: операция запрещена; проверьте fetch. Требуется ручное действие на устройстве', False
            if 'backup save failed' in msg: return 'RouterOS: не удалось создать бинарную копию; проверьте права и место', True
            if 'export failed' in msg: return 'RouterOS: не удалось экспортировать конфигурацию', True
            if 'not appeared' in msg: return 'RouterOS: файл не появился на устройстве', True
            if 'push ' in msg and 'failed' in msg: return 'FTP PUSH: устройство не передало файл; проверьте исходящий доступ к контроллеру', True
            if 'timeout' in msg or 'timed out' in msg: return 'Истекло время ожидания API или FTP', True
            if 'connect ' in msg: return 'Не удалось подключиться к RouterOS API', True
            return 'Ошибка RouterOS/FTP (HTTP 502); проверьте доступ и права', True
    if isinstance(exc, ValueError) and str(exc)=='device changed': return 'Устройство удалено или изменился его адрес', False
    if isinstance(exc, ValueError) and str(exc)=='pair missing': return 'Не подтверждена новая пара .backup/.rsc; проверьте список копий', False
    return 'Операция не подтверждена; проверьте журнал backend и наличие файлов', False


def notify_terminal(db, job):
    # Best effort after commit; no credentials or device addresses in messages.
    if not any(e.get('notify') for e in job.entries): return
    try:
        from .settings import get_settings_dict
        import httpx
        from loguru import logger
        cfg=get_settings_dict(db).get('telegram',{})
        if not cfg.get('enabled') or not cfg.get('bot_token') or not cfg.get('chat_id'): return
        ok=sum(e['state']=='done' for e in job.entries)
        failed=sum(e['state'] in ('failed','unknown') for e in job.entries)
        label={'done':'завершена','failed':'ошибка','stopped':'остановлена','interrupted':'прервана; требуется ручная проверка'}.get(job.state,job.state)
        r=httpx.post('https://api.telegram.org/bot'+cfg['bot_token']+'/sendMessage',json={'chat_id':cfg['chat_id'],'text':f'ROSzetta: очередь #{job.id} ({job.mode}) — {label}. Успешно: {ok}, ошибок: {failed}, всего: {len(job.entries)}.'},timeout=8.0)
        if r.status_code!=200: logger.warning('Device Manager Telegram: HTTP {}',r.status_code)
    except Exception:
        from loguru import logger
        logger.warning('Device Manager Telegram: notification not confirmed')


def work():
    from ..api.v1.backups import create_backup
    with SessionLocal() as db:
        # A prior process died during a request: never replay it automatically.
        for stale in db.query(Job).filter(Job.state=='running').all():
            stale.state='interrupted';stale.entries=[dict(e,state='unknown') if e['state']=='running' else e for e in stale.entries]
        for stopped in db.query(Job).filter(Job.state=='stopped').all():
            if any(e['state']=='running' for e in stopped.entries):
                stopped.entries=[dict(e,state='unknown') if e['state']=='running' else e for e in stopped.entries]
        db.commit()
        enqueue_schedules(db)
        j=db.query(Job).filter(Job.state=='queued',Job.due<=now()).order_by(Job.due,Job.id).with_for_update().first()
        if not j: return
        if j.mode in ('backup','upgrade') and vault_service.is_initialized_cached() is True and not vault_service.is_unlocked():
            if j.mode=='upgrade':
                # Do not wait indefinitely and then start outside the agreed window.
                try: firmware.approved(j.entries[0],now())
                except firmware.FirmwareBlocked as exc:
                    j.state='failed'; j.entries=[dict(e,state='failed',detail=str(exc)) if e['state']=='pending' else e for e in j.entries];db.commit();notify_terminal(db,j)
                else:
                    if any(e['state']=='pending' and e.get('detail')!='Ожидание разблокировки Vault' for e in j.entries):
                        j.entries=[dict(e,detail='Ожидание разблокировки Vault') if e['state']=='pending' else e for e in j.entries];db.commit()
            return
        user=db.get(User,j.owner)
        if not user or not user.is_active or user.role not in ('admin','operator') or (j.mode=='upgrade' and user.role!='admin'):
            j.state='failed'
            j.entries=[dict(e,state='failed',detail='Нет действующего разрешения владельца задания') if e['state']=='pending' else e for e in j.entries];db.commit();notify_terminal(db,j);return
        idx=next((i for i,e in enumerate(j.entries) if e['state']=='pending'),None)
        if idx is None: j.state='failed' if any(e['state']=='failed' for e in j.entries) else 'done';db.commit();return
        entries=[dict(e) for e in j.entries];e=entries[idx];e['state']='running';e['attempts']=e.get('attempts',0)+1;j.entries=entries;j.state='running';jid=j.id;db.commit()
        old=None
        try:
            d=db.get(Device,e['id'])
            if not d or d.host!=e['host']: raise ValueError('device changed')
            if j.mode=='backup':
                old={r[0] for r in db.query(DeviceBackup.id).filter(DeviceBackup.device_id==d.id).all()}
                fresh=[b for b in create_backup(d.id,db,user) if b.id not in old and b.size>0]
                if not any(b.fmt=='binary' and b.filename.endswith('.backup') and any(t.fmt=='text' and t.filename==b.filename[:-7]+'.rsc' for t in fresh) for b in fresh): raise ValueError('pair missing')
                e['backup_ids']=[b.id for b in fresh]
                e['detail']='Новая пара файлов получена'
            elif j.mode=='upgrade':
                from ..api.v1.devices import _creds
                from .routeros.client import routeros_session
                from .routeros.device_mode import guard_mode
                # A single job is picked by the existing PostgreSQL session lock.
                def validate():
                    firmware.approved(e,now())
                    db.expire_all()
                    latest_job=db.get(Job,jid)
                    owner=db.get(User,latest_job.owner) if latest_job else None
                    if latest_job is None or latest_job.state!='running':
                        raise firmware.FirmwareBlocked('Остановлено до отправки команды установки')
                    if not owner or not owner.is_active or owner.role!='admin':
                        raise firmware.FirmwareBlocked('Администратор больше не имеет разрешения')
                    if vault_service.is_initialized_cached() is True and not vault_service.is_unlocked():
                        raise firmware.FirmwareBlocked('Vault заблокирован; установка отменена')
                    firmware.verify_endpoint(db.get(Device,e['id']),e)
                    # Release the read transaction before further network calls.
                    db.commit()
                def publish(detail):
                    e['detail']=detail
                    row=db.query(Job).filter(Job.id==jid).with_for_update().populate_existing().one()
                    if e.get('install_intent') and detail.startswith('Отправка команды'):
                        if row.state!='running':
                            db.rollback();raise firmware.FirmwareBlocked('Остановлено до отправки команды установки')
                        firmware.approved(e,now())
                    row.entries=[dict(x) for x in entries];db.commit()
                def connect():
                    latest=db.get(Device,e['id'],populate_existing=True)
                    firmware.verify_endpoint(latest,e)
                    creds=_creds(latest);db.commit()
                    return routeros_session(creds)
                def backup():
                    old_ids={r[0] for r in db.query(DeviceBackup.id).filter(DeviceBackup.device_id==e['id']).all()}
                    return firmware.fresh_pair(create_backup(e['id'],db,user),old_ids,e['id'])
                def local_prepare(snap, target, selected_channel):
                    records=db.query(Firmware).filter(Firmware.version==target).all()
                    items=firmware.local_manifest(records,snap,target,selected_channel)
                    db.commit()
                    return items
                def local_upload(items,snap):
                    from .routeros.firmware_push import upload_packages
                    latest=db.get(Device,e['id'],populate_existing=True)
                    firmware.verify_endpoint(latest,e)
                    credentials=_creds(latest)
                    db.commit()
                    upload_packages(credentials,items,snap)
                def local_prepare(snap, target, selected_channel):
                    records=db.query(Firmware).filter(Firmware.version==target).all()
                    items=firmware.local_manifest(records,snap,target,selected_channel)
                    db.commit()
                    return items
                def local_upload(items,snap):
                    from .routeros.firmware_push import upload_packages
                    latest=db.get(Device,e['id'],populate_existing=True)
                    firmware.verify_endpoint(latest,e)
                    credentials=_creds(latest)
                    db.commit()
                    upload_packages(credentials,items,snap)
                def local_prepare(snap, target, selected_channel):
                    records=db.query(Firmware).filter(Firmware.version==target).all()
                    items=firmware.local_manifest(records,snap,target,selected_channel)
                    db.commit()
                    return items
                def local_upload(items,snap):
                    from .routeros.firmware_push import upload_packages
                    latest=db.get(Device,e['id'],populate_existing=True)
                    firmware.verify_endpoint(latest,e)
                    credentials=_creds(latest)
                    db.commit()
                    upload_packages(credentials,items,snap)
                e['detail']=firmware.run_update(entry=e,channel=j.channel,connect=connect,
                    guard=lambda api:guard_mode(api,block_flagged=True),backup=backup,publish=publish,validate=validate,
                    local_prepare=local_prepare,local_upload=local_upload)
            elif j.mode=='check':
                e['detail']=availability(d.ros_version,(get_state(db).get(j.channel) or {}))
            else: raise ValueError('invalid mode')
            e['state']='done'
        except Exception as exc:
            db.rollback();e['state']='failed';e['detail'], retryable=error_detail(exc)
            if j.mode=='upgrade' and (e.get('install_intent') or e.get('transfer_intent') or isinstance(exc,firmware.FirmwareUnconfirmed)):
                e['state']='unknown';retryable=False
                e['detail']='Установка могла начаться; проверьте версию, пакеты и доступность вручную. Автоповтор запрещён' 
            # Only retry a known failed backup with no newly committed DB files.
            if j.mode=='backup' and retryable and e.get('error_policy')=='retry' and e['attempts']<=e.get('retries',0) and old is not None:
                try:
                    current={r[0] for r in db.query(DeviceBackup.id).filter(DeviceBackup.device_id==e['id']).all()}
                    if current==old:
                        e['state']='pending';e['detail']+='; повтор запланирован'
                except Exception: db.rollback()
            from loguru import logger
            logger.warning('Device Manager job {} device {} attempt {}: {}',jid,e['id'],e['attempts'],e['detail'])
        j=db.query(Job).filter(Job.id==jid).with_for_update().populate_existing().one()
        j.entries=entries
        if j.state!='stopped':
            stop_on_error=e['state']=='failed' and (j.mode!='backup' or e.get('error_policy','stop')=='stop')
            j.state='interrupted' if e['state']=='unknown' else 'failed' if stop_on_error else 'queued' if any(x['state']=='pending' for x in entries) else 'failed' if any(x['state']=='failed' for x in entries) else 'done'
            if j.mode!='upgrade' or j.state=='queued':
                j.due=now()+timedelta(seconds=max(30,j.interval) if e['state']=='pending' else j.interval)
        db.commit()
        if j.state in ('done','failed','stopped','interrupted'): notify_terminal(db,j)


class RetentionRequest(BaseModel):
    pairs: int=Field(default=10,ge=1,le=100)
    days: int=Field(default=0,ge=0,le=3650)

@router.get('/retention')
def get_retention(db:Session=Depends(get_db),user:User=Depends(roles)):
    from ..api.v1.backups import retention_policy
    return dict(retention_policy(db),can_edit=user.role=='admin')

@router.put('/retention')
def set_retention(p:RetentionRequest,db:Session=Depends(get_db),user:User=Depends(require_role('admin'))):
    from .settings import update_settings_dict
    update_settings_dict(db,{'backup_retention':p.model_dump()})
    return dict(p.model_dump(),can_edit=True)
