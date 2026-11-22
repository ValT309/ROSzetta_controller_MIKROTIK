from typing import Literal
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from ..deps import require_role
from ...services.routeros_generator import generate

router = APIRouter(dependencies=[Depends(require_role('admin', 'operator'))])

class Port(BaseModel):
    name: str
    role: Literal['wan','lan','trunk','hybrid','unused']
    pvid: str

class Vlan(BaseModel):
    id: str
    name: str
    subnet: str
    gateway: str
    dhcp: bool
    poolStart: str
    poolEnd: str
    tagged: str
    untagged: str

class BridgeLan(BaseModel):
    enabled: bool = False
    pvid: str = '1'
    address: str = ''
    dhcp: bool = False
    poolStart: str = ''
    poolEnd: str = ''
    ospf: bool = True

class Request(BaseModel):
    bridgeLan: BridgeLan = Field(default_factory=BridgeLan)
    wanAddress: str = '' 
    ports: list[Port] = Field(max_length=64)
    vlans: list[Vlan] = Field(max_length=256)
    dns: str
    wanPort: str
    model: str
    wifiVlans: list[int] = Field(default_factory=list, max_length=2)
    splitDns: bool = False
    guestIds: list[int] = Field(default_factory=list, max_length=256)

@router.post('/generate-network')
def generate_network(body: Request):
    return generate(body.ports, body.vlans, body.dns, body.wanPort, body.model, body.wifiVlans if body.model == "hAP ax²" else [], body.splitDns, body.guestIds, body.bridgeLan, body.wanAddress)

# Saved objects; only the owner may access them, including administrators.
from uuid import UUID
from fastapi import Body, HTTPException, Response
from pydantic import ValidationError
from sqlalchemy import select, update, delete, func, text
from ipaddress import IPv4Address
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from ...core.db import get_db
from ...models.user import User
from ...models.object_site import ObjectSite, ObjectSiteVersion
from ...services.vault import vault_service, VaultLocked, VaultError

class DraftTunnel(BaseModel):
    enabled: bool
    name: str
    server: str
    user: str
    password: str
    ipsecSecret: str
    ospfKey: str
    cost: str

class WifiNet(BaseModel):
    enabled: bool = True
    ssid: str = ''
    vlan: str = ''
    auth: str = 'wpa2-wpa3-psk'
    password: str = ''
    band24: bool = True
    band5: bool = True
    isolate: bool = False

class DnsException(BaseModel):
    domain: str = Field(max_length=253)
    servers: str = Field(max_length=512)

class Services(BaseModel):
    splitDns: bool = False
    dnsDomain: str = 'gk-nvm.ru'
    dnsCorporate: str = '10.110.0.15,10.110.0.16'
    dnsSubdomains: bool = True
    dnsExceptions: list[DnsException] = Field(default_factory=lambda: [
        DnsException(domain='vpngate1.gk-nvm.ru', servers='77.88.8.8,77.88.8.88,195.208.4.1'),
        DnsException(domain='vpngate2.gk-nvm.ru', servers='77.88.8.8,77.88.8.88,195.208.4.1'),
        DnsException(domain='bitrix.gk-nvm.ru', servers='77.88.8.8,77.88.8.1')], max_length=64)

    wifiMode: Literal['local','capsman'] = 'local'
    country: str = ''
    txPower: str = ''
    corpWifi: WifiNet = Field(default_factory=WifiNet)
    guestWifi: WifiNet = Field(default_factory=lambda: WifiNet(enabled=False,isolate=True))
    radiusAddress: str = ''
    radiusSecret: str = ''
    capVlan: str = ''
    capAddress: str = ''
    radio24: str = 'wifi2'
    radio5: str = 'wifi1'
    ntpEnabled: bool = False
    ntpServers: str = ''
    timezone: str = ''
    snmpEnabled: bool = False
    snmpUser: str = 'monitoring'
    snmpAddress: str = ''
    snmpAuthPassword: str = ''
    snmpEncryptionPassword: str = ''

class Draft(BaseModel):
    bridgeLan: BridgeLan = Field(default_factory=BridgeLan)
    profile: Literal['office','warehouse','production','retail']
    name: str = Field(max_length=200)
    model: Literal['hAP ax²','RB5009','Другая RouterOS 7']
    identity: str
    wanMode: Literal['pppoe','static','dhcp']
    wanPort: str
    pppoeUser: str
    pppoePassword: str
    wanAddress: str
    wanGateway: str
    ports: list[Port] = Field(max_length=64)
    vlans: list[Vlan] = Field(max_length=256)
    dns: str
    l2tp: list[DraftTunnel] = Field(min_length=2, max_length=2)
    loopbackAddress: str = Field(default="", max_length=32)
    ospfRouterId: str
    ospfArea: str
    firewallProfile: Literal['standard','strict','custom']
    management: str
    guests: str
    corporate: str
    wifiEnabled: bool
    wifiSsid: str
    wifiPassword: str
    services: Services = Field(default_factory=Services)

class SaveDraft(BaseModel):
    revision: int = Field(ge=0)
    draft: Draft

def _summary(row):
    return {k: getattr(row, k) for k in ('id','name','profile','model','revision','updated_at')}

def _owned(db, site_id, user):
    row = db.scalar(select(ObjectSite).where(ObjectSite.id == str(site_id), ObjectSite.owner_id == user.id))
    if row is None:
        raise HTTPException(404, 'Object not found')
    return row

def _encrypt(draft):
    raw = draft.model_dump_json()
    if len(raw.encode('utf-8')) > 256000:
        raise HTTPException(413, 'Draft too large')
    try:
        return vault_service.encrypt_secret(raw)
    except VaultLocked:
        raise HTTPException(423, 'Vault locked') from None
    except VaultError:
        raise HTTPException(503, 'Vault unavailable') from None

@router.get('/sites')
def sites(db: Session = Depends(get_db), user: User = Depends(require_role('admin','operator'))):
    return [_summary(row) for row in db.scalars(select(ObjectSite).where(ObjectSite.owner_id == user.id).order_by(ObjectSite.updated_at.desc()))]

@router.get('/sites/{site_id}')
def get_site(site_id: UUID, response: Response, db: Session = Depends(get_db), user: User = Depends(require_role('admin','operator'))):
    response.headers['Cache-Control'] = 'no-store'
    row = _owned(db, site_id, user)
    try:
        draft = Draft.model_validate_json(vault_service.decrypt_secret_v2(row.payload_enc))
    except VaultLocked:
        raise HTTPException(423, 'Vault locked') from None
    except (VaultError, ValueError):
        raise HTTPException(503, 'Cannot read draft') from None
    return {**_summary(row), 'draft': draft}

def _loopback(value):
    value = value.strip().removesuffix('/32')
    try:
        address = IPv4Address(value)
        return str(address) if str(address).startswith('10.') else None
    except ValueError:
        return None

def _check_loopback(db, site_id, value):
    address = _loopback(value)
    if not address:
        return  # incomplete drafts can still be saved
    # All writes using this rule serialize across PostgreSQL workers.
    if db.get_bind().dialect.name == 'postgresql':
        db.execute(text('SELECT pg_advisory_xact_lock(7460107)'))
    for ciphertext in db.scalars(select(ObjectSite.payload_enc).where(ObjectSite.id != str(site_id))):
        try:
            other = Draft.model_validate_json(vault_service.decrypt_secret_v2(ciphertext))
        except VaultLocked:
            raise HTTPException(423, 'Vault locked') from None
        except (VaultError, ValueError):
            raise HTTPException(503, 'Cannot verify Loopback uniqueness') from None
        if _loopback(other.loopbackAddress) == address:
            raise HTTPException(409, 'Loopback already assigned')

@router.put('/sites/{site_id}')
def save_site(site_id: UUID, payload: dict = Body(...), db: Session = Depends(get_db), user: User = Depends(require_role('admin','operator'))):
    try:
        body = SaveDraft.model_validate(payload)
    except ValidationError:
        raise HTTPException(422, "Invalid draft structure") from None
    values = dict(name=body.draft.name.strip() or 'Черновик без названия', profile=body.draft.profile, model=body.draft.model, payload_enc=_encrypt(body.draft))
    _check_loopback(db, site_id, body.draft.loopbackAddress)
    if body.revision == 0:
        row = ObjectSite(id=str(site_id), owner_id=user.id, revision=1, **values)
        db.add(row)
        try:
            db.flush()
            db.add(ObjectSiteVersion(site_id=row.id, revision=1, payload_enc=row.payload_enc, updated_at=row.updated_at))
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, 'Object already exists') from None
    else:
        old = db.scalar(select(ObjectSite).where(ObjectSite.id == str(site_id), ObjectSite.owner_id == user.id).with_for_update())
        if old is None or old.revision != body.revision:
            raise HTTPException(409, 'Object changed or unavailable')
        previous = dict(site_id=old.id, revision=old.revision, payload_enc=old.payload_enc, updated_at=old.updated_at)
        result = db.execute(update(ObjectSite).where(ObjectSite.id == str(site_id), ObjectSite.owner_id == user.id, ObjectSite.revision == body.revision).values(**values, revision=body.revision+1, updated_at=func.now()))
        if result.rowcount != 1:
            db.rollback()
            raise HTTPException(409, 'Object changed or unavailable')
        if db.get(ObjectSiteVersion, (str(site_id), body.revision)) is None:
            db.add(ObjectSiteVersion(**previous))
        db.add(ObjectSiteVersion(site_id=str(site_id), revision=body.revision+1, payload_enc=values['payload_enc']))
        db.commit()
    return _summary(_owned(db, site_id, user))

@router.delete('/sites/{site_id}', status_code=204)
def delete_site(site_id: UUID, revision: int, db: Session = Depends(get_db), user: User = Depends(require_role('admin','operator'))):
    row = db.scalar(select(ObjectSite).where(ObjectSite.id == str(site_id), ObjectSite.owner_id == user.id, ObjectSite.revision == revision).with_for_update())
    if row is None:
        raise HTTPException(409, 'Object changed or unavailable')
    db.execute(delete(ObjectSiteVersion).where(ObjectSiteVersion.site_id == str(site_id)))
    result = db.execute(delete(ObjectSite).where(ObjectSite.id == str(site_id), ObjectSite.owner_id == user.id, ObjectSite.revision == revision))
    if result.rowcount != 1:
        db.rollback()
        raise HTTPException(409, 'Object changed or unavailable')
    db.commit()
    return Response(status_code=204)


@router.get('/sites/{site_id}/versions')
def versions(site_id: UUID, response: Response, db: Session = Depends(get_db), user: User = Depends(require_role('admin','operator'))):
    response.headers['Cache-Control'] = 'no-store'
    row = _owned(db, site_id, user)
    entries = {v.revision: {'revision': v.revision, 'updated_at': v.updated_at} for v in db.scalars(select(ObjectSiteVersion).where(ObjectSiteVersion.site_id == row.id).order_by(ObjectSiteVersion.revision.desc()))}
    entries[row.revision] = {'revision': row.revision, 'updated_at': row.updated_at}
    return sorted(entries.values(), key=lambda v: v['revision'], reverse=True)

@router.get('/sites/{site_id}/versions/{revision}')
def version(site_id: UUID, revision: int, response: Response, db: Session = Depends(get_db), user: User = Depends(require_role('admin','operator'))):
    response.headers['Cache-Control'] = 'no-store'
    row = _owned(db, site_id, user)
    entry = row if revision == row.revision else db.get(ObjectSiteVersion, (row.id, revision))
    if entry is None:
        raise HTTPException(404, 'Version not found')
    try:
        draft = Draft.model_validate_json(vault_service.decrypt_secret_v2(entry.payload_enc))
    except VaultLocked:
        raise HTTPException(423, 'Vault locked') from None
    except (VaultError, ValueError):
        raise HTTPException(503, 'Cannot read draft') from None
    return {'revision': revision, 'draft': draft}

# Read-only preflight. Never accept raw RouterOS commands or credentials from the client.
class PreflightRequest(BaseModel):
    device_id: int = Field(gt=0)
    model: Literal['hAP ax²','RB5009','Другая RouterOS 7']
    ports: list[str] = Field(max_length=64)
    split_dns: bool = False
    wifi_enabled: bool = False
    wifi_mode: Literal['local','capsman'] = 'local'

@router.post('/preflight')
def preflight(body: PreflightRequest, db: Session = Depends(get_db), user: User = Depends(require_role('admin','operator'))):
    from ...models.device import Device
    from ...core.security import decrypt_secret
    from ...services.routeros.client import RouterOSCredentials, routeros_session
    from ...services.object_preflight import inspect_router
    d = db.get(Device, body.device_id)
    if not d or d.kind != 'router':
        raise HTTPException(404, 'Router not found')
    try:
        creds = RouterOSCredentials(host=d.host, username=d.username, password=decrypt_secret(d.password_enc), port=d.port, use_tls=d.use_tls, timeout=8.0, tls_fingerprint=getattr(d, "tls_fingerprint", None))
        with routeros_session(creds) as api:
            result = inspect_router(api, body.model, body.ports, body.split_dns, body.wifi_enabled, body.wifi_mode)
    except VaultLocked:
        _audit(db,user,d.id,'preflight','vault_locked')
        raise HTTPException(423, 'Vault locked')
    except Exception:
        _audit(db,user,d.id,'preflight','failed')
        raise HTTPException(502, 'Router read-only preflight failed') from None
    _audit(db,user,d.id,'preflight','returned')
    return result

# Register table before application startup (Base.metadata.create_all).
from ...models.object_operation import ObjectOperation
from ...models.backup import DeviceBackup
from ...models.device import Device
from ...services.object_plan import check_pair
from ...schemas.backup import BackupOut
from .backups import create_backup as _create_device_backup


def _audit(db, user, device_id, action, outcome, target_host=None):
    event=ObjectOperation(owner_id=user.id, device_id=device_id, action=action, outcome=outcome, target_host=target_host)
    db.add(event)
    db.commit()


def _router(db, device_id):
    device=db.get(Device, device_id)
    if not device or device.kind != 'router':
        raise HTTPException(404, 'Router not found')
    return device


@router.get('/operations/{device_id}')
def operations(device_id: int, db: Session = Depends(get_db), user: User = Depends(require_role('admin','operator'))):
    if device_id==0:
        if user.role!='admin':
            raise HTTPException(403,'Admin only')
    else:
        _router(db, device_id)
    rows=db.scalars(select(ObjectOperation).where(ObjectOperation.owner_id==user.id,ObjectOperation.device_id==device_id).order_by(ObjectOperation.id.desc()).limit(100))
    return [dict(id=r.id, action=r.action, outcome=r.outcome, created_at=r.created_at, target_host=r.target_host) for r in rows]


@router.post('/backup/{device_id}', response_model=list[BackupOut])
def constructor_backup(device_id: int, db: Session = Depends(get_db), user: User = Depends(require_role('admin','operator'))):
    _router(db, device_id)
    _audit(db,user,device_id,'backup','started')
    try:
        rows=_create_device_backup(device_id, db, user)
    except Exception:
        db.rollback()
        _audit(db,user,device_id,'backup','unconfirmed')
        raise HTTPException(502,'Backup result unconfirmed; check stored copies before retry') from None
    _audit(db,user,device_id,'backup','returned')
    return rows


@router.post('/backup-check/{device_id}/{export_id}')
def backup_check(device_id: int, export_id: int, db: Session = Depends(get_db), user: User = Depends(require_role('admin','operator'))):
    _router(db, device_id)
    export=db.get(DeviceBackup, export_id)
    if not export or export.device_id != device_id or export.fmt != 'text':
        raise HTTPException(404,'Export not found')
    # Only read matching rows; do not load all binary backups for the device.
    stem=export.filename[:-4] if export.filename.endswith('.rsc') else ''
    rows=list(db.scalars(select(DeviceBackup).where(DeviceBackup.device_id==device_id,DeviceBackup.filename.in_([stem+'.backup',export.filename]))))
    result=check_pair(rows,export_id)
    _audit(db,user,device_id,'backup_check','fresh_pair' if result['ok'] and result['fresh'] else 'not_ready')
    return result


@router.get('/compare-export/{device_id}/{export_id}')
def compare_export(device_id: int, export_id: int, db: Session = Depends(get_db), user: User = Depends(require_role('admin','operator'))):
    _router(db, device_id)
    entry=db.get(DeviceBackup, export_id)
    if not entry or entry.device_id != device_id or entry.fmt != 'text':
        raise HTTPException(404,'Export not found')
    if len(entry.content)>1200000:
        raise HTTPException(413,'Export too large for textual comparison')
    content=entry.content
    _audit(db,user,device_id,'compare_export','returned')
    return Response(content=content,media_type='text/plain; charset=utf-8',headers={'Cache-Control':'no-store'})


# Manual connection is an explicitly initiated admin-only read of a private IP.
from ipaddress import IPv4Network
from pydantic import SecretStr

class ManualPreflightRequest(BaseModel):
    host: str = Field(max_length=15)
    username: str = Field(min_length=1,max_length=64)
    password: SecretStr
    port: Literal[8728,8729] = 8729
    model: Literal['hAP ax²','RB5009','Другая RouterOS 7']
    ports: list[str] = Field(max_length=64)
    split_dns: bool = False
    wifi_enabled: bool = False
    wifi_mode: Literal['local','capsman'] = 'local'


def _manual_host(host):
    try:
        address=IPv4Address(host)
    except ValueError:
        return False
    return any(address in IPv4Network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))


@router.post('/manual-preflight')
def manual_preflight(payload: dict = Body(...), db: Session = Depends(get_db), user: User = Depends(require_role('admin'))):
    from ...services.routeros.client import RouterOSCredentials, routeros_session
    from ...services.object_preflight import inspect_router
    try:
        body=ManualPreflightRequest.model_validate(payload)
        password=body.password.get_secret_value()
        if not _manual_host(body.host) or len(password)>256 or any(ord(c)<32 or ord(c)==127 for c in body.username+password):
            raise ValueError()
    except (ValidationError, ValueError):
        raise HTTPException(422,'Invalid manual connection parameters') from None
    # Do not persist credentials or create an inventory record.
    try:
        creds=RouterOSCredentials(host=body.host,username=body.username,password=password,port=body.port,use_tls=body.port==8729,timeout=8.0)
        with routeros_session(creds) as api:
            result=inspect_router(api,body.model,body.ports,body.split_dns,body.wifi_enabled,body.wifi_mode)
    except Exception:
        _audit(db,user,0,'manual_preflight','failed',body.host)
        raise HTTPException(502,'Manual read-only preflight failed') from None
    _audit(db,user,0,'manual_preflight','returned',body.host)
    return result
