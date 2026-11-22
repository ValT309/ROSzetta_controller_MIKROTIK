"""Persistent SSH trust and read-only security inventory; no device writes."""
from datetime import datetime, timezone, timedelta
from hashlib import sha256
import base64
import json
import os
from pathlib import Path
import socket
from sqlalchemy import Integer, String, Text, DateTime, ForeignKey, select
from sqlalchemy.orm import Mapped, mapped_column
from ..core.db import Base, SessionLocal
from ..models.device import Device

class SecurityPreferences(Base):
    __tablename__ = 'device_security_preferences'
    device_id: Mapped[int] = mapped_column(ForeignKey('devices.id', ondelete='CASCADE'), primary_key=True)
    host: Mapped[str] = mapped_column(String(255))
    key_type: Mapped[str | None] = mapped_column(String(80))
    public_key: Mapped[str | None] = mapped_column(Text)
    trusted_by: Mapped[str | None] = mapped_column(String(255))
    trusted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    backup_mode: Mapped[str] = mapped_column(String(12), default='auto')
    daily_audit: Mapped[int] = mapped_column(Integer, default=0)
    next_audit: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

class SecuritySnapshot(Base):
    __tablename__ = 'device_security_snapshots'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey('devices.id', ondelete='CASCADE'), index=True)
    host: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    source: Mapped[str] = mapped_column(String(20))
    payload: Mapped[str] = mapped_column(Text)

def fingerprint(key):
    return 'SHA256:' + base64.b64encode(sha256(key.asbytes()).digest()).decode().rstrip('=')

def scan(host):
    import paramiko
    # Key exchange only: no credentials are sent to an untrusted host.
    with socket.create_connection((host,22), timeout=8) as sock:
        transport = paramiko.Transport(sock)
        try:
            transport.banner_timeout=8
            transport.start_client(timeout=8)
            return transport.get_remote_server_key()
        finally:
            transport.close()

def legacy_keys(host):
    import paramiko
    path=Path(os.environ.get('ROSZETTA_SFTP_KNOWN_HOSTS','/app/app/roszetta_sftp_known_hosts'))
    if not path.is_file(): return []
    keys=paramiko.HostKeys(str(path)).lookup(host)
    return list(keys.values()) if keys else []

def db_key(row):
    import paramiko
    return paramiko.PKey.from_type_string(row.key_type, base64.b64decode(row.public_key,validate=True))

def prefs(db, d, create=False):
    row=db.get(SecurityPreferences,d.id)
    if row and row.host != d.host:
        if not create: return None
        # Identity changed; never carry the old key/settings to a different endpoint.
        db.delete(row); db.flush(); row=None
    if row is None and create:
        row=SecurityPreferences(device_id=d.id,host=d.host,backup_mode='auto',daily_audit=0)
        db.add(row); db.flush()
    return row

def backup_options(db,d):
    row=prefs(db,d)
    return {'backup_mode':row.backup_mode if row else 'auto', 'trusted_key':db_key(row) if row and row.public_key else None}

def trust_status(db,d):
    row=prefs(db,d)
    keys=[db_key(row)] if row and row.public_key else legacy_keys(d.host)
    return {'host':d.host,'fingerprints':[fingerprint(k) for k in keys], 'source':'database' if row and row.public_key else 'known_hosts' if keys else 'none', 'backup_mode':row.backup_mode if row else 'auto','daily_audit':bool(row and row.daily_audit),'trusted_by':row.trusted_by if row else None,'next_audit':row.next_audit.isoformat() if row and row.next_audit else None}

def compare_key(observed, current, expected, replace):
    if observed != expected: raise ValueError('Отпечаток изменился после получения; повторите проверку')
    if current and observed not in current and not replace: raise ValueError('Ключ изменился: требуется отдельное подтверждение замены')

def save_trust(db,d,expected,replace,actor):
    # Rescan during confirmation; pin exactly the observed key, never a client-supplied blob.
    host=d.host
    key=scan(host)
    # Serialize concurrent confirmation and host edits on the same device.
    locked=db.execute(select(Device).where(Device.id==d.id).with_for_update().execution_options(populate_existing=True)).scalar_one()
    if locked.host != host: raise ValueError('Адрес устройства изменился')
    current=trust_status(db,locked)['fingerprints']
    compare_key(fingerprint(key),current,expected,replace)
    row=prefs(db,locked,True)
    row.key_type=key.get_name(); row.public_key=key.get_base64(); row.trusted_by=actor; row.trusted_at=datetime.now(timezone.utc)
    db.commit()
    return trust_status(db,locked)

def findings(security):
    """Conservative baseline: configuration observations, not proof of reachability."""
    from .routeros.device_mode import boolean
    out=[]
    def add(code,level,detail): out.append({'code':code,'level':level,'detail':detail})
    sections=security or {}
    services=sections.get('services',{})
    if services.get('status')!='ok': add('services','unknown','Нет данных о службах')
    for name in ('telnet','ftp','www','ssh','winbox','api','api-ssl','www-ssl'):
        rows=[r for r in services.get('rows',[]) if r.get('name')==name and not boolean(r.get('dynamic'))]
        if not rows: continue
        for r in rows:
            if boolean(r.get('disabled')) is not False: continue
            if name in ('telnet','ftp','www'): add(name,'warning',f'{name}: включена незашифрованная служба')
            address = r.get('address')
            if address is None: add(name+'_address','unknown',f'{name}: разрешённые адреса не получены')
            else:
                from .routeros.management import service_networks
                try:
                    nets = service_networks(address)
                    if not nets or any(n.prefixlen == 0 for n in nets): add(name+'_address','warning',f'{name}: нет явного ограничения адресов службы')
                except ValueError: add(name+'_address','unknown',f'{name}: не удалось разобрать разрешённые адреса')
    for section, field in [('mac_telnet','allowed-interface-list'),('mac_winbox','allowed-interface-list'),('discovery','discover-interface-list')]:
        rows=sections.get(section,{}).get('rows',[])
        val=rows[0].get(field) if rows else None
        if val is None: add(section,'unknown','Нет данных')
        elif val in ('all','!dynamic'): add(section,'warning',f'{section}: широкая область ({val})')
    for section,field in [('romon','enabled'),('dns','allow-remote-requests')]:
        rows=sections.get(section,{}).get('rows',[])
        val=boolean(rows[0].get(field)) if rows else None
        if val is None: add(section,'unknown','Нет данных')
        elif val: add(section,'review',f'{section}: включено; проверьте ограничения доступа')
    return out

def collect(db,d,source):
    from ..core.security import decrypt_secret
    from .routeros.client import RouterOSCredentials
    from .routeros.security_audit import inspect_security
    from .routeros.device_mode import inspect_mode
    host=d.host
    creds=RouterOSCredentials(host=host,username=d.username,password=decrypt_secret(d.password_enc),port=d.port,use_tls=d.use_tls, tls_fingerprint=getattr(d, "tls_fingerprint", None))
    sec=inspect_security(creds)
    mode=inspect_mode(creds)
    data={'security':sec,'mode':mode,'findings':findings(sec)}
    row=SecuritySnapshot(device_id=d.id,host=host,source=source,payload=json.dumps(data,ensure_ascii=False))
    db.add(row); db.flush()
    old=db.query(SecuritySnapshot).filter_by(device_id=d.id).order_by(SecuritySnapshot.id.desc()).offset(30).all()
    for item in old: db.delete(item)
    db.commit(); db.refresh(row)
    return snapshot(row)

def snapshot(row):
    return {'id':row.id,'host':row.host,'created_at':row.created_at.isoformat(),'source':row.source,**json.loads(row.payload)}

def run_tick():
    from .vault import vault_service
    if vault_service.is_initialized_cached() is True and not vault_service.is_unlocked(): return
    now=datetime.now(timezone.utc)
    # One due device per tick. Claim before I/O; do not replay after crash.
    with SessionLocal() as db:
        row=db.execute(select(SecurityPreferences).where(SecurityPreferences.daily_audit==1,SecurityPreferences.next_audit<=now).order_by(SecurityPreferences.next_audit).limit(1).with_for_update(skip_locked=True)).scalar_one_or_none()
        if row is None: return
        d=db.get(Device,row.device_id)
        row.next_audit=now+timedelta(days=1)
        if not d or d.host!=row.host: row.daily_audit=0; db.commit(); return
        did=d.id; db.commit()
        try: collect(db,d,'scheduled')
        except Exception:
            db.rollback()
            from loguru import logger
            logger.warning('Scheduled security audit failed for device {}',did)
