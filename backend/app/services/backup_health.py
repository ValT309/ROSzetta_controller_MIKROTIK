"""Read-only backup inventory and conservative export change detection."""
from datetime import datetime, timezone, timedelta
import re

STALE_HOURS = 48
HEALTH_SOURCE = 'backup-health'
HEADER = re.compile(r'^# (?:\d{4}-\d{2}-\d{2}|[a-z]{3}/\d{1,2}/\d{4})[ T].*\bby RouterOS\b.*$', re.I)

def utc(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)

def normalized_export(data: bytes) -> str:
    # Only documented volatile leading export timestamp; preserve version, all commands,
    # comments, order, whitespace inside values, scripts and continuation lines.
    text = data.decode('utf-8-sig', errors='strict').replace('\r\n', '\n')
    lines = text.split('\n')
    for i, line in enumerate(lines):
        if not line.strip():
            continue
        if HEADER.fullmatch(line):
            lines[i] = '# by RouterOS' + re.split(r'\bby RouterOS\b', line, maxsplit=1, flags=re.I)[1]
        break
    return '\n'.join(lines).rstrip('\n')

def complete_pairs(rows):
    groups = {}
    for r in rows:
        suffix = '.backup' if r.fmt == 'binary' else '.rsc' if r.fmt == 'text' else None
        if not suffix or not r.filename.endswith(suffix) or r.size <= 0 or r.created_at is None:
            continue
        groups.setdefault((r.device_id, r.filename[:-len(suffix)]), {}).setdefault(r.fmt, []).append(r)
    result = {}
    for (did, _), group in groups.items():
        if len(group.get('binary', [])) != 1 or len(group.get('text', [])) != 1:
            continue
        b, t = group['binary'][0], group['text'][0]
        result.setdefault(did, []).append((max(utc(b.created_at), utc(t.created_at)), b.id, t.id))
    for pairs in result.values():
        pairs.sort(reverse=True)
    return result

def inventory(db, current=None):
    from ..models.backup import DeviceBackup as B
    from ..models.device import Device
    current = current or datetime.now(timezone.utc)
    rows = db.query(B.id, B.device_id, B.filename, B.fmt, B.size, B.created_at).all()
    pairs = complete_pairs(rows)
    out = {}
    for (did,) in db.query(Device.id).all():
        entries = pairs.get(did, [])
        last = entries[0][0] if entries else None
        state = 'missing' if last is None else 'stale' if current-last >= timedelta(hours=STALE_HOURS) else 'fresh'
        out[str(did)] = {'status':state, 'last_success':last.isoformat() if last else None}
    return {'threshold_hours':STALE_HOURS, 'devices':out}

def inspect_new_pair(db, device_id, text_id):
    from ..models.backup import DeviceBackup as B
    from ..models.device import Device
    from .events import add_alert
    from html import escape
    rows = db.query(B.id, B.device_id, B.filename, B.fmt, B.size, B.created_at).filter(B.device_id == device_id).all()
    pairs = complete_pairs(rows).get(device_id, [])
    # Do not compare against a newer concurrent backup or an incomplete pair.
    if not pairs or pairs[0][2] != text_id or len(pairs)<2:
        return False
    old, new = db.get(B, pairs[1][2]), db.get(B, text_id)
    if not old or not new:
        return False
    if normalized_export(old.content) == normalized_export(new.content):
        return False
    d = db.get(Device, device_id)
    name = escape(str((d.identity or d.name) if d else device_id))
    add_alert(db, title='Изменение конфигурации MikroTik', severity='warning', category='backup', source=str(device_id), message=f'{name}: текстовый экспорт изменился. Проверьте резервные копии в ROSzetta.')
    return True

def safe_inspect(db, device_id, text_id):
    try:
        inspect_new_pair(db, device_id, text_id)
    except Exception:
        db.rollback()
        from loguru import logger
        logger.warning('Backup health: comparison not confirmed for device {}', device_id)

def warn_stale(db, current=None):
    from ..models.alert import Alert
    from .events import add_alert
    current = current or datetime.now(timezone.utc)
    # One aggregate alert per UTC day; no device names or exports in notification.
    midnight = current.replace(hour=0,minute=0,second=0,microsecond=0)
    if db.query(Alert.id).filter(Alert.source==HEALTH_SOURCE, Alert.category=='backup', Alert.created_at>=midnight).first():
        return False
    statuses = inventory(db,current)['devices'].values()
    missing = sum(x['status']=='missing' for x in statuses)
    stale = sum(x['status']=='stale' for x in statuses)
    if not (missing or stale):
        return False
    add_alert(db,title='Резервные копии требуют внимания',severity='warning',category='backup',source=HEALTH_SOURCE,message=f'Без полной пары: {missing}; старше {STALE_HOURS} ч: {stale}. Проверьте фильтр резервных копий в мониторинге.')
    return True
