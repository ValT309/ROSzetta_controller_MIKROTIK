"""Read-only validation of stored backup pairs; not a restore test."""
from datetime import datetime, timezone
from hashlib import sha256

MAX_AGE_SECONDS = 1800

def check_pair(rows, export_id, now=None):
    now = now or datetime.now(timezone.utc)
    export = next((r for r in rows if r.id == export_id and r.fmt == 'text' and r.filename.endswith('.rsc')), None)
    if export is None:
        return dict(ok=False, reason='export_missing', files=[], fresh=False)
    if sum(1 for r in rows if r.device_id==export.device_id and r.fmt=='text' and r.filename==export.filename)!=1:
        return dict(ok=False, reason='export_ambiguous', files=[], fresh=False)
    name = export.filename[:-4]
    matches = [r for r in rows if r.device_id == export.device_id and r.fmt == 'binary' and r.filename == name+'.backup']
    if len(matches) != 1:
        return dict(ok=False, reason='binary_missing_or_ambiguous', files=[], fresh=False)
    pair = [export, matches[0]]
    files=[]; fresh=True; valid=True
    for r in pair:
        raw = bytes(r.content or b'')
        size_ok = bool(raw) and len(raw) == r.size
        ts = r.created_at if r.created_at.tzinfo else r.created_at.replace(tzinfo=timezone.utc)
        age = (now-ts).total_seconds()
        fresh = fresh and 0 <= age <= MAX_AGE_SECONDS
        valid = valid and size_ok
        files.append(dict(id=r.id, filename=r.filename, size=r.size, size_ok=size_ok, sha256=sha256(raw).hexdigest() if raw else ''))
    try:
        source = bytes(export.content or b'').decode('utf-8-sig')
        valid = valid and any(line.lstrip().startswith('/') for line in source.splitlines()) and '\x00' not in source
    except UnicodeError:
        valid=False
    return dict(ok=bool(valid), reason='ok' if valid else 'invalid_content', files=files, fresh=bool(fresh))
