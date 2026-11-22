"""Read-only Device Mode inspection. Missing fields are not interpreted as permission."""
from .client import RouterOSError, routeros_session

FEATURES = ('fetch','scheduler','l2tp','ipsec','routerboard','romon','sniffer','container','install-any-version','partitions','socks','pptp','bandwidth-test','traffic-gen','proxy','hotspot','smb','email','zerotier')

def boolean(value):
    v = str(value).strip().lower()
    if v in ('yes','true','1'): return True
    if v in ('no','false','0'): return False
    return None

def read_mode(api):
    try:
        rows = list(api.path('system','device-mode'))
        row = rows[0] if rows else {}
    except Exception:
        row = {}
    features = {key: boolean(row.get(key)) for key in FEATURES}
    return {'status': 'ok' if row else 'unknown', 'mode': str(row.get('mode') or ''),
            'flagged': boolean(row.get('flagged')), 'features': features,
            'allowed_versions': str(row.get('allowed-versions') or '')}

def inspect_mode(creds):
    with routeros_session(creds) as api:
        return read_mode(api)

def guard_mode(api, feature=None, block_flagged=False):
    info = read_mode(api)
    if feature and info['features'].get(feature) is False:
        raise RouterOSError('Device Mode: '+feature+'=no; операция недоступна')
    if block_flagged and info['flagged'] is True:
        raise RouterOSError('Device Mode: flagged=yes; требуется ручная проверка')
    return info
