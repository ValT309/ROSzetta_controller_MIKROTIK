"""Read-only inventory; return only explicitly selected non-secret fields."""
from .client import routeros_session
from .management import service_address

SECTIONS = {
    'services': (('ip','service'), ('name','disabled','port','address','dynamic')),
    'mac_telnet': (('tool','mac-server'), ('allowed-interface-list',)),
    'mac_winbox': (('tool','mac-server','mac-winbox'), ('allowed-interface-list',)),
    'discovery': (('ip','neighbor','discovery-settings'), ('discover-interface-list',)),
    'romon': (('tool','romon'), ('enabled',)),
    'dns': (('ip','dns'), ('allow-remote-requests','servers','dynamic-servers')),
}

def inspect_security(creds):
    result = {}
    with routeros_session(creds) as api:
        for name, (path, fields) in SECTIONS.items():
            try:
                rows = list(api.path(*path))
                projected = [{k:r.get(k) for k in fields} for r in rows]
                if name == 'services':
                    for raw, row in zip(rows, projected):
                        try: row['address'] = service_address(raw)
                        except ValueError: row['address'] = None
                result[name] = {'status':'ok' if rows else 'unknown', 'rows': projected}
            except Exception:
                result[name] = {'status':'unknown', 'rows':[]}
    return result
