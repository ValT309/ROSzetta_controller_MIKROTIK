"""Read-only checks; no commands that alter a router."""
import re


def inspect_router(api, model, ports, split_dns=False, wifi_enabled=False, wifi_mode='local'):
    def rows(*path):
        return list(api.path(*path))
    resource = rows('system', 'resource')[0]
    identity = rows('system', 'identity')[0]
    interfaces = rows('interface')
    physical = {str(r.get('name','')) for r in interfaces if r.get('type') == 'ether'}
    names = sorted({str(r.get('name','')) for r in interfaces if r.get('name')})
    version = str(resource.get('version',''))
    board = str(resource.get('board-name',''))
    checks = []
    def check(label, ok, detail):
        checks.append(dict(label=label, ok=bool(ok), detail=detail))
    check('RouterOS 7', bool(re.match(r'^7\.', version)), version)
    norm = re.sub(r'[^a-z0-9]', '', board.lower().replace('²','2'))
    match = ('hapax2' in norm or 'c52ig' in norm) if model == 'hAP ax²' else 'rb5009' in norm if model == 'RB5009' else False
    check('Модель', match, board if model != 'Другая RouterOS 7' else 'Сверьте модель вручную: '+board)
    missing = sorted(set(ports)-physical)
    check('Физические порты', not missing and bool(ports), ', '.join(missing) if missing else 'Все указанные порты найдены' if ports else 'Порты не заданы')
    # Existing objects make a clean-configuration export unsafe to apply directly.
    existing = [p for p in [('interface','bridge'),('interface','vlan'),('ip','address'),('ip','firewall','filter'),('ip','firewall','nat')] if rows(*p)]
    check('Признаки существующей конфигурации', not existing, '; '.join('/'+'/'.join(p) for p in existing) if existing else 'Базовые проверенные разделы пусты; это не гарантия чистой конфигурации')
    if split_dns:
        try:
            rows('ip','dns','forwarders'); supported=True
        except Exception:
            supported=False
        check('DNS Forwarders', supported, 'Раздел доступен' if supported else 'Раздел недоступен или недостаточно прав')
    if wifi_enabled:
        try:
            wifi=rows('interface','wifi'); supported=wifi_mode=='capsman' or len(wifi)>=2
            if wifi_mode=='capsman': rows('interface','wifi','capsman')
        except Exception:
            supported=False
        check('Wi-Fi / CAPsMAN', supported, 'Раздел доступен' if supported else 'Проверьте пакет Wi-Fi, версию и интерфейсы')
    return dict(identity=str(identity.get('name','')), board=board, version=version, interfaces=names, checks=checks)
