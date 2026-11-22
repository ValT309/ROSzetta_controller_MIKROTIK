"""Explicit management actions. Never disable the live API or alter firewall."""
import hashlib
import hmac
import ipaddress
import socket
import ssl


def truth(v):
    return v is True or str(v).lower() in ('true', 'yes', '1')


def _acl_text(value):
    # librouteros normally returns a comma-delimited string; allow a list too.
    if isinstance(value, (list, tuple)):
        if not all(isinstance(v, str) for v in value):
            raise ValueError('Не удалось прочитать разрешённые адреса IP Services')
        value = ','.join(value)
    if not isinstance(value, str):
        raise ValueError('Не получены разрешённые адреса IP Services')
    return value.strip()


def service_networks(value):
    return [ipaddress.ip_network(x.strip(), strict=False) for x in _acl_text(value).split(',') if x.strip()]


def service_address_field(row):
    # RouterOS 7.24 renamed address -> available-from. Never assume that
    # missing data means unrestricted access, nor retry a write on another key.
    if 'available-from' in row:
        value = _acl_text(row['available-from'])
        if 'address' in row and row['address'] is not None:
            if set(service_networks(value)) != set(service_networks(row['address'])):
                raise ValueError('IP Services: address и available-from различаются; проверьте вручную')
        return 'available-from'
    if 'address' in row:
        _acl_text(row['address'])
        return 'address'
    raise ValueError('IP Services не вернул address или available-from')


def service_address(row):
    return _acl_text(row[service_address_field(row)])


def static_service(api, name):
    rows = [r for r in api.path('ip', 'service') if r.get('name') == name and not truth(r.get('dynamic'))]
    if len(rows) != 1 or not rows[0].get('.id'):
        raise ValueError('Не найдена однозначная статическая служба '+name)
    row = dict(rows[0])
    # Keep actual wire field in the row, expose a backwards-compatible alias.
    row['address'] = service_address(row)
    return row


def prepare_service(api, name, source, certificate=None):
    if name not in ('ssh', 'api-ssl'):
        raise ValueError('Недопустимая служба')
    ip = ipaddress.ip_network(source, strict=True)
    if ip.version != 4 or ip.prefixlen != 32 or ip.network_address.is_unspecified:
        raise ValueError('Укажите фактический IPv4 контроллера /32')
    row = static_service(api, name)
    old = str(row.get('address') or '')
    disabled = truth(row.get('disabled'))
    if any(ipaddress.ip_network(v.strip(), strict=False).prefixlen == 0 for v in old.split(',') if v.strip()):
        raise ValueError('Служба имеет правило доступа /0; проверьте адреса вручную')
    if not disabled and not old:
        # An enabled unrestricted service is not silently restricted.
        raise ValueError('Служба уже включена без ограничения адресов; настройте её отдельно')
    addresses = [str(ipaddress.ip_network(v.strip(), strict=False)) for v in old.split(',') if v.strip()]
    if not any(ip.version == n.version and ip.subnet_of(n) for n in map(lambda v: ipaddress.ip_network(v, strict=False), addresses)):
        addresses.append(str(ip))
    args = {'.id': row['.id'], service_address_field(row): ','.join(addresses), 'disabled': 'no'}
    if name == 'api-ssl':
        cert = (certificate or str(row.get('certificate') or '')).strip()
        if not cert or cert == 'none':
            raise ValueError('Сначала установите TLS-сертификат на MikroTik')
        if not disabled and cert != row.get('certificate'):
            raise ValueError('Нельзя заменить сертификат действующей службы этим действием')
        if not any(r.get('name') == cert for r in api.path('certificate')):
            raise ValueError('Сертификат не найден')
        args['certificate'] = cert
    list(api.path('ip','service')('set', **args))
    updated = static_service(api, name)
    actual = {str(n) for n in service_networks(service_address(updated))}
    if truth(updated.get('disabled')) or actual != set(addresses) or (name=='api-ssl' and updated.get('certificate') != args['certificate']):
        # RouterOS may canonicalize addresses; report unknown rather than repeat a write.
        raise ValueError('Изменение отправлено, но результат не подтверждён; проверьте службу')
    return updated


def append_service_source(api, name, source):
    """Add only one explicit IPv4 /32, never narrow an unrestricted service.
    Do not modify certificate, port, disabled state or unrelated ACL entries.
    """
    if name not in ('ssh', 'api', 'api-ssl'):
        raise ValueError('Недопустимая служба')
    ip = ipaddress.ip_network(source, strict=True)
    if ip.version != 4 or ip.prefixlen != 32 or ip.network_address.is_unspecified:
        raise ValueError('Укажите IPv4 контроллера /32')
    old = static_service(api, name)
    nets = service_networks(service_address(old))
    if not nets or any(n.prefixlen == 0 for n in nets):
        # An unrestricted ACL must not silently become restricted.
        return old, old
    if any(ip.version == n.version and ip.subnet_of(n) for n in nets):
        return old, old
    if static_service(api, name) != old:
        raise ValueError('Служба изменилась во время проверки; повторите диагностику')
    desired = set(nets) | {ip}
    list(api.path('ip','service')('set', **{'.id': old['.id'], service_address_field(old): ','.join(map(str, [*nets, ip]))}))
    now = static_service(api, name)
    if set(service_networks(service_address(now))) != desired or any(now.get(k) != old.get(k) for k in ('port','disabled','certificate','.id')):
        raise ValueError('Изменение адресов не подтверждено; проверьте IP Services вручную')
    return old, now


def certificate_fingerprint(host, port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=8) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            if not der:
                raise ValueError('Сертификат не получен')
            return hashlib.sha256(der).hexdigest()


def pinned_wrapper(ctx, fingerprint):
    def wrap(sock):
        tls = ctx.wrap_socket(sock)
        der = tls.getpeercert(binary_form=True)
        if not der or not hmac.compare_digest(hashlib.sha256(der).hexdigest(), fingerprint):
            tls.close()
            raise ssl.SSLError('TLS certificate fingerprint mismatch')
        return tls
    return wrap


def rename_identity(api, name):
    list(api(cmd='/system/identity/set', name=name))
    rows = list(api.path('system','identity'))
    if not rows or rows[0].get('name') != name:
        raise ValueError('Identity отправлен, но не подтверждён; проверьте устройство')
