"""Draft L2/L3 generator. No router connections or side effects."""
import ipaddress as ip
import re


def generate(ports, vlans, dns, wan_port, model, wifi_vlans=(), split_dns=False, guest_ids=(), bridge=None, wan_address=""):
    errors = []
    lines = ['# --- Bridge / VLAN / DHCP ---', '/interface bridge add name=bridge-lan protocol-mode=rstp vlan-filtering=no ingress-filtering=yes frame-types=admit-only-vlan-tagged']
    roles = {}
    access = {}
    trunks = set()
    hybrids = set()
    ids = set()
    networks = []
    membership = {}
    def fail(message):
        errors.append(message)
    def vid(value):
        if not re.fullmatch(r'[0-9]{1,4}', value):
            raise ValueError()
        n = int(value)
        if not 1 <= n <= 4094:
            raise ValueError()
        return n
    def members(value):
        return [s.strip() for s in value.split(',') if s.strip()]
    allowed = {'hAP ax²': {f'ether{i}' for i in range(1,6)}, 'RB5009': {f'ether{i}' for i in range(1,9)} | {'sfp-sfpplus1'}}.get(model)
    for p in ports:
        name, role = p.name, p.role
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}', name) or name in {'bridge-lan','pppoe-out1'} or name in roles or (allowed is not None and name not in allowed):
            fail(f'Некорректный или повторный порт: {name}')
            continue
        roles[name] = role
        if role in ('lan', 'hybrid'):
            try:
                access[name] = vid(p.pvid)
            except ValueError:
                fail(f'{name}: некорректный PVID')
        if role == 'trunk':
            trunks.add(name)
        if role == 'hybrid':
            hybrids.add(name)
    if roles.get(wan_port) != 'wan' or sum(r == 'wan' for r in roles.values()) != 1:
        fail('Укажите ровно один WAN-порт, совпадающий с портом провайдера.')
    try:
        servers = [str(ip.IPv4Address(s)) for s in members(dns)]
        if not servers:
            raise ValueError()
    except ValueError:
        fail('Укажите корректные IPv4 DNS-серверы.')
        servers = []
    native = None
    if bridge is not None and bridge.enabled:
        try:
            native = vid(bridge.pvid)
            iface = ip.IPv4Interface(bridge.address)
            net, gw = iface.network, iface.ip
            if net.prefixlen > 30 or not net.network_address < gw < net.broadcast_address:
                raise ValueError()
            if wan_address and net.overlaps(ip.IPv4Interface(wan_address).network):
                fail('Bridge: пересечение со статической WAN-сетью')
            ids.add(native)
            networks.append(net)
            native_ports = [t for t, n in access.items() if n == native]
            if not native_ports:
                fail('Bridge: назначьте Access или Hybrid порт с PVID Bridge')
            lines[1] = f'/interface bridge add name=bridge-lan protocol-mode=rstp vlan-filtering=no ingress-filtering=yes frame-types=admit-all pvid={native}'
            lines.append(f'/interface bridge vlan add bridge=bridge-lan vlan-ids={native} untagged='+','.join(['bridge-lan']+native_ports))
            lines.append(f'/ip address add address={iface} interface=bridge-lan')
            if bridge.dhcp:
                start, end = ip.IPv4Address(bridge.poolStart), ip.IPv4Address(bridge.poolEnd)
                if not net.network_address < start <= end < net.broadcast_address or start <= gw <= end:
                    raise ValueError()
                lines.extend([f'/ip pool add name=pool-bridge ranges={start}-{end}', f'/ip dhcp-server network add address={net} gateway={gw} dns-server='+ (str(gw) if split_dns else ','.join(servers)), '/ip dhcp-server add name=dhcp-bridge interface=bridge-lan address-pool=pool-bridge disabled=no'])
            if native in guest_ids or native in wifi_vlans:
                fail('Bridge: PVID не должен совпадать с гостевым или Wi-Fi VLAN')
        except (ValueError, TypeError):
            fail('Bridge: проверьте PVID, IPv4/CIDR, статический WAN и DHCP-пул (границы внутри подсети, без IP шлюза)')
    for v in vlans:
        try:
            n = vid(v.id)
        except ValueError:
            fail(f'Некорректный VLAN ID: {v.id}')
            continue
        if n in ids:
            fail(f'Повторный VLAN ID: {n}')
            continue
        ids.add(n)
        tagged, untagged = members(v.tagged), members(v.untagged)
        if len(set(tagged + untagged)) != len(tagged + untagged):
            fail(f'VLAN {n}: повтор порта или конфликт tagged/untagged')
        if not tagged and not untagged and n not in wifi_vlans:
            fail(f'VLAN {n}: назначьте хотя бы один порт')
        for t in tagged:
            if t not in trunks and t not in hybrids:
                fail(f'VLAN {n}: {t} должен быть trunk или hybrid')
            if access.get(t) == n:
                fail(f'VLAN {n}: {t} не может быть tagged для своего PVID')
            membership.setdefault(t, set()).add(n)
        for t in untagged:
            if access.get(t) != n:
                fail(f'VLAN {n}: {t} должен быть LAN access или hybrid с PVID {n}')
        for t, pvid in access.items():
            if pvid == n and t not in untagged:
                fail(f'VLAN {n}: добавьте {t} в untagged')
        iface = f'vlan{n}'
        lines.append(f'/interface bridge vlan add bridge=bridge-lan vlan-ids={n} tagged='+','.join(['bridge-lan']+tagged)+((' untagged='+','.join(untagged)) if untagged else ''))
        lines.append(f'/interface vlan add name={iface} interface=bridge-lan vlan-id={n}')
        try:
            net = ip.IPv4Network(v.subnet, strict=True)
            gw = ip.IPv4Address(v.gateway)
            if net.prefixlen > 30 or not net.network_address < gw < net.broadcast_address:
                raise ValueError()
        except ValueError:
            fail(f'VLAN {n}: некорректная подсеть или шлюз')
            continue
        if any(net.overlaps(other) for other in networks):
            fail(f'VLAN {n}: пересечение подсетей')
        networks.append(net)
        lines.append(f'/ip address add address={gw}/{net.prefixlen} interface={iface}')
        if v.dhcp:
            try:
                start, end = ip.IPv4Address(v.poolStart), ip.IPv4Address(v.poolEnd)
                if not net.network_address < start <= end < net.broadcast_address or start <= gw <= end:
                    raise ValueError()
            except ValueError:
                fail(f'VLAN {n}: DHCP-пул вне подсети, перевёрнут или включает шлюз')
                continue
            lines.extend([f'/ip pool add name=pool-vlan{n} ranges={start}-{end}', f'/ip dhcp-server network add address={net} gateway={gw} dns-server='+ (str(gw) if split_dns and n not in guest_ids else ','.join(servers)), f'/ip dhcp-server add name=dhcp-vlan{n} interface={iface} address-pool=pool-vlan{n} disabled=no'])
    for t,n in access.items():
        if n not in ids:
            fail(f'{t}: PVID {n} отсутствует в VLAN')
        frame = 'admit-all' if t in hybrids else 'admit-only-untagged-and-priority-tagged'
        if t in hybrids and not membership.get(t):
            fail(f'{t}: hybrid требует хотя бы один tagged VLAN')
        lines.insert(2, f'/interface bridge port add bridge=bridge-lan interface={t} pvid={n} ingress-filtering=yes frame-types={frame}')
    for t in sorted(trunks):
        if not membership.get(t):
            fail(f'{t}: trunk не назначен ни одному VLAN')
        lines.insert(2, f'/interface bridge port add bridge=bridge-lan interface={t} ingress-filtering=yes frame-types=admit-only-vlan-tagged')
    lines.append('/interface bridge set [find where name=bridge-lan] vlan-filtering=yes')
    return {'errors': errors, 'config': '\n'.join(lines) if not errors else ''}
