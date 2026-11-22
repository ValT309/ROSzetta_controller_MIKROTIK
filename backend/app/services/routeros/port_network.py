"""Read-only selected-port L2/L3 observations. No inferred direct endpoint links."""
from datetime import datetime, timezone
from dataclasses import replace
from ipaddress import ip_address
import re

TABLES = {
    "interfaces": ("interface",), "bridges": ("interface", "bridge"),
    "ports": ("interface", "bridge", "port"), "vlans": ("interface", "bridge", "vlan"),
    "vlan_interfaces": ("interface", "vlan"), "neighbors": ("ip", "neighbor"),
    "hosts": ("interface", "bridge", "host"), "arp": ("ip", "arp"),
    "bonds": ("interface", "bonding"),
}
LIMIT = 12000

def flag(value):
    if value is None: return None
    if str(value).lower() in ("true", "yes", "1"): return True
    if str(value).lower() in ("false", "no", "0"): return False
    return None

def names(value):
    if isinstance(value, (list, tuple)): return {str(x).strip() for x in value if str(x).strip()}
    return {x.strip() for x in str(value or "").split(",") if x.strip()}

def mac(value):
    s = str(value or "").upper()
    return s if re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", s) else None

def ip(value):
    try: return str(ip_address(str(value)))
    except ValueError: return None

def vid(value):
    return ",".join(map(str,value)) if isinstance(value,(tuple,list)) else str(value or "")

def summarize(tables, errors, port):
    # Exact current interface name; factory aliases are resolved by the existing UI.
    interfaces = tables.get("interfaces", [])
    matches = [r for r in interfaces if r.get("name") == port and str(r.get("type", "")).lower() in ("ether", "ethernet", "sfp", "qsfp")]
    if len(matches) != 1: raise ValueError("Физический интерфейс не найден или данные неоднозначны")
    bonds = [r for r in tables.get("bonds", []) if port in names(r.get("slaves")) and flag(r.get("disabled")) is not True]
    bonded = [str(r["name"]) for r in bonds if r.get("name")]
    candidates = {port, *bonded}
    members = [r for r in tables.get("ports", []) if r.get("interface") in candidates and flag(r.get("disabled")) is not True]
    bridge = None; vlans = []; mode = "unknown"; membership_source = None
    if len(members) == 1:
        p = members[0]; bname = p.get("bridge"); member = p.get("interface")
        b = next((r for r in tables.get("bridges", []) if r.get("name") == bname), {})
        filtering = flag(b.get("vlan-filtering"))
        bridge = {"name": bname, "member": member, "pvid": p.get("pvid"), "filtering": filtering,
                  "frame_types": p.get("frame-types"), "ingress_filtering": flag(p.get("ingress-filtering")),
                  "hw_configured": flag(p.get("hw")), "hw_active": flag(p.get("hw-offload")), "inactive": flag(p.get("inactive"))}
        tagged = untagged = False; complete = "vlans" not in errors
        for r in tables.get("vlans", []):
            if r.get("bridge") != bname or flag(r.get("disabled")) is True: continue
            actual = "current-tagged" in r and "current-untagged" in r
            t = member in names(r.get("current-tagged" if actual else "tagged"))
            u = member in names(r.get("current-untagged" if actual else "untagged"))
            if not actual: complete = False
            if not (t or u): continue
            vlans.append({"ids": vid(r.get("vlan-ids")), "tagged": t, "untagged": u, "actual": actual, "dynamic": flag(r.get("dynamic"))})
            tagged |= t; untagged |= u
        if filtering is False: mode = "unfiltered"
        elif filtering is True and complete and not any(k in errors for k in ("bridges", "ports", "bonds")) and flag(p.get("inactive")) is not True:
            mode = "hybrid" if tagged and untagged else "trunk" if tagged else "access" if untagged else "unknown"
        membership_source = "current" if complete else "partial"
    elif not members and "ports" not in errors and "bonds" not in errors: mode = "no_bridge"
    direct_vlans = [{"name":r.get("name"),"parent":r.get("interface"),"id":r.get("vlan-id"),"disabled":flag(r.get("disabled"))} for r in tables.get("vlan_interfaces", []) if r.get("interface") in candidates]
    neighbors = []
    for r in tables.get("neighbors", []):
        raw = str(r.get("interface") or "")
        # Exact names first; bridge/physical composite only with a known bridge prefix.
        matched = next((n for n in candidates if raw == n), None)
        if not matched and bridge and raw.startswith(str(bridge["name"])+"/"):
            suffix = raw[len(str(bridge["name"]))+1:]
            if suffix in candidates: matched = suffix
        if not matched: continue
        neighbors.append({"identity":r.get("identity"),"mac":mac(r.get("mac-address")),"ip":ip(r.get("address4") or r.get("address")),"platform":r.get("platform"),"board":r.get("board"),"remote_port":r.get("interface-name"),"protocol":r.get("discovered-by"),"interface":matched})
    arp_by_mac = {}
    for r in tables.get("arp", []):
        m=mac(r.get("mac-address")); a=ip(r.get("address"))
        if not m or not a or flag(r.get("invalid")) is True or flag(r.get("disabled")) is True or flag(r.get("complete")) is False: continue
        item={"ip":a,"interface":r.get("interface"),"status":r.get("status")}
        if item not in arp_by_mac.setdefault(m,[]): arp_by_mac[m].append(item)
    hosts=[]
    for r in tables.get("hosts", []):
        m=mac(r.get("mac-address")); iface=r.get("on-interface") or r.get("interface")
        if not m or iface not in candidates or flag(r.get("local")) is True: continue
        if bridge and r.get("bridge") and r.get("bridge") != bridge["name"]: continue
        hosts.append({"mac":m,"vid":r.get("vid"),"interface":iface,"dynamic":flag(r.get("dynamic")),"external":flag(r.get("external")),"ip_candidates":arp_by_mac.get(m,[])[:12]})
    return {"port":port,"bridge":bridge,"bonding":bonded,"mode":mode,"membership_source":membership_source,"vlans":vlans[:500],"vlan_interfaces":direct_vlans[:200],"neighbors":neighbors[:100],"hosts":hosts[:200],"host_count":len(hosts),"neighbor_count":len(neighbors),"errors":errors,"sampled_at":datetime.now(timezone.utc).isoformat(),"truncated":len(hosts)>200 or len(neighbors)>100 or len(vlans)>500 or len(direct_vlans)>200}

def fetch_port_network(creds, port):
    from .client import routeros_session
    from librouteros.exceptions import LibRouterosError
    tables={}; errors={}
    # One read-only session per explicit port selection; no automatic polling of FDB.
    with routeros_session(replace(creds, timeout=8.0)) as api:
        for key,path in TABLES.items():
            rows=[]
            try:
                for r in api.path(*path):
                    if len(rows)<LIMIT: rows.append(dict(r))
                    else: errors[key]="Таблица ограничена: неполные данные"
                tables[key]=rows
            except (LibRouterosError, OSError):
                errors[key]="Не удалось прочитать таблицу (права, версия или соединение)"
    return summarize(tables,errors,port)
