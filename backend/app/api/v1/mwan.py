from __future__ import annotations

import ipaddress
import re
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ...core.db import get_db
from ...core.security import decrypt_secret
from ...models.device import Device
from ...models.user import User
from ...services.routeros.client import RouterOSCredentials, RouterOSError, routeros_session
from ..deps import require_role

router = APIRouter()

TAG = "roszetta-mwan"
STATE = "roszetta-mwan-state"
MARKER = "roszetta-mwan-ok-"
ROLLBACK_SECONDS = 300
BH_DISTANCE = 250
_IFACE = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
_RID = re.compile(r"^\*[0-9A-Fa-f]+$")
_SAFE = re.compile(r"^[A-Za-z0-9_.:/!*,@%+=-]+$")
EXPORTS = (
    ("/ip route", "routes"),
    ("/tool netwatch", "netwatch"),
    ("/ip firewall mangle", "mangle"),
    ("/ip firewall nat", "nat"),
)
PATHS = {
    "routes": ("ip", "route"),
    "nat": ("ip", "firewall", "nat"),
    "mangle": ("ip", "firewall", "mangle"),
    "netwatch": ("tool", "netwatch"),
    "bridge": ("interface", "bridge"),
}


class WanIn(BaseModel):
    name: str = ""
    kind: str                 # pppoe | static
    interface: str            # pppoe-out1 или физический интерфейс (ether1, vlan…)
    gateway: str = ""         # только для static
    check_ip: str             # проверочный адрес (пингуется через этого провайдера)
    distance: int


class MwanIn(BaseModel):
    device_ids: list[int] = Field(default_factory=list)
    wans: list[WanIn]
    masquerade: bool = True
    disable_other_defaults: bool = True
    netwatch: bool = False
    netwatch_interval: int = 30
    netwatch_bridges: bool = True
    mangle: bool = False
    export_before: bool = True


class DevicesIn(BaseModel):
    device_ids: list[int] = Field(default_factory=list)


class MwanResult(BaseModel):
    device_id: int
    device_name: str | None = None
    ok: bool
    message: str | None = None
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    commands: list[str] = Field(default_factory=list)
    routes: list[dict[str, Any]] = Field(default_factory=list)
    netwatch: list[dict[str, Any]] = Field(default_factory=list)
    bridges: list[dict[str, Any]] = Field(default_factory=list)


class MwanOut(BaseModel):
    results: list[MwanResult]


# ---------------------------------------------------------------- проверка ввода

def _v4(value: str, what: str) -> str:
    try:
        ip = ipaddress.IPv4Address(value.strip())
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"{what}: некорректный IPv4-адрес")
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"{what}: недопустимый адрес")
    return str(ip)


def _validate(payload: MwanIn) -> list[WanIn]:
    if not payload.device_ids:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Не выбрано ни одного устройства")
    if not 2 <= len(payload.wans) <= 3:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Нужно от 2 до 3 провайдеров")
    if not 5 <= payload.netwatch_interval <= 300:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Интервал netwatch: от 5 до 300 секунд")
    out: list[WanIn] = []
    checks: set[str] = set()
    dists: set[int] = set()
    ifaces: set[str] = set()
    for i, w in enumerate(payload.wans, 1):
        label = (w.name.strip() or f"WAN{i}")[:32]
        if w.kind not in ("pppoe", "static"):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"{label}: тип должен быть pppoe или static")
        iface = w.interface.strip()
        if not _IFACE.match(iface):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"{label}: некорректное имя интерфейса")
        if iface in ifaces:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "У провайдеров должны быть разные интерфейсы")
        gw = _v4(w.gateway, f"{label}: шлюз") if w.kind == "static" else ""
        chk = _v4(w.check_ip, f"{label}: проверочный адрес")
        if not 1 <= w.distance <= 254:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"{label}: distance от 1 до 254")
        if chk in checks:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Проверочные адреса провайдеров должны различаться")
        if w.distance in dists:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "У провайдеров должны быть разные distance (одинаковые дают балансировку, а не резерв)",
            )
        if chk == gw:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"{label}: проверочный адрес не должен совпадать со шлюзом")
        checks.add(chk)
        dists.add(w.distance)
        ifaces.add(iface)
        out.append(WanIn(name=label, kind=w.kind, interface=iface, gateway=gw, check_ip=chk, distance=w.distance))
    return out


# ---------------------------------------------------------------- сравнение объектов

_BOOL = {"yes": "true", "true": "true", "no": "false", "false": "false"}


def _norm(v: Any) -> str:
    return "" if v is None else str(v)


def _truthy(v: Any) -> bool:
    return v is True or str(v).lower() in ("yes", "true")


def _int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _eq(a: Any, b: Any) -> bool:
    x, y = _norm(a), _norm(b)
    return _BOOL.get(x.lower(), x) == _BOOL.get(y.lower(), y)


def _is_tag(row: dict[str, Any]) -> bool:
    return _norm(row.get("comment")).startswith(TAG)


def _same(want: dict[str, Any], row: dict[str, Any], skip: tuple[str, ...] = ("comment",)) -> bool:
    for k, v in want.items():
        if k in skip:
            continue
        if k == "routing-table":
            if _norm(row.get("routing-table") or "main") != _norm(v):
                return False
        elif not _eq(row.get(k), v):
            return False
    if "blackhole" not in want and _truthy(row.get("blackhole")):
        return False
    if "dst-address" in want and "routing-table" not in want and _norm(row.get("routing-table") or "main") != "main":
        return False
    return True


def _reconcile(desired: list[dict[str, Any]], existing: list[dict[str, Any]],
               skip: tuple[str, ...] = ("comment",)) -> tuple[list[dict[str, Any]], list[str]]:
    """Что добавить и какие id удалить, чтобы наши объекты совпали с желаемыми."""
    remaining = list(existing)
    to_add: list[dict[str, Any]] = []
    for w in desired:
        hit = next((r for r in remaining if _same(w, r, skip)), None)
        if hit is None:
            to_add.append(w)
        else:
            remaining.remove(hit)
    return to_add, [str(r[".id"]) for r in remaining]


def _q(v: Any) -> str:
    s = str(v)
    if _SAFE.match(s):
        return s
    esc = s.replace("\\", "\\\\").replace('"', '\\"')
    esc = esc.replace("$", "\\24").replace("[", "\\5B").replace("]", "\\5D")
    return '"' + esc + '"'


# ---------------------------------------------------------------- план изменений

def _nw_script(label: str, state: str, bridge: str | None) -> str:
    """Скрипт netwatch: лог и (если есть мониторный bridge) включение или выключение интерфейса."""
    text = f':log warning "{label} {state}"'
    if bridge:
        text += f"; /interface {'enable' if state == 'UP' else 'disable'} [find name={bridge}]"
    return text


def _nw_label(rank: int, w: WanIn) -> str:
    role = "PRIMARY" if rank == 0 else ("BACKUP" if rank == 1 else f"BACKUP{rank}")
    nm = re.sub(r"[^A-Za-z0-9_-]", "", w.name)
    parts = [f"WAN-{role}"] + ([nm] if nm and nm != w.interface else []) + [w.interface]
    return " ".join(parts)


def _build_plan(api: Any, wans: list[WanIn], opts: MwanIn) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []

    def safe(*path: str) -> list[dict[str, Any]]:
        try:
            return list(api.path(*path))
        except Exception:  # noqa: BLE001 — раздел может отсутствовать
            return []

    routes = list(api.path("ip", "route"))
    nat_rows = safe("ip", "firewall", "nat")
    mangle_rows = safe("ip", "firewall", "mangle")
    filter_rows = safe("ip", "firewall", "filter")
    nw_rows = safe("tool", "netwatch")
    table_rows = safe("routing", "table")
    iface_names = {str(r.get("name")) for r in api.path("interface")}
    pppoe = {str(r.get("name")): r for r in safe("interface", "pppoe-client")}

    pinned: list[dict[str, Any]] = []
    blackholes: list[dict[str, Any]] = []
    table_routes: list[dict[str, Any]] = []
    defaults: list[dict[str, Any]] = []
    pppoe_change: list[dict[str, str]] = []

    for i, w in enumerate(wans, 1):
        if w.kind == "pppoe":
            cl = pppoe.get(w.interface)
            if cl is None:
                errors.append(f"{w.name}: PPPoE-клиент «{w.interface}» не найден на устройстве")
            elif _truthy(cl.get("add-default-route")):
                pppoe_change.append({"id": str(cl[".id"]), "name": w.interface})
            gateway = w.interface
        else:
            if w.interface not in iface_names:
                errors.append(f"{w.name}: интерфейс «{w.interface}» не найден на устройстве")
            gateway = w.gateway
        pinned.append({
            "dst-address": f"{w.check_ip}/32", "gateway": gateway,
            "distance": 1, "scope": 10, "target-scope": 10,
        })
        if opts.netwatch:
            blackholes.append({"dst-address": f"{w.check_ip}/32", "blackhole": "yes", "distance": BH_DISTANCE})
        if opts.mangle:
            table_routes.append({
                "dst-address": "0.0.0.0/0", "gateway": gateway, "distance": 1,
                "routing-table": f"rzmw_wan{i}",
            })
    for w in wans:
        defaults.append({
            "dst-address": "0.0.0.0/0", "gateway": w.check_ip, "distance": w.distance,
            "scope": 30, "target-scope": 11, "check-gateway": "ping",
        })
    desired_routes = pinned + blackholes + table_routes + defaults

    # прежние default-маршруты: только таблица main (маршруты в других таблицах не трогаем)
    changed_names = {c["name"] for c in pppoe_change}
    to_disable: list[dict[str, str]] = []
    for r in routes:
        if _is_tag(r) or _norm(r.get("routing-table") or "main") != "main":
            continue
        if _norm(r.get("dst-address")) != "0.0.0.0/0" or _truthy(r.get("disabled")) or _truthy(r.get("blackhole")):
            continue
        desc = f"{r.get('gateway')} (distance {r.get('distance')})"
        if _truthy(r.get("dynamic")):
            if not any(n in str(r) for n in changed_names):
                warnings.append(
                    f"динамический default-маршрут через {desc} отключить нельзя "
                    "(его создаёт DHCP/PPPoE-клиент); он может конкурировать с новыми"
                )
        elif opts.disable_other_defaults:
            to_disable.append({"id": str(r[".id"]), "desc": desc})
        else:
            warnings.append(f"остаётся прежний default-маршрут через {desc}: он может конкурировать с новыми")

    routes_add, routes_remove = _reconcile(desired_routes, [r for r in routes if _is_tag(r)])

    # NAT
    old_nat = [r for r in nat_rows if _is_tag(r)]
    want_nat: list[dict[str, Any]] = []
    if opts.masquerade:
        others = [
            r for r in nat_rows
            if not _is_tag(r) and r.get("chain") == "srcnat" and r.get("action") == "masquerade"
        ]
        if any(r.get("out-interface-list") for r in others):
            warnings.append("в NAT есть masquerade по списку интерфейсов: проверьте, что WAN-интерфейсы в него входят")
        for w in wans:
            if any(_norm(r.get("out-interface")) == w.interface for r in others):
                warnings.append(f"masquerade для «{w.interface}» уже есть (не мой), новое правило не создаётся")
            else:
                want_nat.append({"chain": "srcnat", "out-interface": w.interface, "action": "masquerade"})
    nat_add, nat_remove = _reconcile(want_nat, old_nat)

    # mangle: ответ уходит тому провайдеру, откуда пришёл запрос
    want_mangle: list[dict[str, Any]] = []
    want_tables: list[str] = []
    if opts.mangle:
        for i, w in enumerate(wans, 1):
            conn, table = f"rzmw_in_{i}", f"rzmw_wan{i}"
            want_tables.append(table)
            c = f"{TAG} reply-via {w.interface}"
            want_mangle += [
                {"chain": "prerouting", "action": "mark-connection", "in-interface": w.interface,
                 "connection-state": "new", "connection-mark": "no-mark",
                 "new-connection-mark": conn, "passthrough": "yes", "comment": c},
                {"chain": "prerouting", "action": "mark-routing", "in-interface": f"!{w.interface}",
                 "connection-mark": conn, "new-routing-mark": table, "passthrough": "no", "comment": c},
                {"chain": "output", "action": "mark-routing",
                 "connection-mark": conn, "new-routing-mark": table, "passthrough": "no", "comment": c},
            ]
        for r in filter_rows:
            if (r.get("action") == "fasttrack-connection" and not _truthy(r.get("disabled"))
                    and _norm(r.get("connection-mark")) != "no-mark"):
                warnings.append(
                    "включён FastTrack: пакеты fasttrack-соединений обходят mangle, и ответы могут уходить не тому провайдеру; "
                    "добавьте в правило fasttrack-connection условие connection-mark=no-mark"
                )
                break
        if any(not _is_tag(r) and r.get("action") == "mark-routing" for r in mangle_rows):
            warnings.append(
                "в mangle уже есть ваши правила mark-routing: новые добавляются в конец цепочки и срабатывают после них"
            )
    mangle_add, mangle_remove = _reconcile(want_mangle, [r for r in mangle_rows if _is_tag(r)])

    # netwatch: проверки доступности (только лог UP/DOWN, как в исходной схеме)
    want_br: list[dict[str, Any]] = []
    want_nw: list[dict[str, Any]] = []
    if opts.netwatch:
        order = sorted(range(len(wans)), key=lambda k: wans[k].distance)
        rank = {k: pos for pos, k in enumerate(order)}
        for k, w in enumerate(wans):
            label = _nw_label(rank[k], w)
            br = f"mon-wan{k + 1}" if opts.netwatch_bridges else None
            if br:
                shown = re.sub(r"[^A-Za-z0-9_-]", "", w.name) or w.interface
                want_br.append({
                    "name": br, "protocol-mode": "none", "arp": "disabled",
                    "comment": f"{TAG} {shown} {w.interface} probe {w.check_ip}",
                })
            want_nw.append({
                "host": w.check_ip, "type": "icmp", "interval": f"{opts.netwatch_interval}s",
                "comment": f"{TAG} {label}",
                "down-script": _nw_script(label, "DOWN", br),
                "up-script": _nw_script(label, "UP", br),
            })
    nw_add, nw_remove = _reconcile(want_nw, [r for r in nw_rows if _is_tag(r)], skip=())

    # мониторные bridge: пустые, без ARP и STP, включаются и выключаются скриптами netwatch
    br_rows = safe("interface", "bridge")
    for b in want_br:
        if any(_norm(r.get("name")) == b["name"] and not _is_tag(r) for r in br_rows):
            errors.append(
                f"bridge «{b['name']}» уже есть на устройстве и создан не контроллером: удалите его "
                "или снимите флажок «мониторные bridge»"
            )
    br_add, br_remove = _reconcile(
        want_br, [r for r in br_rows if _is_tag(r)], skip=("comment", "protocol-mode", "arp"),
    )
    if opts.netwatch:
        for w in wans:
            if any(not _is_tag(r) and _norm(r.get("host")) == w.check_ip for r in nw_rows):
                warnings.append(
                    f"на устройстве уже есть netwatch для {w.check_ip} (создан не контроллером): "
                    "будут две проверки одного адреса, лишнюю лучше удалить"
                )

    # таблицы маршрутизации
    existing_tables = [r for r in table_rows if _is_tag(r)]
    tables_add = [t for t in want_tables if not any(_norm(r.get("name")) == t for r in existing_tables)]
    tables_remove = [str(r[".id"]) for r in existing_tables if _norm(r.get("name")) not in want_tables]

    return {
        "errors": errors, "warnings": warnings,
        "routes_add": routes_add, "routes_remove": routes_remove,
        "nat_add": nat_add, "nat_remove": nat_remove,
        "mangle_add": mangle_add, "mangle_remove": mangle_remove,
        "nw_add": nw_add, "nw_remove": nw_remove,
        "br_add": br_add, "br_remove": br_remove,
        "tables_add": tables_add, "tables_remove": tables_remove,
        "pppoe_change": pppoe_change, "to_disable": to_disable,
    }


def _render(plan: dict[str, Any], opts: MwanIn, token: str = "<время>") -> list[str]:
    out: list[str] = []
    if opts.export_before:
        for menu, name in EXPORTS:
            out.append(f"{menu} export file=rzmw-{name}-before-{token}")
    for t in plan["tables_add"]:
        out.append(f"/routing table add name={t} fib comment={TAG}")
    for menu, key in (("/ip route", "routes_add"), ("/ip firewall nat", "nat_add"),
                      ("/ip firewall mangle", "mangle_add"), ("/interface bridge", "br_add"),
                      ("/tool netwatch", "nw_add")):
        for d in plan[key]:
            item = {"comment": TAG, **d}
            out.append(f"{menu} add " + " ".join(f"{k}={_q(v)}" for k, v in item.items()))
    for c in plan["pppoe_change"]:
        out.append(f"/interface pppoe-client set [find name={c['name']}] add-default-route=no")
    for r in plan["to_disable"]:
        out.append(f"/ip route disable {r['id']}    # прежний default: {r['desc']}")
    for key, menu in (("mangle_remove", "/ip firewall mangle"), ("nw_remove", "/tool netwatch"), ("br_remove", "/interface bridge"),
                      ("routes_remove", "/ip route"), ("nat_remove", "/ip firewall nat"),
                      ("tables_remove", "/routing table")):
        for rid in plan[key]:
            out.append(f"{menu} remove {rid}    # устаревший объект {TAG}")
    if not any(not l.startswith("/") or "export" not in l for l in out) or not [
        l for l in out if "export file=" not in l
    ]:
        out.append("# изменений нет: настройка уже соответствует профилю")
    return out


def _route_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for r in rows:
        if not _is_tag(r):
            continue
        dst = _norm(r.get("dst-address"))
        table = _norm(r.get("routing-table") or "main")
        if _truthy(r.get("blackhole")):
            role = "blackhole"
        elif table != "main":
            role = "table"
        elif dst == "0.0.0.0/0":
            role = "default"
        else:
            role = "check"
        out.append({
            "role": role, "dst": dst,
            "gateway": _norm(r.get("gateway")) or ("blackhole" if role == "blackhole" else ""),
            "distance": _int(r.get("distance")), "table": table,
            "active": _truthy(r.get("active")), "disabled": _truthy(r.get("disabled")),
        })
    order = {"check": 0, "blackhole": 1, "default": 2, "table": 3}
    return sorted(out, key=lambda x: (order[x["role"]], x["distance"]))


def _bridge_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {"name": _norm(r.get("name")), "running": _truthy(r.get("running")),
         "disabled": _truthy(r.get("disabled")),
         "comment": _norm(r.get("comment")).replace(TAG, "").strip()}
        for r in rows if _is_tag(r)
    ]


def _netwatch_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {"host": _norm(r.get("host")), "comment": _norm(r.get("comment")).replace(TAG, "").strip(),
         "status": _norm(r.get("status")) or "unknown", "since": _norm(r.get("since"))}
        for r in rows if _is_tag(r)
    ]


# ---------------------------------------------------------------- состояние отката на роутере

def _read_state(api: Any) -> tuple[list[str], list[str]]:
    for r in api.path("system", "script"):
        if r.get("name") == STATE:
            src = str(r.get("source") or "")
            pp = re.search(r"pppoe=([^;]*)", src)
            dd = re.search(r"disabled=([^;]*)", src)
            names = [x for x in (pp.group(1).split(",") if pp else []) if _IFACE.match(x)]
            ids = [x for x in (dd.group(1).split(",") if dd else []) if _RID.match(x)]
            return names, ids
    return [], []


def _write_state(api: Any, pppoe_names: list[str], disabled_ids: list[str]) -> None:
    scripts = api.path("system", "script")
    old = [str(r[".id"]) for r in scripts if r.get("name") == STATE]
    if old:
        scripts.remove(*old)
    scripts.add(name=STATE, source=f"pppoe={','.join(pppoe_names)};disabled={','.join(disabled_ids)}")


def _safety_script(marker: str, pppoe_names: list[str], disabled_ids: list[str]) -> str:
    def guard(cmd: str) -> str:
        return ":do { " + cmd + " } on-error={};"

    lines = [
        f":delay {ROLLBACK_SECONDS}s;",
        ':if ([:len [/system script find name="' + marker + '"]] = 0) do={',
    ]
    for n in pppoe_names:
        lines.append(guard('/interface pppoe-client set [find name="' + n + '"] add-default-route=yes'))
    for i in disabled_ids:
        lines.append(guard("/ip route enable numbers=" + i))
    for menu in ("/ip firewall mangle", "/tool netwatch", "/interface bridge", "/ip route",
                 "/ip firewall nat", "/routing table"):
        lines.append(guard(menu + ' remove [find comment~"^' + TAG + '"]'))
    lines.append(guard('/system script remove [find name="' + STATE + '"]'))
    lines.append('} else={ /system script remove [find name="' + marker + '"] }')
    return "\n".join(lines)


def _export_before(api: Any, token: str) -> list[str]:
    names: list[str] = []
    for menu, name in EXPORTS:
        fname = f"rzmw-{name}-before-{token}"
        list(api(cmd="/execute", script=f"{menu} export file={fname}"))
        names.append(fname + ".rsc")
    return names


def _undo(api: Any, created: dict[str, list[str]], changed_p: list[str], disabled: list[str]) -> None:
    try:
        for rid in disabled:
            api.path("ip", "route").update(**{".id": rid, "disabled": False})
        for pid in changed_p:
            api.path("interface", "pppoe-client").update(**{".id": pid, "add-default-route": "yes"})
        for key in ("mangle", "netwatch", "bridge", "routes", "nat"):
            if created[key]:
                api.path(*PATHS[key]).remove(*created[key])
        if created["tables"]:
            api.path("routing", "table").remove(*created["tables"])
    except Exception as exc:  # noqa: BLE001
        logger.warning("mwan undo failed: {}", exc)


# ---------------------------------------------------------------- операции на одном устройстве

def _apply_one(creds: RouterOSCredentials, wans: list[WanIn], opts: MwanIn) -> MwanResult:
    token = str(int(time.time()))
    marker = f"{MARKER}{token}"
    created: dict[str, list[str]] = {k: [] for k in ("tables", "routes", "nat", "mangle", "bridge", "netwatch")}
    changed_p: list[str] = []
    disabled: list[str] = []
    exported: list[str] = []
    with routeros_session(creds) as api:
        plan = _build_plan(api, wans, opts)
        if plan["errors"]:
            return MwanResult(device_id=0, ok=False, errors=plan["errors"], warnings=plan["warnings"],
                              message="не применено: исправьте ошибки профиля")
        warnings = list(plan["warnings"])
        prev_pppoe, prev_disabled = _read_state(api)
        all_pppoe = sorted(set(prev_pppoe) | {c["name"] for c in plan["pppoe_change"]})
        all_disabled = sorted(set(prev_disabled) | {d["id"] for d in plan["to_disable"] if _RID.match(d["id"])})

        if opts.export_before:
            try:
                exported = _export_before(api, token)
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"резервные экспорты на роутере не созданы: {exc}")

        # страховка: откат на самом роутере через 5 минут, если не будет отметки
        list(api(cmd="/execute", script=_safety_script(marker, all_pppoe, all_disabled)))

        try:
            tables = api.path("routing", "table")
            for t in plan["tables_add"]:
                created["tables"].append(str(tables.add(name=t, fib="yes", comment=TAG)))
            for key, items in (("routes", plan["routes_add"]), ("nat", plan["nat_add"]),
                               ("mangle", plan["mangle_add"]), ("bridge", plan["br_add"]),
                               ("netwatch", plan["nw_add"])):
                path = api.path(*PATHS[key])
                for item in items:
                    created[key].append(str(path.add(**{"comment": TAG, **item})))
            for c in plan["pppoe_change"]:
                api.path("interface", "pppoe-client").update(**{".id": c["id"], "add-default-route": "no"})
                changed_p.append(c["id"])
            routes = api.path("ip", "route")
            for d in plan["to_disable"]:
                routes.update(**{".id": d["id"], "disabled": True})
                disabled.append(d["id"])
            for key, ids in (("mangle", plan["mangle_remove"]), ("netwatch", plan["nw_remove"]), ("bridge", plan["br_remove"]),
                             ("routes", plan["routes_remove"]), ("nat", plan["nat_remove"])):
                if ids:
                    api.path(*PATHS[key]).remove(*ids)
            if plan["tables_remove"]:
                api.path("routing", "table").remove(*plan["tables_remove"])
        except Exception:
            _undo(api, created, changed_p, disabled)
            try:  # изменения отменены: откат по таймеру больше не нужен и снёс бы прежнюю рабочую настройку
                api.path("system", "script").add(name=marker, source="# ok (undo)")
            except Exception:  # noqa: BLE001
                pass
            raise

    # проверка: связь с устройством должна сохраниться, только тогда ставим отметку
    time.sleep(3)
    try:
        with routeros_session(creds) as api2:
            rows = _route_rows(list(api2.path("ip", "route")))
            try:
                nw = _netwatch_rows(list(api2.path("tool", "netwatch")))
            except Exception:  # noqa: BLE001
                nw = []
            try:
                br = _bridge_rows(list(api2.path("interface", "bridge")))
            except Exception:  # noqa: BLE001
                br = []
            _write_state(api2, all_pppoe, all_disabled)
            api2.path("system", "script").add(name=marker, source="# ok")
    except Exception as exc:  # noqa: BLE001
        raise RouterOSError(
            "после применения не удалось заново подключиться к устройству; роутер сам откатит "
            f"изменения примерно через {ROLLBACK_SECONDS // 60} минут ({exc})"
        ) from exc

    if not any(r["active"] for r in rows if r["role"] == "default"):
        warnings.append(
            "пока ни один default-маршрут не активен: проверка check-gateway выполняется раз в ~10 секунд, "
            "проверьте состояние кнопкой «Статус»"
        )
    msg = "применено"
    if exported:
        msg += "; экспорты до изменений на роутере: " + ", ".join(exported)
    return MwanResult(device_id=0, ok=True, message=msg, warnings=warnings,
                      commands=_render(plan, opts, token), routes=rows, netwatch=nw, bridges=br)


def _remove_one(creds: RouterOSCredentials) -> MwanResult:
    counts: dict[str, int] = {}
    with routeros_session(creds) as api:
        pp, dd = _read_state(api)
        # сначала возвращаем прежнее, потом убираем своё: разрыва нет
        for r in list(api.path("interface", "pppoe-client")):
            if str(r.get("name")) in pp:
                api.path("interface", "pppoe-client").update(**{".id": r[".id"], "add-default-route": "yes"})
        for rid in dd:
            try:
                api.path("ip", "route").update(**{".id": rid, "disabled": False})
            except Exception as exc:  # noqa: BLE001
                logger.warning("mwan: не удалось включить маршрут {}: {}", rid, exc)
        for key, path in (("mangle", PATHS["mangle"]), ("netwatch", PATHS["netwatch"]), ("bridge", PATHS["bridge"]),
                          ("routes", PATHS["routes"]), ("nat", PATHS["nat"]),
                          ("tables", ("routing", "table"))):
            try:
                p = api.path(*path)
                ids = [str(r[".id"]) for r in list(p) if _is_tag(r)]
                if ids:
                    p.remove(*ids)
                counts[key] = len(ids)
            except Exception as exc:  # noqa: BLE001
                logger.warning("mwan: не удалось удалить {}: {}", key, exc)
                counts[key] = 0
        scripts = api.path("system", "script")
        sids = [str(r[".id"]) for r in list(scripts)
                if str(r.get("name")) == STATE or str(r.get("name")).startswith(MARKER)]
        if sids:
            scripts.remove(*sids)
    return MwanResult(
        device_id=0, ok=True,
        message=(f"удалено: маршрутов {counts.get('routes', 0)}, NAT {counts.get('nat', 0)}, "
                 f"mangle {counts.get('mangle', 0)}, netwatch {counts.get('netwatch', 0)}, bridge {counts.get('bridge', 0)}, "
                 f"таблиц {counts.get('tables', 0)}; прежние настройки возвращены"),
    )


# ---------------------------------------------------------------- эндпоинты

def _each(db: Session, ids: list[int], fn) -> list[MwanResult]:
    results: list[MwanResult] = []
    for did in ids:
        d = db.get(Device, did)
        if not d:
            results.append(MwanResult(device_id=did, ok=False, message="устройство не найдено"))
            continue
        name = d.identity or d.name
        try:
            creds = RouterOSCredentials(
                host=d.host, username=d.username, password=decrypt_secret(d.password_enc),
                port=d.port, use_tls=d.use_tls, tls_fingerprint=getattr(d, "tls_fingerprint", None), timeout=15.0,
            )
            res = fn(creds)
            res.device_id, res.device_name = did, name
        except Exception as exc:  # noqa: BLE001 — ошибка одного устройства не останавливает остальные
            logger.warning("mwan failed on {}: {}", d.host, exc)
            res = MwanResult(device_id=did, device_name=name, ok=False, message=str(exc))
        results.append(res)
    return results


@router.post("/preview", response_model=MwanOut)
def preview(
    payload: MwanIn,
    db: Session = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
) -> MwanOut:
    wans = _validate(payload)

    def fn(creds: RouterOSCredentials) -> MwanResult:
        with routeros_session(creds) as api:
            plan = _build_plan(api, wans, payload)
        ok = not plan["errors"]
        return MwanResult(
            device_id=0, ok=ok, errors=plan["errors"], warnings=plan["warnings"],
            commands=_render(plan, payload),
            message="можно применять" if ok else "есть ошибки, применять нельзя",
        )

    return MwanOut(results=_each(db, payload.device_ids, fn))


@router.post("/apply", response_model=MwanOut)
def apply(
    payload: MwanIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin")),
) -> MwanOut:
    wans = _validate(payload)
    logger.info("mwan apply by {}: devices={} wans={} netwatch={} mangle={}", user.email, payload.device_ids,
                [(w.kind, w.interface, w.check_ip, w.distance) for w in wans], payload.netwatch, payload.mangle)
    return MwanOut(results=_each(db, payload.device_ids, lambda c: _apply_one(c, wans, payload)))


@router.post("/status", response_model=MwanOut)
def mwan_status(
    payload: DevicesIn,
    db: Session = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
) -> MwanOut:
    if not payload.device_ids:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Не выбрано ни одного устройства")

    def fn(creds: RouterOSCredentials) -> MwanResult:
        with routeros_session(creds) as api:
            rows = _route_rows(list(api.path("ip", "route")))
            try:
                nw = _netwatch_rows(list(api.path("tool", "netwatch")))
            except Exception:  # noqa: BLE001
                nw = []
        try:
            with routeros_session(creds) as api_b:
                br = _bridge_rows(list(api_b.path("interface", "bridge")))
        except Exception:  # noqa: BLE001
            br = []
        if not rows and not nw:
            return MwanResult(device_id=0, ok=True, message="настройка Multi-WAN не найдена")
        act = [f"{r['gateway']} (distance {r['distance']})" for r in rows if r["role"] == "default" and r["active"]]
        return MwanResult(device_id=0, ok=True, routes=rows, netwatch=nw, bridges=br,
                          message=("активен: " + ", ".join(act)) if act else "ни один default-маршрут не активен")

    return MwanOut(results=_each(db, payload.device_ids, fn))


@router.post("/remove", response_model=MwanOut)
def remove(
    payload: DevicesIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin")),
) -> MwanOut:
    if not payload.device_ids:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Не выбрано ни одного устройства")
    logger.info("mwan remove by {}: devices={}", user.email, payload.device_ids)
    return MwanOut(results=_each(db, payload.device_ids, _remove_one))
