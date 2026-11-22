from __future__ import annotations

import ipaddress
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from librouteros.query import Key
from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ...core.db import get_db
from ...core.security import decrypt_secret
from ...models.device import Device
from ...models.user import User
from ...services.routeros.client import RouterOSCredentials, routeros_session
from ..deps import require_role

router = APIRouter()

PATH = ("ip", "firewall", "address-list")
KEYS = (".id", "list", "address", "comment", "timeout", "dynamic", "disabled")
MAX_ENTRIES = 5000      # записей на устройство в ответе просмотра
MAX_ADDRS = 1000        # адресов в одном запросе на изменение
MAX_LINES = 200         # строк плана в ответе
ACTIONS = ("add", "remove", "replace", "update")

_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_TIME = re.compile(r"^(?:\d+[wdhms])+$|^\d+:\d{2}:\d{2}$")
_RANGE = re.compile(r"^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$")
_HOST = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z]{2,63}$")


# ---------------------------------------------------------------- модели запросов и ответов

class ReadIn(BaseModel):
    device_ids: list[int] = Field(default_factory=list)
    list_name: str = ""
    entries: bool = False


class ChangeIn(BaseModel):
    device_ids: list[int] = Field(default_factory=list)
    action: str                       # add | remove | replace | update
    list_name: str
    addresses: str = ""
    whole_list: bool = False          # remove/update: все статические записи списка
    comment: str | None = None        # None = не менять; "" при update = очистить
    timeout: str = ""                 # только add
    state: str = "keep"               # update: keep | enable | disable
    new_address: str = ""             # update: заменить адрес (ровно одна запись)


class ALResult(BaseModel):
    device_id: int
    device_name: str | None = None
    ok: bool
    message: str | None = None
    lists: list[dict[str, Any]] = Field(default_factory=list)
    entries: list[dict[str, Any]] = Field(default_factory=list)
    truncated: bool = False
    lines: list[str] = Field(default_factory=list)
    undo: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class ALOut(BaseModel):
    results: list[ALResult]


# ---------------------------------------------------------------- вспомогательное

def _norm(v: Any) -> str:
    return "" if v is None else str(v)


def _truthy(v: Any) -> bool:
    return v is True or str(v).lower() in ("yes", "true")


def _rq(v: Any) -> str:
    """Строка в формате RouterOS (для файлов отката)."""
    s = str(v).replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("?", "\\?")
    return f'"{s}"'


def _norm_addr(raw: str) -> str:
    a = raw.strip()
    if not a:
        raise ValueError("пустой адрес")
    m = _RANGE.match(a)
    if m:
        s, e = ipaddress.IPv4Address(m.group(1)), ipaddress.IPv4Address(m.group(2))
        if s > e:
            raise ValueError(f"диапазон задан наоборот: {a}")
        return f"{s}-{e}"
    try:
        n = ipaddress.ip_network(a, strict=False)
    except ValueError:
        if _HOST.match(a):
            return a.lower()
        raise ValueError(f"некорректный адрес: {a}")
    if n.version != 4:
        raise ValueError(f"IPv6 не поддерживается (раздел /ip firewall address-list только для IPv4): {a}")
    if n.prefixlen == 0:
        raise ValueError("0.0.0.0/0 запрещён: он охватывает все адреса")
    return str(n.network_address) if n.prefixlen == 32 else str(n)


def _row_addr(row: dict[str, Any]) -> str:
    a = _norm(row.get("address"))
    try:
        return _norm_addr(a)
    except ValueError:
        return a.lower()


def _parse_addresses(text: str) -> list[str]:
    out: list[str] = []
    bad: list[str] = []
    for token in re.split(r"[\s,;]+", text.strip()):
        if not token:
            continue
        try:
            a = _norm_addr(token)
        except ValueError as exc:
            bad.append(str(exc))
            continue
        if a not in out:
            out.append(a)
    if bad:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "; ".join(bad[:5]) + (" …" if len(bad) > 5 else ""))
    if len(out) > MAX_ADDRS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Слишком много адресов за раз (максимум {MAX_ADDRS})")
    return out


def _check_text(v: str, what: str, max_len: int) -> str:
    s = v.strip()
    if not s or len(s) > max_len or _CTRL.search(s):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"{what}: от 1 до {max_len} символов, без управляющих символов")
    return s


def _validate(p: ChangeIn) -> tuple[list[str], str]:
    if not p.device_ids:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Не выбрано ни одного устройства")
    if p.action not in ACTIONS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Неизвестное действие")
    p.list_name = _check_text(p.list_name, "Название списка", 64)
    if p.comment is not None:
        if len(p.comment) > 255 or _CTRL.search(p.comment):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Комментарий: до 255 символов, без управляющих символов")
    if p.timeout:
        p.timeout = p.timeout.strip()
        if not _TIME.match(p.timeout):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Timeout: например 1d, 12h, 1d12h30m или 00:30:00")
    if p.state not in ("keep", "enable", "disable"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Неизвестное состояние записи")
    addrs = _parse_addresses(p.addresses) if p.addresses.strip() else []
    need_addrs = p.action in ("add", "replace") or not p.whole_list
    if need_addrs and not addrs:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Укажите хотя бы один адрес")
    new_addr = ""
    if p.new_address.strip():
        if p.action != "update" or p.whole_list or len(addrs) != 1:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Замена адреса: режим «Изменить», ровно один исходный адрес")
        try:
            new_addr = _norm_addr(p.new_address)
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
    if p.action == "update" and p.comment is None and p.state == "keep" and not new_addr:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Укажите, что менять: комментарий, состояние или адрес")
    return addrs, new_addr


# ---------------------------------------------------------------- чтение с устройства

def _rows(api: Any, list_name: str | None, keys: tuple[str, ...]) -> list[dict[str, Any]]:
    path = api.path(*PATH)
    try:
        q = path.select(*[Key(k) for k in keys])
        if list_name:
            q = q.where(Key("list") == list_name)
        return list(q)
    except Exception:  # noqa: BLE001 — запасной путь: прочитать всё и отфильтровать здесь
        rows = list(path)
        if list_name:
            rows = [r for r in rows if _norm(r.get("list")) == list_name]
        return rows


def _summary(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    acc: dict[str, dict[str, Any]] = {}
    for r in rows:
        n = _norm(r.get("list"))
        item = acc.setdefault(n, {"name": n, "total": 0, "dynamic": 0})
        item["total"] += 1
        if _truthy(r.get("dynamic")):
            item["dynamic"] += 1
    return sorted(acc.values(), key=lambda x: x["name"].lower())


def _usage(api: Any, list_name: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for label, path in (("filter", ("ip", "firewall", "filter")), ("nat", ("ip", "firewall", "nat")),
                        ("mangle", ("ip", "firewall", "mangle")), ("raw", ("ip", "firewall", "raw"))):
        try:
            n = sum(
                1 for r in api.path(*path)
                if list_name in (_norm(r.get("src-address-list")).lstrip("!"),
                                 _norm(r.get("dst-address-list")).lstrip("!"))
            )
        except Exception:  # noqa: BLE001 — раздела может не быть
            n = 0
        if n:
            out[label] = n
    return out


# ---------------------------------------------------------------- план изменений

def _plan(api: Any, p: ChangeIn, addrs: list[str], new_addr: str) -> dict[str, Any]:
    name = p.list_name
    rows = _rows(api, name, KEYS)
    by_addr: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        by_addr.setdefault(_row_addr(r), []).append(r)
    static = [r for r in rows if not _truthy(r.get("dynamic"))]
    dynamic_n = len(rows) - len(static)

    add: list[dict[str, Any]] = []
    remove: list[dict[str, Any]] = []
    update: list[tuple[dict[str, Any], dict[str, Any]]] = []
    skipped = 0
    errors: list[str] = []
    warnings: list[str] = []

    if p.action == "add":
        for a in addrs:
            if a in by_addr:
                skipped += 1
                continue
            item: dict[str, Any] = {"list": name, "address": a}
            if p.comment:
                item["comment"] = p.comment
            if p.timeout:
                item["timeout"] = p.timeout
            add.append(item)

    elif p.action == "remove":
        if p.whole_list:
            remove = list(static)
            if dynamic_n:
                warnings.append(f"динамические записи (созданные правилами или с таймаутом) не затронуты: {dynamic_n}")
        else:
            for a in addrs:
                hit = by_addr.get(a)
                if hit:
                    remove += hit
                else:
                    skipped += 1

    elif p.action == "replace":
        want = set(addrs)
        seen: set[str] = set()
        for r in static:
            k = _row_addr(r)
            if k in want and k not in seen:
                seen.add(k)
            else:
                remove.append(r)          # лишняя запись или дубликат
        for a in addrs:
            if a in by_addr:
                skipped += 1
            else:
                item = {"list": name, "address": a}
                if p.comment:
                    item["comment"] = p.comment
                add.append(item)
        if dynamic_n:
            warnings.append(f"динамические записи не затронуты: {dynamic_n}")

    else:  # update
        if p.whole_list:
            targets = list(static)
            if dynamic_n:
                warnings.append(f"динамические записи не затронуты: {dynamic_n}")
        else:
            targets = []
            for a in addrs:
                hit = by_addr.get(a)
                if hit:
                    targets += hit
                else:
                    skipped += 1
        if new_addr and new_addr in by_addr:
            errors.append(f"адрес {new_addr} уже есть в списке")
        for r in targets:
            f: dict[str, Any] = {}
            if p.comment is not None and _norm(r.get("comment")) != p.comment:
                f["comment"] = p.comment
            dis = _truthy(r.get("disabled"))
            if p.state == "disable" and not dis:
                f["disabled"] = "yes"
            if p.state == "enable" and dis:
                f["disabled"] = "no"
            if new_addr:
                f["address"] = new_addr
            if f:
                update.append((r, f))
            else:
                skipped += 1

    if (remove or update) and p.action != "add":
        use = _usage(api, name)
        if use:
            warnings.append(
                f"список «{name}» используется в правилах firewall ("
                + ", ".join(f"{k}: {v}" for k, v in use.items())
                + "): изменение содержимого повлияет на их работу"
            )

    lines: list[str] = []
    for a in add:
        lines.append(f"+ {a['address']}" + (f"   # {a['comment']}" if a.get("comment") else ""))
    for r in remove:
        c = _norm(r.get("comment"))
        lines.append(f"- {_norm(r.get('address'))}" + (f"   # {c}" if c else ""))
    for r, f in update:
        lines.append(f"~ {_norm(r.get('address'))}: " + ", ".join(f"{k}={v or '(пусто)'}" for k, v in f.items()))

    undo: list[str] = [
        f"/ip firewall address-list remove [find list={_rq(name)} address={_rq(a['address'])}]" for a in add
    ]
    for r in remove:
        cmd = f"/ip firewall address-list add list={_rq(name)} address={_rq(_norm(r.get('address')))}"
        if _norm(r.get("comment")):
            cmd += f" comment={_rq(_norm(r.get('comment')))}"
        if _truthy(r.get("disabled")):
            cmd += " disabled=yes"
        undo.append(cmd)
    for r, f in update:
        old_addr = _norm(r.get("address"))
        cur = f.get("address", old_addr)
        parts = [f"/ip firewall address-list set [find list={_rq(name)} address={_rq(cur)}]"]
        if "comment" in f:
            parts.append(f"comment={_rq(_norm(r.get('comment')))}")
        if "disabled" in f:
            parts.append("disabled=" + ("yes" if _truthy(r.get("disabled")) else "no"))
        if "address" in f:
            parts.append(f"address={_rq(old_addr)}")
        undo.append(" ".join(parts))

    return {"add": add, "remove": remove, "update": update, "skipped": skipped,
            "errors": errors, "warnings": warnings, "lines": lines, "undo": undo}


def _counts(plan: dict[str, Any]) -> str:
    return (f"добавить {len(plan['add'])}, удалить {len(plan['remove'])}, "
            f"изменить {len(plan['update'])}, пропущено {plan['skipped']}")


def _trim(lines: list[str]) -> list[str]:
    if len(lines) <= MAX_LINES:
        return lines
    return lines[:MAX_LINES] + [f"… и ещё {len(lines) - MAX_LINES}"]


def _execute(api: Any, plan: dict[str, Any]) -> tuple[int, int, int, list[str]]:
    path = api.path(*PATH)
    errs: list[str] = []
    added = removed = updated = 0
    for item in plan["add"]:
        try:
            path.add(**item)
            added += 1
        except Exception as exc:  # noqa: BLE001
            errs.append(f"добавление {item['address']}: {exc}")
    ids = [str(r[".id"]) for r in plan["remove"]]
    for i in range(0, len(ids), 50):
        chunk = ids[i:i + 50]
        try:
            path.remove(*chunk)
            removed += len(chunk)
        except Exception:  # noqa: BLE001 — разбираем пачку по одной записи
            for rid in chunk:
                try:
                    path.remove(rid)
                    removed += 1
                except Exception as exc:  # noqa: BLE001
                    errs.append(f"удаление {rid}: {exc}")
    for r, f in plan["update"]:
        try:
            path.update(**{".id": r[".id"], **f})
            updated += 1
        except Exception as exc:  # noqa: BLE001
            errs.append(f"изменение {_norm(r.get('address'))}: {exc}")
    if len(errs) > 10:
        errs = errs[:10] + [f"… и ещё {len(errs) - 10} ошибок"]
    return added, removed, updated, errs


# ---------------------------------------------------------------- эндпоинты

def _each(db: Session, ids: list[int], fn) -> list[ALResult]:
    results: list[ALResult] = []
    for did in ids:
        d = db.get(Device, did)
        if not d:
            results.append(ALResult(device_id=did, ok=False, message="устройство не найдено"))
            continue
        name = d.identity or d.name
        try:
            creds = RouterOSCredentials(
                host=d.host, username=d.username, password=decrypt_secret(d.password_enc),
                port=d.port, use_tls=d.use_tls, tls_fingerprint=getattr(d, "tls_fingerprint", None), timeout=30.0,
            )
            res = fn(creds)
            res.device_id, res.device_name = did, name
        except Exception as exc:  # noqa: BLE001 — ошибка одного устройства не останавливает остальные
            logger.warning("address-lists failed on {}: {}", d.host, exc)
            res = ALResult(device_id=did, device_name=name, ok=False, message=str(exc))
        results.append(res)
    return results


@router.post("/read", response_model=ALOut)
def read_lists(
    payload: ReadIn,
    db: Session = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
) -> ALOut:
    if not payload.device_ids:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Не выбрано ни одного устройства")
    name = payload.list_name.strip()
    if len(name) > 64 or _CTRL.search(name):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Некорректное название списка")

    def fn(creds: RouterOSCredentials) -> ALResult:
        with routeros_session(creds) as api:
            if payload.entries:
                rows = _rows(api, name or None, KEYS)
            else:
                rows = _rows(api, None, ("list", "dynamic"))
        lists = _summary(rows)
        if not payload.entries:
            return ALResult(device_id=0, ok=True, lists=lists,
                            message=f"списков: {len(lists)}, записей: {len(rows)}")
        ents = [{
            "list": _norm(r.get("list")), "address": _norm(r.get("address")),
            "comment": _norm(r.get("comment")) or None, "timeout": _norm(r.get("timeout")) or None,
            "dynamic": _truthy(r.get("dynamic")), "disabled": _truthy(r.get("disabled")),
        } for r in rows[:MAX_ENTRIES]]
        return ALResult(device_id=0, ok=True, lists=lists, entries=ents, truncated=len(rows) > MAX_ENTRIES,
                        message=f"записей: {len(rows)}" + (f" (показано {MAX_ENTRIES})" if len(rows) > MAX_ENTRIES else ""))

    return ALOut(results=_each(db, payload.device_ids, fn))


@router.post("/preview", response_model=ALOut)
def preview(
    payload: ChangeIn,
    db: Session = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
) -> ALOut:
    addrs, new_addr = _validate(payload)

    def fn(creds: RouterOSCredentials) -> ALResult:
        with routeros_session(creds) as api:
            plan = _plan(api, payload, addrs, new_addr)
        ok = not plan["errors"]
        return ALResult(
            device_id=0, ok=ok, errors=plan["errors"], warnings=plan["warnings"],
            lines=_trim(plan["lines"]), message=("будет: " + _counts(plan)) if ok else "есть ошибки, применять нельзя",
        )

    return ALOut(results=_each(db, payload.device_ids, fn))


@router.post("/apply", response_model=ALOut)
def apply(
    payload: ChangeIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin")),
) -> ALOut:
    addrs, new_addr = _validate(payload)
    logger.info("address-lists apply by {}: action={} list={} addresses={} whole={} devices={}",
                user.email, payload.action, payload.list_name, len(addrs), payload.whole_list, payload.device_ids)

    def fn(creds: RouterOSCredentials) -> ALResult:
        with routeros_session(creds) as api:
            plan = _plan(api, payload, addrs, new_addr)
            if plan["errors"]:
                return ALResult(device_id=0, ok=False, errors=plan["errors"], warnings=plan["warnings"],
                                message="не применено: есть ошибки")
            added, removed, updated, errs = _execute(api, plan)
        msg = f"выполнено: добавлено {added}, удалено {removed}, изменено {updated}, пропущено {plan['skipped']}"
        return ALResult(
            device_id=0, ok=not errs, message=msg if not errs else msg + "; часть операций не удалась",
            errors=errs, warnings=plan["warnings"], lines=_trim(plan["lines"]), undo=plan["undo"][:5000],
        )

    return ALOut(results=_each(db, payload.device_ids, fn))
