"""Конвертер команд RouterOS (синтаксис терминала) в формат API и их выполнение."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .routeros.client import RouterOSCredentials, RouterOSError, routeros_session


class ConvertError(Exception):
    """Команду нельзя перевести в формат API (текст показывается пользователю)."""


MAX_IDS = 500
MAX_ROWS = 2000
COMMAND_WORDS = {
    "add", "set", "remove", "enable", "disable", "print", "find", "get",
    "comment", "move", "unset", "export", "import", "edit", "run",
}
TARGET_COMMANDS = {"set", "remove", "enable", "disable", "move"}
NEED_TARGET = {"remove", "enable", "disable", "move"}
PRINT_DROP = {"detail", "terse", "brief", "without-paging", "as-value", "value-list", "verbose", "stats", "oid"}
PRINT_UNSUPPORTED = {"follow", "follow-only"}
DANGEROUS_PREFIXES = (
    "/system/reboot", "/system/shutdown", "/system/reset-configuration",
    "/system/routerboard/upgrade", "/file/remove",
)

_WORD = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")
_KEY = re.compile(r"^[A-Za-z.][A-Za-z0-9_.-]*$")
_PARAM = re.compile(r"^(?P<k>[A-Za-z.][A-Za-z0-9_.-]*)=(?P<v>.*)$", re.S)
_COND = re.compile(r"^(?P<k>[A-Za-z.][A-Za-z0-9_.-]*)(?P<op>!=|>=|<=|=|~|<|>)(?P<v>.*)$", re.S)
_IDS = re.compile(r"^\*[0-9A-Fa-f]+(,\*[0-9A-Fa-f]+)*$")
_ESC = {"n": "\n", "r": "\r", "t": "\t"}
_BOOL = {"yes": "true", "true": "true", "no": "false", "false": "false"}


@dataclass
class Cond:
    key: str
    op: str            # = != ~ < > <= >= true false
    value: str = ""


@dataclass
class Parsed:
    source: str
    api_path: str = ""
    menu: str = ""
    command: str = ""
    params: dict[str, str] = field(default_factory=dict)
    where: list[Cond] = field(default_factory=list)
    ids: list[str] = field(default_factory=list)
    target_find: bool = False
    count_only: bool = False
    proplist: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    dangerous: bool = False
    script: bool = False


# ------------------------------------------------------------------ разбор

def _strip_quoted(line: str) -> str:
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', line)


def _is_script(line: str) -> bool:
    bare = _strip_quoted(line)
    return bool(bare.lstrip().startswith(":") or re.search(r"[{};$]", bare) or re.search(r"\[\s*:", bare))


def tokenize(s: str) -> list[str]:
    toks: list[str] = []
    cur: list[str] = []
    has = False
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c.isspace():
            if has:
                toks.append("".join(cur))
                cur, has = [], False
            i += 1
        elif c == '"':
            has = True
            i += 1
            while True:
                if i >= n:
                    raise ConvertError("незакрытая кавычка")
                ch = s[i]
                if ch == '"':
                    i += 1
                    break
                if ch == "\\" and i + 1 < n:
                    cur.append(_ESC.get(s[i + 1], s[i + 1]))
                    i += 2
                else:
                    cur.append(ch)
                    i += 1
        elif c == "[":
            has = True
            depth, j, in_q = 0, i, False
            while j < n:
                ch = s[j]
                if in_q:
                    if ch == "\\":
                        j += 2
                        continue
                    if ch == '"':
                        in_q = False
                else:
                    if ch == '"':
                        in_q = True
                    elif ch == "[":
                        depth += 1
                    elif ch == "]":
                        depth -= 1
                        if depth == 0:
                            break
                j += 1
            if j >= n or depth != 0:
                raise ConvertError("незакрытая скобка «[»")
            cur.append(s[i:j + 1])
            i = j + 1
        else:
            has = True
            cur.append(c)
            i += 1
    if has:
        toks.append("".join(cur))
    return toks


def parse_where(tokens: list[str]) -> list[Cond]:
    out: list[Cond] = []
    for t in tokens:
        low = t.lower()
        if low in ("and", "&&"):
            continue
        if low in ("or", "||"):
            raise ConvertError("оператор «or» в where не поддерживается: выполните два запроса")
        if t in ("(", ")"):
            raise ConvertError("скобки группировки в where не поддерживаются")
        m = _COND.match(t)
        if m:
            c = Cond(m["k"], m["op"], m["v"])
            if c.op == "~":
                try:
                    re.compile(c.value)
                except re.error:
                    raise ConvertError(f"некорректное регулярное выражение: {c.value}")
            out.append(c)
        elif t.startswith("!") and _KEY.match(t[1:]):
            out.append(Cond(t[1:], "false"))
        elif _KEY.match(t):
            out.append(Cond(t, "true"))
        else:
            raise ConvertError(f"не удалось разобрать условие where: «{t}»")
    return out


def _set_target(p: Parsed, v: str) -> None:
    if p.ids or p.target_find:
        raise ConvertError("цель команды указана дважды")
    if v.startswith("[") and v.endswith("]"):
        inner = tokenize(v[1:-1])
        if not inner or inner[0].lower() != "find":
            raise ConvertError("в квадратных скобках поддерживается только [find ...]")
        rest = inner[1:]
        if rest and rest[0].lower() == "where":
            rest = rest[1:]
        conds = parse_where(rest)
        if not conds:
            raise ConvertError("пустой [find] охватил бы все записи: укажите условие или *ID")
        p.where += conds
        p.target_find = True
    elif _IDS.match(v):
        p.ids += v.split(",")
    else:
        raise ConvertError(
            f"цель «{v}»: номера и имена записей в API недоступны, используйте [find ...] или *ID"
        )


def _as_script(p: Parsed, why: str) -> Parsed:
    p.script = True
    p.command = "execute"
    p.menu = ""
    p.api_path = "/execute"
    p.params = {"script": p.source}
    p.notes.append(f"{why}: передаётся роутеру как /execute script=…; вывод не возвращается")
    return p


def parse(source: str) -> Parsed:
    line = source.strip()
    if not line:
        raise ConvertError("пустая команда")
    p = Parsed(source=line)
    if _is_script(line):
        return _as_script(p, "скриптовая конструкция")

    toks = tokenize(line)
    first = toks[0]
    if not first.startswith("/"):
        raise ConvertError("команда должна начинаться с «/» (полный путь меню, например /ip address print)")
    segs = [s for s in first.split("/") if s]
    if not segs:
        raise ConvertError("не указан путь команды")
    i = 1
    if segs[-1] not in COMMAND_WORDS:
        while i < len(toks) and _WORD.match(toks[i]) and toks[i].lower() != "where":
            segs.append(toks[i])
            i += 1
            if segs[-1] in COMMAND_WORDS:
                break
    p.command = segs[-1]
    p.menu = "/" + "/".join(segs[:-1])
    p.api_path = "/" + "/".join(segs)
    cmd = p.command

    if cmd in ("export", "import"):
        return _as_script(p, f"«{cmd}» недоступна через API")

    args = toks[i:]
    k = 0
    while k < len(args):
        t = args[k]
        k += 1
        if t.lower() == "where":
            if p.target_find:
                raise ConvertError("цель команды указана дважды")
            p.where += parse_where(args[k:])
            break
        if t.startswith("["):
            _set_target(p, t)
            continue
        m = _PARAM.match(t)
        if m:
            key, val = m["k"], m["v"]
            if key in ("numbers", ".id"):
                _set_target(p, val)
            elif val.startswith("[") and val.endswith("]"):
                raise ConvertError(
                    f"параметр {key}: подстановки [...] поддерживаются только как цель команды (numbers=[find ...])"
                )
            elif cmd == "print" and key == "proplist":
                p.proplist = [x for x in val.split(",") if x]
            elif cmd == "print" and key == "interval":
                raise ConvertError("print interval=… (постоянное обновление) через API недоступен")
            elif cmd == "print":
                p.where.append(Cond(key, "=", val))
                p.notes.append(f"параметр «{key}» в print воспринят как условие where")
            else:
                p.params[key] = val
            continue
        low = t.lower()
        if cmd == "print":
            if low == "count-only":
                p.count_only = True
                continue
            if low in PRINT_DROP:
                p.notes.append(f"модификатор «{t}» отброшен: у API нет форматов вывода")
                continue
            if low in PRINT_UNSUPPORTED:
                raise ConvertError(f"print {t} (постоянное обновление) через API недоступен")
        if _IDS.match(t):
            _set_target(p, t)
            continue
        raise ConvertError(
            f"позиционный аргумент «{t}» (номер или имя записи) в API недоступен, используйте [find ...] или *ID"
        )

    has_target = bool(p.ids or p.where)
    messages = {
        "get": "get через API не поддерживается: используйте print where … proplist=…",
        "comment": "comment: используйте set [find …] comment=…",
        "unset": "unset через API не поддерживается: задайте значение через set",
        "edit": "edit — интерактивная команда, в API недоступна",
        "find": "find: используйте print where …",
    }
    if cmd in messages:
        raise ConvertError(messages[cmd])
    if cmd == "print":
        if p.ids:
            raise ConvertError("print: *ID не поддерживается, используйте where .id=*ID")
    elif cmd == "add":
        if has_target:
            raise ConvertError("add: цель и where не используются")
    elif cmd in NEED_TARGET and not has_target:
        raise ConvertError(f"{cmd}: нужна цель, например numbers=[find …] или *ID")
    elif has_target and cmd not in TARGET_COMMANDS:
        raise ConvertError(f"для команды «{cmd}» цель и where не поддерживаются")
    if cmd == "move" and "destination" in p.params and not _IDS.match(p.params["destination"]):
        p.warnings.append("move: destination должен быть *ID записи")
    if cmd in TARGET_COMMANDS and has_target:
        p.notes.append("записи находятся запросом print по условию, затем команда выполняется для каждой по .id")
    p.dangerous = cmd == "remove" or any(p.api_path.startswith(x) for x in DANGEROUS_PREFIXES)
    return p


def _q(v: str) -> str:
    if v and not re.search(r'[\s"\\\[\]]', v):
        return v
    esc = (v.replace("\\", "\\\\").replace('"', '\\"')
           .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t"))
    return f'"{esc}"'


def _cond_str(c: Cond) -> str:
    if c.op == "true":
        return c.key
    if c.op == "false":
        return f"!{c.key}"
    return f"{c.key}{c.op}{_q(c.value)}"


def api_line(p: Parsed) -> str:
    parts = [p.api_path]
    if p.ids:
        parts.append(".id=" + ",".join(p.ids))
    parts += [f"{k}={_q(v)}" for k, v in p.params.items()]
    if p.proplist:
        parts.append("proplist=" + ",".join(p.proplist))
    if p.count_only:
        parts.append("count-only")
    if p.where:
        parts.append("where " + " ".join(_cond_str(c) for c in p.where))
    return " ".join(parts)


def split_statements(text: str) -> list[str]:
    text = re.sub(r"\\\r?\n[ \t]*", " ", text)
    out: list[str] = []
    buf: list[str] = []
    depth = 0
    for raw in text.splitlines():
        line = raw.rstrip()
        if not buf and (not line.strip() or line.lstrip().startswith("#")):
            continue
        buf.append(line)
        bare = _strip_quoted(line)
        depth += bare.count("{") - bare.count("}")
        if depth <= 0:
            out.append("\n".join(buf).strip())
            buf, depth = [], 0
    if buf:
        out.append("\n".join(buf).strip())
    return out


def convert_text(text: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for n, stmt in enumerate(split_statements(text), 1):
        item: dict[str, Any] = {
            "n": n, "source": stmt, "api": None, "path": None, "command": None,
            "notes": [], "warnings": [], "error": None, "dangerous": False,
        }
        try:
            p = parse(stmt)
            item.update(api=api_line(p), path=p.api_path, command=p.command,
                        notes=p.notes, warnings=p.warnings, dangerous=p.dangerous)
        except ConvertError as exc:
            item["error"] = str(exc)
        items.append(item)
    return items


# ------------------------------------------------------------------ выполнение

def _nb(s: str) -> str:
    return _BOOL.get(s.lower(), s)


def _match(row: dict[str, Any], c: Cond) -> bool:
    cur = row.get(c.key)
    s = "" if cur is None else str(cur)
    if c.op == "true":
        return _nb(s) == "true"
    if c.op == "false":
        return _nb(s) != "true"
    if c.op == "=":
        return _nb(s) == _nb(c.value)
    if c.op == "!=":
        return _nb(s) != _nb(c.value)
    if c.op == "~":
        return re.search(c.value, s) is not None
    try:
        a, b = float(s), float(c.value)
    except ValueError:
        return False
    return {"<": a < b, ">": a > b, "<=": a <= b, ">=": a >= b}[c.op]


def _match_all(row: dict[str, Any], conds: list[Cond]) -> bool:
    return all(_match(row, c) for c in conds)


def _cap(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if len(rows) > MAX_ROWS:
        return rows[:MAX_ROWS] + [{"truncated": True, "total": len(rows)}]
    return rows


def _run(api: Any, p: Parsed) -> list[dict[str, Any]]:
    if p.command == "print" and not p.script:
        rows = list(api(cmd=p.api_path))
        if p.where:
            rows = [r for r in rows if _match_all(r, p.where)]
        if p.count_only:
            return [{"count": len(rows)}]
        if p.proplist:
            rows = [{k: r[k] for k in p.proplist if k in r} for r in rows]
        return _cap(rows)

    if (p.ids or p.where) and p.command in TARGET_COMMANDS:
        ids = list(p.ids)
        if p.where:
            menu = p.api_path.rsplit("/", 1)[0]
            ids += [str(r[".id"]) for r in api(cmd=menu + "/print")
                    if ".id" in r and _match_all(r, p.where)]
        ids = list(dict.fromkeys(ids))
        if not ids:
            return [{"result": "записи не найдены, ничего не изменено"}]
        if len(ids) > MAX_IDS:
            raise ConvertError(f"под условие подходит {len(ids)} записей (максимум {MAX_IDS}): уточните условие")
        key = "numbers" if p.command == "move" else ".id"
        out: list[dict[str, Any]] = []
        for rid in ids:
            try:
                list(api(cmd=p.api_path, **{key: rid, **p.params}))
                out.append({"id": rid, "ok": True})
            except Exception as exc:  # noqa: BLE001 — ошибка одной записи не останавливает остальные
                out.append({"id": rid, "ok": False, "error": str(exc)})
        return out

    return list(api(cmd=p.api_path, **p.params))


def run(creds: RouterOSCredentials, p: Parsed) -> list[dict[str, Any]]:
    try:
        with routeros_session(creds) as api:
            return _run(api, p)
    except RouterOSError:
        raise
    except ConvertError as exc:
        raise RouterOSError(str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise RouterOSError(f"cli failed: {exc}") from exc
