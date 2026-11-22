from __future__ import annotations

import ipaddress
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ...core.db import get_db
from ...core.security import decrypt_secret, encrypt_secret
from ...models.device import Device
from ...models.user import User
from ...services.events import add_audit
from ...services.routeros.client import (
    RouterOSCredentials,
    RouterOSError,
    execute_cli,
    routeros_session,
)
from ..deps import require_role
from ...services.routeros import management as mg
from ...services.cli_convert import ConvertError, convert_text, parse as parse_command, run as run_parsed

router = APIRouter()


# Опасные команды требуют явного подтверждения через query ?confirm=1
DANGEROUS_PREFIXES = (
    "/system/reboot",
    "/system/shutdown",
    "/system/reset-configuration",
    "/system/routerboard/upgrade",
    "/file/remove",
)


class CLIRunIn(BaseModel):
    device_ids: list[int] = Field(default_factory=list)
    command: str
    confirm: bool = False


class CLIDeviceResult(BaseModel):
    device_id: int
    device_name: str | None = None
    ok: bool
    rows: list[dict[str, Any]] | None = None
    error: str | None = None


class CLIRunOut(BaseModel):
    command: str
    results: list[CLIDeviceResult]


@router.post("/run", response_model=CLIRunOut)
def run_cli(
    payload: CLIRunIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin", "operator")),
) -> CLIRunOut:
    if not payload.device_ids:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "device_ids is empty")
    cmd = payload.command.strip()
    if not cmd:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "command is empty")

    try:
        parsed = parse_command(cmd)
    except ConvertError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

    is_dangerous = parsed.dangerous or any(cmd.startswith(p) for p in DANGEROUS_PREFIXES)
    if is_dangerous and not payload.confirm:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "dangerous command requires confirmation (set confirm=true)",
        )

    results: list[CLIDeviceResult] = []
    for did in payload.device_ids:
        d = db.get(Device, did)
        if not d:
            results.append(CLIDeviceResult(device_id=did, ok=False, error="device not found"))
            continue
        try:
            rows = run_parsed(RouterOSCredentials(
                    host=d.host,
                    username=d.username,
                    password=decrypt_secret(d.password_enc),
                    port=d.port,
                    use_tls=d.use_tls, tls_fingerprint=getattr(d, "tls_fingerprint", None),
                    timeout=10.0,
                ), parsed)
            results.append(
                CLIDeviceResult(device_id=did, device_name=d.identity or d.name, ok=True, rows=rows)
            )
        except RouterOSError as exc:
            results.append(
                CLIDeviceResult(device_id=did, device_name=d.identity or d.name, ok=False, error=str(exc))
            )
        add_audit(
            db,
            actor=user.email,
            action="cli.run",
            target=f"device:{did}",
            detail=cmd[:200],
        )

    return CLIRunOut(command=cmd, results=results)


# ---------- Добавление пользователя на устройства ----------
# Пароль приходит в теле запроса и передаётся роутеру параметром API-вызова
# (а не склеивается в текст команды). Он НЕ логируется и НЕ попадает в ответ.

_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


class AddUserIn(BaseModel):
    device_ids: list[int] = Field(default_factory=list)
    username: str
    password: str
    group: str = "read"
    address: str = ""          # необязательное ограничение по адресам, через запятую
    update_existing: bool = False


class AddUserDeviceResult(BaseModel):
    device_id: int
    device_name: str | None = None
    ok: bool
    action: str | None = None  # created | updated | exists
    error: str | None = None


class AddUserOut(BaseModel):
    username: str
    results: list[AddUserDeviceResult]


def _apply_user(creds: RouterOSCredentials, username: str, password: str,
                group: str, address: str, update_existing: bool) -> str:
    with routeros_session(creds) as api:
        groups = {g.get("name") for g in api.path("user", "group")}
        if group not in groups:
            raise RouterOSError(f"группа «{group}» не найдена на устройстве")
        users = api.path("user")
        existing = next((u for u in users if u.get("name") == username), None)
        if existing:
            if not update_existing:
                return "exists"
            params = {".id": existing[".id"], "password": password, "group": group}
            if address:
                params["address"] = address
            users.update(**params)
            return "updated"
        params = {"name": username, "password": password, "group": group}
        if address:
            params["address"] = address
        users.add(**params)
        return "created"


@router.post("/add-user", response_model=AddUserOut)
def add_user(
    payload: AddUserIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin")),
) -> AddUserOut:
    if not payload.device_ids:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Не выбрано ни одного устройства")
    username = payload.username.strip()
    group = payload.group.strip()
    if not _NAME_RE.match(username):
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "Логин: 1-32 символа, только латиница, цифры, _ . -")
    if not _NAME_RE.match(group):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Некорректное имя группы")
    pwd = payload.password
    if len(pwd) < 8 or len(pwd) > 128 or any(ord(c) < 32 for c in pwd):
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "Пароль: 8-128 символов, без управляющих символов")
    address = ""
    if payload.address.strip():
        parts = [a.strip() for a in payload.address.split(",") if a.strip()]
        try:
            address = ",".join(str(ipaddress.ip_network(a, strict=False)) for a in parts)
        except ValueError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                "Адрес: IP или подсеть, через запятую")

    logger.info("add-user by {}: login={} group={} devices={} update={}",
                user.email, username, group, payload.device_ids, payload.update_existing)

    results: list[AddUserDeviceResult] = []
    for did in payload.device_ids:
        d = db.get(Device, did)
        if not d:
            results.append(AddUserDeviceResult(device_id=did, ok=False, error="устройство не найдено"))
            continue
        name = d.identity or d.name
        try:
            action = _apply_user(
                RouterOSCredentials(
                    host=d.host, username=d.username,
                    password=decrypt_secret(d.password_enc),
                    port=d.port, use_tls=d.use_tls, tls_fingerprint=getattr(d, "tls_fingerprint", None), timeout=10.0,
                ),
                username, pwd, group, address, payload.update_existing,
            )
            results.append(AddUserDeviceResult(device_id=did, device_name=name, ok=True, action=action))
        except Exception as exc:  # noqa: BLE001 — любая ошибка роутера показывается построчно
            msg = str(exc)
            if pwd:
                msg = msg.replace(pwd, "***")
            logger.warning("add-user failed on {}: {}", d.host, msg)
            results.append(AddUserDeviceResult(device_id=did, device_name=name, ok=False, error=msg))
    return AddUserOut(username=username, results=results)


# ---------- Смена пароля и удаление пользователя на устройствах ----------

class ChangePwdIn(BaseModel):
    device_ids: list[int] = Field(default_factory=list)
    username: str
    password: str


class DeleteUserIn(BaseModel):
    device_ids: list[int] = Field(default_factory=list)
    username: str


def _check_username(raw: str) -> str:
    name = raw.strip()
    if not _NAME_RE.match(name):
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "Логин: 1-32 символа, только латиница, цифры, _ . -")
    return name


def _check_password(pwd: str) -> None:
    if len(pwd) < 8 or len(pwd) > 128 or any(ord(c) < 32 for c in pwd):
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "Пароль: 8-128 символов, без управляющих символов")


def _foreach_device(db: Session, device_ids: list[int], op, secret: str = "") -> list[AddUserDeviceResult]:
    """Выполняет op(creds, device) -> action на каждом устройстве.
    Ошибка одного устройства не останавливает остальные; секрет вычищается из текста ошибки."""
    results: list[AddUserDeviceResult] = []
    for did in device_ids:
        d = db.get(Device, did)
        if not d:
            results.append(AddUserDeviceResult(device_id=did, ok=False, error="устройство не найдено"))
            continue
        name = d.identity or d.name
        try:
            creds = RouterOSCredentials(
                host=d.host, username=d.username,
                password=decrypt_secret(d.password_enc),
                port=d.port, use_tls=d.use_tls, tls_fingerprint=getattr(d, "tls_fingerprint", None), timeout=10.0,
            )
            action = op(creds, d)
            results.append(AddUserDeviceResult(device_id=did, device_name=name, ok=True, action=action))
        except Exception as exc:  # noqa: BLE001 — ошибка роутера показывается построчно
            msg = str(exc)
            if secret:
                msg = msg.replace(secret, "***")
            logger.warning("user op failed on {}: {}", d.host, msg)
            results.append(AddUserDeviceResult(device_id=did, device_name=name, ok=False, error=msg))
    return results


@router.post("/change-password", response_model=AddUserOut)
def change_user_password(
    payload: ChangePwdIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin")),
) -> AddUserOut:
    if not payload.device_ids:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Не выбрано ни одного устройства")
    username = _check_username(payload.username)
    _check_password(payload.password)
    pwd = payload.password
    logger.info("change-password by {}: login={} devices={}", user.email, username, payload.device_ids)

    def op(creds: RouterOSCredentials, d: Device) -> str:
        if username == d.username:
            raise RouterOSError(
                "это учётная запись самого контроллера на данном устройстве: "
                "смените пароль на роутере и затем в «Изменить» устройства"
            )
        with routeros_session(creds) as api:
            users = api.path("user")
            existing = next((u for u in users if u.get("name") == username), None)
            if not existing:
                return "missing"
            users.update(**{".id": existing[".id"], "password": pwd})
            return "updated"

    return AddUserOut(username=username, results=_foreach_device(db, payload.device_ids, op, pwd))


@router.post("/delete-user", response_model=AddUserOut)
def delete_device_user(
    payload: DeleteUserIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin")),
) -> AddUserOut:
    if not payload.device_ids:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Не выбрано ни одного устройства")
    username = _check_username(payload.username)
    logger.info("delete-user by {}: login={} devices={}", user.email, username, payload.device_ids)

    def op(creds: RouterOSCredentials, d: Device) -> str:
        if username == d.username:
            raise RouterOSError(
                "это учётная запись самого контроллера на данном устройстве, удалять её нельзя"
            )
        with routeros_session(creds) as api:
            users = api.path("user")
            rows = list(users)
            existing = next((u for u in rows if u.get("name") == username), None)
            if not existing:
                return "missing"
            if existing.get("group") == "full":
                others = [u for u in rows if u.get("group") == "full" and u.get(".id") != existing.get(".id")]
                if not others:
                    raise RouterOSError("это последний пользователь группы full, удалять его нельзя")
            users.remove(existing[".id"])
            return "deleted"

    return AddUserOut(username=username, results=_foreach_device(db, payload.device_ids, op))


# ---------- Разрешённые адреса служб (/ip service, «Available From» в Winbox) ----------
# api/api-ssl: чтение; добавление адреса контроллера — только в постоянной очереди.

ALLOWED_SERVICES = ("winbox", "ssh", "telnet", "ftp", "www", "www-ssl", "api", "api-ssl")


class ServiceReadIn(BaseModel):
    device_ids: list[int] = Field(default_factory=list)
    service: str = "winbox"


class ServiceSetIn(ServiceReadIn):
    mode: str = "add"          # add | remove | set
    addresses: str = ""        # IP или подсети через запятую
    allow_any: bool = False    # при mode=set: очистить список (разрешить с любого адреса)


class ServiceAddrResult(BaseModel):
    device_id: int
    device_name: str | None = None
    ok: bool
    action: str | None = None  # changed | unchanged | skipped | read
    before: str | None = None
    after: str | None = None
    note: str | None = None
    error: str | None = None


class ServiceAddrOut(BaseModel):
    service: str
    results: list[ServiceAddrResult]


def _norm_addr(a: str) -> str:
    a = a.strip()
    try:
        return str(ipaddress.ip_network(a, strict=False))
    except ValueError:
        return a


def _norm_list(raw: str | None) -> list[str]:
    out: list[str] = []
    for a in (raw or "").split(","):
        if a.strip():
            n = _norm_addr(a)
            if n not in out:
                out.append(n)
    return out


def _parse_addresses(text: str) -> list[str]:
    out: list[str] = []
    for a in text.split(","):
        a = a.strip()
        if not a:
            continue
        try:
            n = str(ipaddress.ip_network(a, strict=False))
        except ValueError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Некорректный адрес: {a}")
        if n not in out:
            out.append(n)
    return out


def _check_service(name: str) -> str:
    name = name.strip()
    if name not in ALLOWED_SERVICES:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Служба не поддерживается",
        )
    return name


def _service_loop(db: Session, device_ids: list[int], op) -> list[ServiceAddrResult]:
    results: list[ServiceAddrResult] = []
    for did in device_ids:
        d = db.get(Device, did)
        if not d:
            results.append(ServiceAddrResult(device_id=did, ok=False, error="устройство не найдено"))
            continue
        name = d.identity or d.name
        try:
            creds = RouterOSCredentials(
                host=d.host, username=d.username,
                password=decrypt_secret(d.password_enc),
                port=d.port, use_tls=d.use_tls, tls_fingerprint=getattr(d, "tls_fingerprint", None), timeout=10.0,
            )
            action, before, after, note = op(creds, d)
            results.append(ServiceAddrResult(
                device_id=did, device_name=name, ok=True,
                action=action, before=before, after=after, note=note,
            ))
        except Exception as exc:  # noqa: BLE001 — ошибка роутера показывается построчно
            logger.warning("ip-service op failed on {}: {}", d.host, exc)
            results.append(ServiceAddrResult(device_id=did, device_name=name, ok=False, error=str(exc)))
    return results


@router.post("/ip-service/read", response_model=ServiceAddrOut)
def read_service_addresses(
    payload: ServiceReadIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin", "operator")),
) -> ServiceAddrOut:
    if not payload.device_ids:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Не выбрано ни одного устройства")
    service = _check_service(payload.service)

    def op(creds: RouterOSCredentials, d: Device):
        with routeros_session(creds) as api:
            row = mg.static_service(api, service)
            cur = ",".join(_norm_list(mg.service_address(row)))
            return "read", cur, cur, None

    return ServiceAddrOut(service=service, results=_service_loop(db, payload.device_ids, op))


@router.post("/ip-service/set", response_model=ServiceAddrOut)
def set_service_addresses(
    payload: ServiceSetIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin")),
) -> ServiceAddrOut:
    if not payload.device_ids:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Не выбрано ни одного устройства")
    service = _check_service(payload.service)
    mode = payload.mode
    if mode not in ("add", "remove", "set"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Неизвестный режим")
    given = _parse_addresses(payload.addresses)
    if mode == "set" and payload.allow_any:
        given = []
    elif not given:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Укажите хотя бы один адрес")
    if service in ('api','api-ssl'):
        raise HTTPException(422, 'Для API и API-SSL добавляйте IPv4 контроллера /32 через постоянную очередь управления службами ниже; удаление и замена запрещены')
    logger.info("ip-service {} by {}: service={} mode={} addresses={} devices={}",
                "set", user.email, service, mode, given, payload.device_ids)

    def op(creds: RouterOSCredentials, d: Device):
        with routeros_session(creds) as api:
            path = api.path("ip", "service")
            row = mg.static_service(api, service)
            if str(row.get("port")) == str(d.port):
                raise RouterOSError(
                    "через эту службу контроллер подключён к устройству, менять её нельзя"
                )
            cur = _norm_list(mg.service_address(row))
            before = ",".join(cur)

            if mode == "set":
                new = given
            elif mode == "add":
                if not cur:
                    return ("skipped", before, before,
                            "сейчас разрешено с любого адреса, «добавить» сузило бы доступ; используйте «заменить»")
                new = cur + [a for a in given if a not in cur]
            else:  # remove
                if not cur:
                    return "skipped", before, before, "список пуст (разрешено всем), убирать нечего"
                new = [a for a in cur if a not in given]
                if not new:
                    return ("skipped", before, before,
                            "после удаления список стал бы пустым (= разрешено всем); используйте «заменить»")

            if new == cur:
                return "unchanged", before, before, None
            if mg.static_service(api, service) != row:
                raise RouterOSError('Служба изменилась после чтения; повторите проверку')
            path.update(**{".id": row[".id"], mg.service_address_field(row): ",".join(new)})
            actual = _norm_list(mg.service_address(mg.static_service(api, service)))
            if set(actual) != set(new):
                raise RouterOSError('Изменение не подтверждено; проверьте службу вручную')
            return "changed", before, ",".join(actual), None

    return ServiceAddrOut(service=service, results=_service_loop(db, payload.device_ids, op))


# ---------- Список групп пользователей на устройствах ----------

class GroupsIn(BaseModel):
    device_ids: list[int] = Field(default_factory=list)


class GroupsOut(BaseModel):
    groups: list[str]
    failed: int = 0


@router.post("/user-groups", response_model=GroupsOut)
def user_groups(
    payload: GroupsIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin")),
) -> GroupsOut:
    if not payload.device_ids:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Не выбрано ни одного устройства")
    found: set[str] = set()
    failed = 0
    for did in payload.device_ids:
        d = db.get(Device, did)
        if not d:
            failed += 1
            continue
        try:
            with routeros_session(RouterOSCredentials(
                host=d.host, username=d.username,
                password=decrypt_secret(d.password_enc),
                port=d.port, use_tls=d.use_tls, tls_fingerprint=getattr(d, "tls_fingerprint", None), timeout=10.0,
            )) as api:
                for g in api.path("user", "group"):
                    name = g.get("name")
                    if name:
                        found.add(str(name))
        except Exception as exc:  # noqa: BLE001
            failed += 1
            logger.warning("user-groups failed on {}: {}", d.host, exc)
    order = {"read": 0, "write": 1, "full": 2}
    return GroupsOut(groups=sorted(found, key=lambda g: (order.get(g, 3), g)), failed=failed)


# ---------- Массовая смена данных подключения контроллера к устройствам ----------
# Новая пара логин/пароль сначала проверяется входом на устройство; в БД сохраняется
# только после успешного входа. Пароль не логируется и вычищается из текста ошибок.

class BulkCredsIn(BaseModel):
    device_ids: list[int] = Field(default_factory=list)
    username: str
    password: str
    transport: str = "keep"    # keep | api (8728) | api-ssl (8729)
    apply: bool = False        # False = только проверить


class BulkCredsResult(BaseModel):
    device_id: int
    device_name: str | None = None
    ok: bool
    action: str | None = None  # verified | saved
    endpoint: str | None = None
    error: str | None = None


class BulkCredsOut(BaseModel):
    results: list[BulkCredsResult]


@router.post("/bulk-credentials", response_model=BulkCredsOut)
def bulk_credentials(
    payload: BulkCredsIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin")),
) -> BulkCredsOut:
    if not payload.device_ids:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Не выбрано ни одного устройства")
    username = payload.username.strip()
    if not _NAME_RE.match(username):
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "Логин: 1-32 символа, только латиница, цифры, _ . -")
    pwd = payload.password
    if not pwd or len(pwd) > 128 or any(ord(c) < 32 for c in pwd):
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "Пароль: от 1 до 128 символов, без управляющих символов")
    if payload.transport not in ("keep", "api", "api-ssl"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Неизвестный тип подключения")

    logger.info("bulk-credentials by {}: login={} transport={} apply={} devices={}",
                user.email, username, payload.transport, payload.apply, payload.device_ids)

    results: list[BulkCredsResult] = []
    for did in payload.device_ids:
        d = db.get(Device, did)
        if not d:
            results.append(BulkCredsResult(device_id=did, ok=False, error="устройство не найдено"))
            continue
        name = d.identity or d.name
        if payload.transport == "api":
            port, tls = 8728, False
        elif payload.transport == "api-ssl":
            port, tls = 8729, True
        else:
            port, tls = d.port, d.use_tls
        if d.tls_fingerprint and (not tls or port != d.port):
            results.append(BulkCredsResult(device_id=did, device_name=name, ok=False, error="Защищённый транспорт нельзя менять через массовые учётные данные"))
            continue
        endpoint = f"{d.host}:{port}{' (TLS)' if tls else ''}"
        if tls and not d.tls_fingerprint:
            results.append(BulkCredsResult(device_id=did, device_name=name, ok=False, endpoint=endpoint,
                error="Сначала сверить и закрепить TLS-отпечаток во вкладке Безопасность или Службы IP"))
            continue
        try:
            creds = RouterOSCredentials(
                host=d.host, username=username, password=pwd,
                port=port, use_tls=tls, timeout=10.0, tls_fingerprint=d.tls_fingerprint,
            )
            with routeros_session(creds) as api:
                list(api.path("system", "identity"))   # реальный запрос: вход должен пройти
            if payload.apply:
                d.username = username
                d.password_enc = encrypt_secret(pwd)
                d.port = port
                d.use_tls = tls
                d.last_error = None
                db.commit()
                action = "saved"
            else:
                action = "verified"
            results.append(BulkCredsResult(
                device_id=did, device_name=name, ok=True, action=action, endpoint=endpoint,
            ))
        except Exception as exc:  # noqa: BLE001 — любая ошибка показывается построчно
            db.rollback()
            msg = str(exc).replace(pwd, "***")
            logger.warning("bulk-credentials failed on {}: {}", d.host, msg)
            results.append(BulkCredsResult(
                device_id=did, device_name=name, ok=False, endpoint=endpoint,
                error=f"вход не удался, настройки не изменены: {msg}",
            ))
    return BulkCredsOut(results=results)


# ---------- Конвертер команд терминала в формат API ----------

class ConvertIn(BaseModel):
    text: str


@router.post("/convert")
def convert_commands(
    payload: ConvertIn,
    user: User = Depends(require_role("admin", "operator")),
) -> dict[str, Any]:
    text = payload.text
    if not text.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Введите команды")
    if len(text) > 20000:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Слишком длинный текст (максимум 20000 символов)")
    items = convert_text(text)
    if len(items) > 200:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Слишком много команд за раз (максимум 200)")
    return {"items": items}
