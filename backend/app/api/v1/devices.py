from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from ...core.db import get_db
from ...core.security import decrypt_secret, encrypt_secret
from ...models.device import Device
from ...models.credential import CredentialProfile
from ...models.metric import DeviceMetric
from ...models.user import User
from ...schemas.device import (
    DeviceCreate,
    DeviceOut,
    DeviceResource,
    DeviceUpdate,
)
from ...services.events import add_alert, add_audit
from ...services.durations import format_duration
from ...services.routeros.client import (
    RouterOSCredentials,
    RouterOSError,
    check_internet,
    cmd_reboot,
    cmd_safe_mode,
    cmd_upgrade_check,
    cmd_upgrade_install,
    fetch_dhcp_leases,
    fetch_identity,
    fetch_interface_stats,
    fetch_resource,
    fetch_serial,
    parse_uptime,
    push_firmware_via_ftp,
)
from ..deps import get_current_user, require_role

router = APIRouter()


def _creds(d: Device) -> RouterOSCredentials:
    return RouterOSCredentials(
        host=d.host,
        username=d.username,
        password=decrypt_secret(d.password_enc),
        port=d.port,
        use_tls=d.use_tls, tls_fingerprint=getattr(d, "tls_fingerprint", None),
    )


@router.get("", response_model=list[DeviceOut])
def list_devices(
    kind: str | None = None,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[Device]:
    q = db.query(Device)
    if kind:
        q = q.filter(Device.kind == kind)
    return q.order_by(Device.id.desc()).all()


@router.post("", response_model=DeviceOut, status_code=status.HTTP_201_CREATED)
def create_device(
    payload: DeviceCreate,
    db: Session = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
) -> Device:
    username = payload.username
    if payload.credential_id:
        prof = db.get(CredentialProfile, payload.credential_id)
        if not prof:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Сохранённая учётная запись не найдена")
        username, password_enc = prof.username, prof.password_enc
    elif not payload.username or not payload.password:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Укажите логин и пароль или выберите сохранённую учётную запись",
        )
    else:
        password_enc = encrypt_secret(payload.password)
    port = payload.port if "port" in payload.model_fields_set else (8729 if payload.use_tls else 8728)
    identity = None
    if payload.use_tls:
        if not payload.tls_fingerprint:
            raise HTTPException(422, "Для API-SSL укажите независимо сверенный SHA-256 отпечаток")
        password = decrypt_secret(password_enc)
        try:
            identity = fetch_identity(RouterOSCredentials(host=payload.host, port=port, username=username, password=password, use_tls=True, tls_fingerprint=payload.tls_fingerprint))
            if not identity:
                raise ValueError("identity missing")
        except Exception as exc:
            raise HTTPException(502, "API-SSL не подтверждён; устройство не добавлено") from exc
    d = Device(
        name=(payload.name or "").strip() or identity or payload.host,
        identity=identity,
        host=payload.host,
        port=port,
        use_tls=payload.use_tls,
        tls_fingerprint=payload.tls_fingerprint if payload.use_tls else None,
        username=username,
        password_enc=password_enc,
        kind=payload.kind or "router",
        group_name=(payload.group_name or "").strip() or None,
    )
    db.add(d)
    db.commit()
    db.refresh(d)
    if not identity and not (payload.name or "").strip():
        try:
            ident = fetch_identity(_creds(d))
            if ident:
                d.name = ident
                d.identity = ident
                db.commit()
                db.refresh(d)
        except Exception:
            pass  # устройство пока недоступно: имя = host, identity подтянется при опросе
    return d


@router.get("/{device_id}", response_model=DeviceOut)
def get_device(
    device_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> Device:
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    return d


@router.patch("/{device_id}", response_model=DeviceOut)
def update_device(
    device_id: int,
    payload: DeviceUpdate,
    db: Session = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
) -> Device:
    d = db.get(Device, device_id, with_for_update=True)
    if not d:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    data = payload.model_dump(exclude_unset=True)
    for key in ("host", "port", "use_tls", "username", "password"):
        if key in data and (data[key] is None or data[key] == ""):
            raise HTTPException(422, "Параметры подключения не могут быть пустыми")
    if "use_tls" in data and "port" not in data and data["use_tls"] != d.use_tls and d.port in (8728,8729):
        data["port"] = 8729 if data["use_tls"] else 8728
    if d.tls_fingerprint and any(k in data and data[k] != getattr(d, k) for k in ("host", "port", "use_tls")):
        raise HTTPException(409, "Защищённый транспорт нельзя менять через обычное редактирование")
    pin = data.pop("tls_fingerprint", None)
    tls = data.get("use_tls", d.use_tls)
    if pin and not tls:
        raise HTTPException(422, "Отпечаток применяется только к API-SSL")
    if pin and d.tls_fingerprint and pin != d.tls_fingerprint:
        raise HTTPException(409, "Смена отпечатка — через вкладку Безопасность")
    pin_added = bool(pin and not d.tls_fingerprint)
    if (pin_added or tls != d.use_tls) and _.role != "admin":
        raise HTTPException(403, "Смена транспорта и закрепление TLS — только администратор")
    changed = pin_added or any(k in data and data[k] != getattr(d, k) for k in ("host", "port", "use_tls", "username")) or "password" in data
    if changed:
        if tls and not (d.tls_fingerprint or pin):
            raise HTTPException(422, "Укажите независимо сверенный SHA-256 отпечаток API-SSL")
        password = data["password"] if "password" in data else decrypt_secret(d.password_enc)
        candidate = RouterOSCredentials(host=data.get("host", d.host), port=data.get("port", d.port), username=data.get("username", d.username), password=password, use_tls=tls, tls_fingerprint=(d.tls_fingerprint or pin) if tls else None)
        old = _creds(d) if tls and not d.use_tls and candidate.host == d.host else None
        try:
            old_identity = fetch_identity(old) if old else None
            identity = fetch_identity(candidate)
            if not identity or (old and (not old_identity or identity != old_identity)):
                raise ValueError("identity mismatch")
        except Exception as exc:
            raise HTTPException(502, "Подключение не подтверждено; прежние параметры сохранены") from exc
        if pin_added:
            d.tls_fingerprint = pin
            record_management(db,d,_,"tls-edit",f"TCP {d.port} → {candidate.port}; SHA256={pin}")
    if "group_name" in data:
        data["group_name"] = (data["group_name"] or "").strip() or None
    if "password" in data:
        d.password_enc = encrypt_secret(data.pop("password"))
    for k, v in data.items():
        setattr(d, k, v)
    db.commit()
    db.refresh(d)
    return d


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
def delete_device(
    device_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_role("admin")),
) -> Response:
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    db.delete(d)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{device_id}/probe", response_model=DeviceResource)
def probe_device(
    device_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> DeviceResource:
    """Подключиться к устройству, прочитать `/system/resource` и обновить
    метаданные (identity, model, serial, version, status)."""
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")

    try:
        res = fetch_resource(_creds(d))
        identity = fetch_identity(_creds(d))
    except RouterOSError as exc:
        d.status = "down"
        d.last_error = str(exc)
        db.commit()
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc

    d.identity = identity or d.identity
    d.model = res.get("board-name") or d.model
    d.ros_version = res.get("version") or d.ros_version
    d.architecture = res.get("architecture-name") or d.architecture
    if not d.serial:
        try:
            d.serial = fetch_serial(_creds(d)) or d.serial
        except Exception:
            pass  # у CHR нет routerboard, а у учётки может не хватать прав
    prev_status = d.status
    d.status = "up"
    d.last_error = None
    d.last_seen = datetime.now(timezone.utc)

    def _to_int(v):
        try:
            return int(v) if v is not None else None
        except (TypeError, ValueError):
            return None

    cpu = _to_int(res.get("cpu-load"))
    free_mem = _to_int(res.get("free-memory"))
    total_mem = _to_int(res.get("total-memory"))
    uptime_s = parse_uptime(res.get("uptime"))

    # abnormal reboot detection: новый uptime < предыдущего и отличие > 60s
    abnormal = False
    if uptime_s is not None and d.last_uptime_seconds is not None:
        if uptime_s < d.last_uptime_seconds - 60:
            abnormal = True
            d.abnormal_reboot = True
            add_alert(
                db,
                severity="warning",
                category="abnormal_reboot",
                source=f"device:{d.id}",
                title=f"Возможен аварийный перезапуск: {d.identity or d.name}",
                message=(
                    f"Время работы сократилось с {format_duration(d.last_uptime_seconds)} до {format_duration(uptime_s)} "
                    f"без штатной команды reboot."
                ),
            )
    if not abnormal:
        d.abnormal_reboot = False
    d.last_uptime_seconds = uptime_s

    # internet check
    try:
        ok = check_internet(_creds(d))
        d.internet_ok = ok
        if not ok:
            add_alert(
                db,
                severity="warning",
                category="internet",
                source=f"device:{d.id}",
                title=f"Нет интернета на {d.identity or d.name}",
                message="Ping проверочного адреса не прошёл.",
            )
    except Exception:
        d.internet_ok = None

    # уведомление о возврате в строй
    if prev_status == "down" and d.status == "up":
        add_alert(
            db,
            severity="info",
            category="device",
            source=f"device:{d.id}",
            title=f"Устройство снова онлайн: {d.identity or d.name}",
        )

    mem_used_pct = None
    if free_mem is not None and total_mem and total_mem > 0:
        mem_used_pct = round(100 - (free_mem / total_mem) * 100, 1)

    metric = DeviceMetric(
        device_id=d.id,
        cpu_load=float(cpu) if cpu is not None else None,
        mem_used_pct=mem_used_pct,
        free_memory=free_mem,
        total_memory=total_mem,
        uptime_seconds=uptime_s,
        internet_ok=d.internet_ok,
    )
    db.add(metric)
    db.commit()

    return DeviceResource(
        cpu_load=cpu,
        free_memory=free_mem,
        total_memory=total_mem,
        uptime=res.get("uptime"),
        version=res.get("version"),
        board_name=res.get("board-name"),
        architecture_name=res.get("architecture-name"),
    )


@router.post("/{device_id}/reboot", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
def reboot_device(
    device_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin", "operator")),
) -> Response:
    """Отправить команду перезагрузки устройству."""
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    try:
        cmd_reboot(_creds(d))
    except RouterOSError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    add_audit(db, actor=user.email, action="device.reboot", target=f"device:{device_id}")
    add_alert(db, severity="info", category="device", source=f"device:{device_id}",
              title=f"Reboot отправлен: {d.identity or d.name}", message=f"by {user.email}")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{device_id}/safe-mode", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
def toggle_safe_mode(
    device_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin", "operator")),
) -> Response:
    """Переключить safe mode на устройстве."""
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    try:
        cmd_safe_mode(_creds(d))
    except RouterOSError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    add_audit(db, actor=user.email, action="device.safe_mode", target=f"device:{device_id}")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------- Sprint 09: интерфейсы / DHCP / upgrade ----------

@router.get("/{device_id}/interfaces")
def list_interfaces(
    device_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
    diagnostics: bool = False,
) -> list[dict]:
    """Список интерфейсов устройства со счётчиками rx/tx и running."""
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    try:
        return fetch_interface_stats(_creds(d), diagnostics=True) if diagnostics else fetch_interface_stats(_creds(d))
    except RouterOSError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc


@router.get("/{device_id}/port-network")
def port_network(device_id: int, port: str, db: Session = Depends(get_db),
                 _: User = Depends(get_current_user)) -> dict:
    """Read-only VLAN, bridge, neighbor and learned MAC details for one port."""
    from ...services.routeros.port_network import fetch_port_network, ip
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(404, "Устройство не найдено")
    if not port or len(port) > 255 or any(ord(c) < 32 for c in port):
        raise HTTPException(422, "Некорректное имя порта")
    if d.use_tls and not getattr(d, "tls_fingerprint", None):
        raise HTTPException(409, "Сначала закрепите TLS-отпечаток")
    try:
        result = fetch_port_network(_creds(d), port)
    except ValueError as exc:
        raise HTTPException(422, "Физический порт не найден или данные недоступны") from exc
    except Exception as exc:
        raise HTTPException(502, "Не удалось получить сетевые данные порта") from exc
    # Link only a unique matching management IP. Identity is not proof of identity.
    by_ip = {}
    for other in db.query(Device).all():
        addr = ip(other.host)
        if addr and other.id != device_id:
            by_ip.setdefault(addr, []).append(other)
    for n in result["neighbors"]:
        matches = by_ip.get(n["ip"], [])
        if len(matches) == 1:
            n["device_id"] = matches[0].id
            n["device_name"] = matches[0].name
    return result


@router.get("/{device_id}/interface-traffic")
def interface_traffic(
    device_id: int,
    names: str | None = None,
    hours: float = 24.0,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> dict:
    """Серии bps по выбранным интерфейсам за окно `hours`.

    `names` — CSV. Если пусто — берётся из `device.monitored_interfaces`.
    Возвращает {"series": {name: [{ts, rx_bps, tx_bps, running}]}}.
    """
    from ...models.interface_stat import InterfaceStat
    from datetime import datetime, timedelta, timezone
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    if not names:
        names = d.monitored_interfaces or ""
    name_list = [x.strip() for x in names.split(",") if x.strip()]
    if not name_list:
        return {"series": {}, "hours": hours}
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = (
        db.query(InterfaceStat)
        .filter(
            InterfaceStat.device_id == device_id,
            InterfaceStat.name.in_(name_list),
            InterfaceStat.ts >= since,
        )
        .order_by(InterfaceStat.name.asc(), InterfaceStat.ts.asc())
        .all()
    )
    by_name: dict[str, list] = {n: [] for n in name_list}
    last: dict[str, tuple] = {}
    for r in rows:
        prev = last.get(r.name)
        rx_bps = tx_bps = None
        if prev is not None:
            dt = (r.ts - prev[0]).total_seconds()
            if dt > 0:
                # счётчики могут сброситься после reboot — игнорируем отрицательные дельты
                drx = r.rx_bytes - prev[1]
                dtx = r.tx_bytes - prev[2]
                if drx >= 0 and dtx >= 0:
                    rx_bps = round(drx * 8 / dt)
                    tx_bps = round(dtx * 8 / dt)
        by_name[r.name].append({
            "ts": r.ts.isoformat(),
            "rx_bps": rx_bps,
            "tx_bps": tx_bps,
            "running": r.running,
        })
        last[r.name] = (r.ts, r.rx_bytes, r.tx_bytes)
    return {"series": by_name, "hours": hours}


@router.get("/{device_id}/uplink-status")
def uplink_status(
    device_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[dict]:
    """Текущий статус выбранных аплинков (running) — по последней записи."""
    from ...models.interface_stat import InterfaceStat
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    name_list = [x.strip() for x in (d.uplink_interfaces or "").split(",") if x.strip()]
    out = []
    for n in name_list:
        last = (
            db.query(InterfaceStat)
            .filter(InterfaceStat.device_id == device_id, InterfaceStat.name == n)
            .order_by(InterfaceStat.ts.desc()).first()
        )
        out.append({
            "name": n,
            "running": bool(last.running) if last else None,
            "ts": last.ts.isoformat() if last else None,
        })
    return out


@router.get("/{device_id}/dhcp-leases")
def dhcp_leases(
    device_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[dict]:
    """Список выданных DHCP-лизов по всем DHCP-серверам устройства."""
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    try:
        return fetch_dhcp_leases(_creds(d))
    except RouterOSError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc


@router.post("/{device_id}/upgrade/internet")
def upgrade_from_internet(
    device_id: int,
    channel: str = "stable",
    install: bool = False,
    expected_version: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin", "operator")),
) -> dict:
    """Запросить у MikroTik проверку обновления и при `install=true` — установить.

    Идёт через штатный `/system/package/update` (репозиторий MikroTik).
    Установка перезагрузит устройство.
    """
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    try:
        info = cmd_upgrade_check(_creds(d), channel=channel)
        if install:
            if expected_version is not None:
                import re
                def release(value):
                    m = re.match(r"^\d+(?:\.\d+){1,2}(?=\s|$)", str(value or "").strip())
                    return m.group(0) if m else ""
                if (channel not in ("stable", "long-term") or info.get("channel") != channel
                        or release(info.get("latest-version")) != expected_version
                        or not release(info.get("installed-version"))
                        or "new version is available" not in str(info.get("status", "")).lower()):
                    raise HTTPException(409, "Канал или целевая версия изменились; установка отменена")
                def numeric(value):
                    parts = tuple(map(int, value.split(".")))
                    return parts + (0,) * (3 - len(parts))
                if numeric(expected_version) <= numeric(release(info.get("installed-version"))):
                    raise HTTPException(409, "Запрещено понижение или повторная установка версии")
            cmd_upgrade_install(_creds(d))
            add_audit(db, actor=user.email, action="device.upgrade.internet",
                      target=f"device:{device_id}", detail=f"channel={channel}")
            add_alert(db, severity="info", category="firmware",
                      source=f"device:{device_id}",
                      title=f"Обновление из интернета запущено: {d.identity or d.name}",
                      message=f"by {user.email}, channel={channel}")
            db.commit()
        return {"ok": True, "info": info, "installed": bool(install)}
    except RouterOSError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc


@router.post("/{device_id}/upgrade/local")
def upgrade_from_local(
    device_id: int,
    firmware_id: int,
    reboot: bool = True,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin", "operator")),
) -> dict:
    """Установить прошивку из локального репозитория контроллера.

    Файл прошивки временно публикуется во встроенный FTP, устройство сам
    скачивает его командой `/tool/fetch`, затем (опц.) перезагружается —
    RouterOS установит .npk при загрузке.
    """
    from ...models.firmware import Firmware
    from ...services.backup_ftp_server import get_server, detect_push_host
    from ...core.config import get_settings as _cfg
    import os
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    fw = db.get(Firmware, firmware_id)
    if not fw:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "firmware not found")
    if not fw.content:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "firmware has no payload")
    srv = get_server()
    if srv is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "backup ftp server not running")
    cfg = _cfg()
    push_host = cfg.backup_push_host or detect_push_host()
    if not push_host:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "BACKUP_PUSH_HOST not configured")
    sess = srv.open_session([fw.name])
    try:
        path = os.path.join(sess.home_dir, fw.name)
        with open(path, "wb") as f:
            f.write(fw.content)
        try:
            push_firmware_via_ftp(
                _creds(d),
                server=push_host, port=int(cfg.backup_ftp_port),
                user=sess.username, password=sess.password,
                src_path=fw.name, dst_filename=fw.name,
            )
        except RouterOSError as exc:
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
        if reboot:
            try:
                cmd_reboot(_creds(d))
            except RouterOSError as exc:
                raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
        add_audit(db, actor=user.email, action="device.upgrade.local",
                  target=f"device:{device_id}", detail=f"firmware={fw.name}")
        add_alert(db, severity="info", category="firmware",
                  source=f"device:{device_id}",
                  title=f"Установлена локальная прошивка: {d.identity or d.name}",
                  message=f"{fw.name} by {user.email}")
        db.commit()
        return {"ok": True, "file": fw.name, "reboot": reboot}
    finally:
        srv.close_session(sess.session_id)

# Device Manager: read-only live state, plus explicit RouterBOOT staging.
@router.get('/{device_id}/maintenance-state')
def maintenance_state(device_id: int, db: Session = Depends(get_db),
                      _: User = Depends(require_role('admin', 'operator'))) -> dict:
    from ...services.routeros.client import routeros_session
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(404, 'device not found')
    try:
        with routeros_session(_creds(d)) as api:
            resources = list(api.path('system', 'resource'))
            if not resources:
                raise ValueError('empty resource response')
            r = resources[0]
            packages = list(api.path('system', 'package'))
            try:
                boards = list(api.path('system', 'routerboard'))
            except Exception:
                boards = []
            b = boards[0] if boards else {}
            return {'version': r.get('version'), 'architecture': r.get('architecture-name'),
                    'free_disk': r.get('free-hdd-space'), 'uptime_seconds': parse_uptime(r.get('uptime')),
                    'packages': [p.get('name') for p in packages if p.get('name')],
                    'routerboard': b.get('routerboard'), 'current_firmware': b.get('current-firmware'),
                    'upgrade_firmware': b.get('upgrade-firmware')}
    except Exception as exc:
        raise HTTPException(502, 'Не удалось прочитать состояние устройства') from exc


@router.post('/{device_id}/maintenance-routerboot')
def maintenance_routerboot(device_id: int, expected: str, db: Session = Depends(get_db),
                           user: User = Depends(require_role('admin', 'operator'))) -> dict:
    from ...services.routeros.client import routeros_session
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(404, 'device not found')
    try:
        with routeros_session(_creds(d)) as api:
            boards = list(api.path('system', 'routerboard'))
            b = boards[0] if boards else {}
            if str(b.get('routerboard')).lower() not in ('true', 'yes') or not b.get('current-firmware') or str(b.get('upgrade-firmware')) != expected:
                raise HTTPException(409, 'RouterBOOT не поддерживается или целевая версия изменилась')
            if str(b.get('current-firmware')) == expected:
                return {'ok': True, 'staged': False}
            tuple(api(cmd='/system/routerboard/upgrade'))
        add_audit(db, actor=user.email, action='device.routerboot.stage', target=f'device:{device_id}', detail=f'version={expected}')
        db.commit()
        return {'ok': True, 'staged': True}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, 'Результат RouterBOOT неизвестен; проверьте устройство вручную') from exc


@router.get('/{device_id}/device-mode')
def audit_device_mode(device_id: int, db: Session = Depends(get_db),
                      user: User = Depends(require_role('admin', 'operator'))):
    from ...services.routeros.device_mode import inspect_mode
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(404, 'device not found')
    try:
        return inspect_mode(_creds(d))
    except Exception as exc:
        raise HTTPException(502, 'Device Mode: не удалось получить данные; проверьте API и Vault') from exc


@router.get('/{device_id}/security-audit')
def audit_device_security(device_id: int, db: Session = Depends(get_db),
                          user: User = Depends(require_role('admin', 'operator'))):
    from ...services.routeros.security_audit import inspect_security
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(404, 'device not found')
    try:
        return inspect_security(_creds(d))
    except Exception as exc:
        raise HTTPException(502, 'Не удалось прочитать параметры безопасности; проверьте API и Vault') from exc

# Device Manager v0.8: registered devices only, admin-only trust and policy writes.
from pydantic import BaseModel, Field
from ...services import security_manager as sm

class TrustRequest(BaseModel):
    fingerprint: str = Field(min_length=10,max_length=100)
    replace: bool = False

class SecurityPolicy(BaseModel):
    backup_mode: str = 'auto'
    daily_audit: bool = False

def _security_device(db, device_id):
    d=db.get(Device,device_id)
    if not d: raise HTTPException(404,'device not found')
    return d

@router.get('/{device_id}/ssh-trust')
def get_trust(device_id:int, db:Session=Depends(get_db), user:User=Depends(require_role('admin','operator'))):
    return sm.trust_status(db,_security_device(db,device_id))

@router.post('/{device_id}/ssh-trust/scan')
def scan_trust(device_id:int, db:Session=Depends(get_db), user:User=Depends(require_role('admin','operator'))):
    d=_security_device(db,device_id)
    try:
        from ...services.routeros.client import routeros_session
        from ...services.routeros.management import static_service, truth
        with routeros_session(_creds(d)) as api: ssh_row=static_service(api,'ssh')
        if truth(ssh_row.get('disabled')): raise HTTPException(409,'SSH отключён на MikroTik. Включите службу через API.')
        if int(ssh_row['port']) != 22: raise HTTPException(409,'SSH использует нестандартный порт; SFTP сейчас поддерживает TCP 22.')
        key=sm.scan(d.host)
        status=sm.trust_status(db,d)
        fp=sm.fingerprint(key)
        return {**status,'observed':fp,'algorithm':key.get_name(),'changed':bool(status['fingerprints'] and fp not in status['fingerprints'])}
    except HTTPException: raise
    except Exception as exc: raise HTTPException(502,'SSH: не удалось получить ключ; проверьте TCP 22, Firewall и доступность API') from exc

@router.post('/{device_id}/ssh-trust/confirm')
def confirm_trust(device_id:int, body:TrustRequest, db:Session=Depends(get_db), user:User=Depends(require_role('admin'))):
    d=_security_device(db,device_id)
    try: return sm.save_trust(db,d,body.fingerprint,body.replace,user.email)
    except ValueError as exc: raise HTTPException(409,str(exc)) from exc
    except Exception as exc: raise HTTPException(502,'Не удалось подтвердить ключ SSH') from exc

@router.put('/{device_id}/security-policy')
def set_security_policy(device_id:int, body:SecurityPolicy, db:Session=Depends(get_db), user:User=Depends(require_role('admin'))):
    from datetime import timedelta
    from sqlalchemy import select
    if body.backup_mode not in ('auto','push','pull'): raise HTTPException(422,'Unknown backup mode')
    d=db.execute(select(Device).where(Device.id==device_id).with_for_update()).scalar_one_or_none()
    if not d: raise HTTPException(404,'device not found')
    row=sm.prefs(db,d,True)
    row.backup_mode=body.backup_mode
    if body.daily_audit and not row.daily_audit: row.next_audit=datetime.now(timezone.utc)+timedelta(days=1)
    if not body.daily_audit: row.next_audit=None
    row.daily_audit=int(body.daily_audit)
    db.commit()
    return sm.trust_status(db,d)

@router.post('/{device_id}/security-snapshots')
def collect_security(device_id:int, db:Session=Depends(get_db), user:User=Depends(require_role('admin','operator'))):
    d=_security_device(db,device_id)
    try: return sm.collect(db,d,'manual')
    except Exception as exc: raise HTTPException(502,'Аудит недоступен: проверьте API и Vault') from exc

@router.get('/{device_id}/security-snapshots')
def list_security(device_id:int, db:Session=Depends(get_db), user:User=Depends(require_role('admin','operator'))):
    d=_security_device(db,device_id)
    return [sm.snapshot(r) for r in db.query(sm.SecuritySnapshot).filter_by(device_id=d.id,host=d.host).order_by(sm.SecuritySnapshot.id.desc()).limit(30).all()]

# Device Manager v0.9: deliberately limited writes, admin only.
from typing import Literal
from dataclasses import replace as dc_replace
from ...services.routeros import management as mg
from ...services.routeros.client import routeros_session
from sqlalchemy import select
from ...models.device_management import DeviceManagementEvent

class ManagementEdit(BaseModel):
    name: str = Field(min_length=1,max_length=128)
    kind: Literal['router','switch']
    sync_identity: bool = True

class EnableService(BaseModel):
    service: Literal['ssh','api-ssl']
    source: str = Field(max_length=64)
    certificate: str | None = Field(default=None,max_length=128)

class TLSConfirmation(BaseModel):
    fingerprint: str = Field(pattern=r'^[0-9a-f]{64}$')
    port: int = Field(ge=1,le=65535)

class CategoryBatch(BaseModel):
    ids: list[int] = Field(min_length=1,max_length=200)
    kind: Literal['router','switch']


def management_lock(db, device_id):
    d=db.execute(select(Device).where(Device.id==device_id).with_for_update()).scalar_one_or_none()
    if not d: raise HTTPException(404,'Устройство не найдено')
    return d


def record_management(db,d,user,action,detail):
    db.add(DeviceManagementEvent(device_id=d.id,actor=user.email,action=action,detail=detail))


@router.post('/management/category')
def management_category(body:CategoryBatch, db:Session=Depends(get_db), user:User=Depends(require_role('admin'))):
    ids=sorted(set(body.ids))
    rows=db.execute(select(Device).where(Device.id.in_(ids)).order_by(Device.id).with_for_update()).scalars().all()
    if len(rows)!=len(ids): raise HTTPException(404,'Часть устройств не найдена; ничего не изменено')
    for d in rows:
        if d.kind!=body.kind:
            record_management(db,d,user,'category',f'{d.kind} → {body.kind}')
            d.kind=body.kind
    db.commit()
    return {'count':len(rows)}


@router.post('/{device_id}/management/edit')
def management_edit(device_id:int, body:ManagementEdit,db:Session=Depends(get_db),user:User=Depends(require_role('admin'))):
    d=management_lock(db,device_id)
    name=body.name.strip()
    if not name or any(ord(x)<32 or ord(x)==127 for x in name): raise HTTPException(422,'Недопустимое имя')
    from sqlalchemy import func, or_
    other=db.query(Device.id).filter(Device.id!=d.id,or_(func.lower(Device.name)==name.lower(),func.lower(Device.identity)==name.lower())).first()
    if other: raise HTTPException(409,'Имя уже используется')
    old=d.identity or d.name
    if body.sync_identity and (name!=d.identity or name!=d.name):
        try:
            with routeros_session(_creds(d)) as api: mg.rename_identity(api,name)
        except Exception as exc:
            record_management(db,d,user,'rename-unconfirmed','Identity не подтверждён; проверьте устройство')
            db.commit()
            raise HTTPException(502,'Identity не подтверждён; возможно, имя уже изменилось на MikroTik. Проверьте опросом.') from exc
        d.identity=name
    d.name=name
    old_kind=d.kind
    d.kind=body.kind
    record_management(db,d,user,'edit',f'{old} → {name}; {old_kind} → {d.kind}; identity={body.sync_identity}')
    db.commit()
    return {'name':d.name,'identity':d.identity,'kind':d.kind}


@router.get('/{device_id}/management/services')
def management_services(device_id:int,db:Session=Depends(get_db),user:User=Depends(require_role('admin','operator'))):
    d=_security_device(db,device_id)
    if d.use_tls and not d.tls_fingerprint:
        return {'services':[], 'port':d.port,'tls':True,'fingerprint':None}
    try:
        with routeros_session(_creds(d)) as api:
            rows=[mg.static_service(api,n) for n in ('ssh','api','api-ssl')]
        return {'services':[{k:r.get(k) for k in ('name','port','disabled','address','certificate')} for r in rows], 'port':d.port,'tls':d.use_tls,'fingerprint':d.tls_fingerprint}
    except Exception as exc: raise HTTPException(502,'Не удалось прочитать IP Services через API') from exc


@router.get('/{device_id}/management/certificates')
def management_certificates(device_id:int,db:Session=Depends(get_db),user:User=Depends(require_role('admin','operator'))):
    d=_security_device(db,device_id)
    if d.use_tls and not d.tls_fingerprint: raise HTTPException(409,'Сначала восстановите доверие TLS')
    try:
        with routeros_session(_creds(d)) as api:
            return management_jobs.cert_summary(api)
    except Exception as exc: raise HTTPException(502,'Не удалось получить список серверных сертификатов') from exc


@router.post('/{device_id}/management/enable')
def management_enable(device_id:int,body:EnableService,db:Session=Depends(get_db),user:User=Depends(require_role('admin'))):
    d=management_lock(db,device_id)
    try:
        with routeros_session(_creds(d)) as api:
            if body.service=='api-ssl' and d.use_tls: raise ValueError('ROSzetta уже использует TLS; действующую службу не меняем')
            row=mg.prepare_service(api,body.service,body.source,body.certificate)
    except ValueError as exc:
        record_management(db,d,user,'service-unconfirmed',body.service);db.commit()
        raise HTTPException(409,str(exc)) from exc
    except Exception as exc:
        record_management(db,d,user,'service-unconfirmed',body.service);db.commit()
        raise HTTPException(502,'Изменение службы не подтверждено; проверьте IP Services и Firewall') from exc
    record_management(db,d,user,'enable-service',f'{body.service}; {body.source}')
    db.commit()
    if body.service=='api-ssl': management_jobs.update_cache_best_effort(db,d)
    return {k:row.get(k) for k in ('name','port','disabled','address','certificate')}


@router.post('/{device_id}/management/tls-scan')
def management_tls_scan(device_id:int,db:Session=Depends(get_db),user:User=Depends(require_role('admin'))):
    d=_security_device(db,device_id)
    try:
        if d.use_tls and not d.tls_fingerprint:
            fp,expires=management_jobs.peer_certificate(d.host,d.port)
            return {'port':d.port,'fingerprint':fp,'current_fingerprint':None,'expires':expires,'recovery':True}
        with routeros_session(_creds(d)) as api:
            row=mg.static_service(api,'api-ssl')
            certs=[r for r in api.path('certificate') if r.get('name')==row.get('certificate')]
        if mg.truth(row.get('disabled')): raise ValueError('API-SSL отключён')
        port=int(row['port'])
        fp,expires=management_jobs.peer_certificate(d.host,port)
        if len(certs)!=1 or management_jobs.fingerprint(certs[0])!=fp:
            raise ValueError('Отпечаток TLS не совпадает с сертификатом RouterOS')
        return {'port':port,'fingerprint':fp,'current_fingerprint':d.tls_fingerprint,'expires':expires}
    except ValueError as exc: raise HTTPException(409,str(exc)) from exc
    except Exception as exc: raise HTTPException(502,'Не удалось получить TLS-сертификат; проверьте порт, Firewall и сертификат') from exc


@router.post('/{device_id}/management/tls-switch')
def management_tls_switch(device_id:int,body:TLSConfirmation,db:Session=Depends(get_db),user:User=Depends(require_role('admin'))):
    d=management_lock(db,device_id)
    try:
        if d.use_tls and not d.tls_fingerprint:
            if body.port!=d.port: raise ValueError('Порт восстановления изменился')
            fp,_=management_jobs.peer_certificate(d.host,d.port)
            if fp!=body.fingerprint: raise ValueError('Отпечаток изменился')
            candidate=dc_replace(_creds(d),tls_fingerprint=body.fingerprint)
            with routeros_session(candidate) as api:
                row=mg.static_service(api,'api-ssl')
                certs=[r for r in api.path('certificate') if r.get('name')==row.get('certificate')]
                if mg.truth(row.get('disabled')) or int(row['port'])!=d.port or len(certs)!=1 or management_jobs.fingerprint(certs[0])!=fp:
                    raise ValueError('Сертификат или служба не подтверждены')
                ident=list(api.path('system','identity'))[0]['name']
                if (d.identity and ident!=d.identity) or not list(api.path('system','resource')): raise ValueError('Устройство не подтверждено')
            d.tls_fingerprint=fp
            record_management(db,d,user,'tls-recover',f'port={d.port}; SHA256={fp}')
            db.commit()
            management_jobs.update_cache_best_effort(db,d)
            return {'port':d.port,'tls':True,'fingerprint':fp}
        old=_creds(d)
        with routeros_session(old) as api:
            row=mg.static_service(api,'api-ssl')
            if mg.truth(row.get('disabled')) or int(row['port'])!=body.port: raise ValueError('Порт или состояние API-SSL изменились')
            ident=list(api.path('system','identity'))[0]['name']
        new=dc_replace(old,port=body.port,use_tls=True,tls_fingerprint=body.fingerprint)
        with routeros_session(new) as api:
            if list(api.path('system','identity'))[0]['name']!=ident or not list(api.path('system','resource')):
                raise ValueError('Ответ API-SSL не соответствует устройству')
    except Exception as exc:
        record_management(db,d,user,'tls-failed','Старый транспорт сохранён');db.commit()
        raise HTTPException(502,'Защищённое подключение не подтверждено; старый транспорт сохранён') from exc
    d.port=body.port;d.use_tls=True;d.tls_fingerprint=body.fingerprint
    record_management(db,d,user,'tls-switch',f'port={body.port}; SHA256={body.fingerprint}')
    db.commit()
    # Cache failure must not invalidate the already confirmed connection switch.
    management_jobs.update_cache_best_effort(db,d)
    return {'port':d.port,'tls':True,'fingerprint':d.tls_fingerprint}


@router.get('/{device_id}/management/history')
def management_history(device_id:int,db:Session=Depends(get_db),user:User=Depends(require_role('admin','operator'))):
    _security_device(db,device_id)
    rows=db.query(DeviceManagementEvent).filter_by(device_id=device_id).order_by(DeviceManagementEvent.id.desc()).limit(50).all()
    return [{'id':r.id,'actor':r.actor,'action':r.action,'detail':r.detail,'created_at':r.created_at} for r in rows]


@router.post('/{device_id}/management/sftp-check')
def management_sftp_check(device_id:int,db:Session=Depends(get_db),user:User=Depends(require_role('admin'))):
    import paramiko
    from contextlib import closing
    d=_security_device(db,device_id)
    try:
        keys=sm.backup_options(db,d)['trusted_key']
        keys=[keys] if keys is not None else sm.legacy_keys(d.host)
        if not keys: raise HTTPException(409,'Сначала подтвердите SSH-ключ устройства')
        creds=_creds(d)
        with closing(paramiko.SSHClient()) as ssh:
            for key in keys: ssh.get_host_keys().add(d.host,key.get_name(),key)
            ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
            ssh.connect(d.host,port=22,username=creds.username,password=creds.password,look_for_keys=False,allow_agent=False,timeout=8,auth_timeout=8,banner_timeout=8)
            with closing(ssh.open_sftp()) as sftp:
                sftp.get_channel().settimeout(8)
                sftp.listdir('.')
        return {'ok':True,'detail':'SSH-ключ проверен, авторизация и SFTP работают; файлы не создавались'}
    except HTTPException: raise
    except paramiko.BadHostKeyException as exc: raise HTTPException(409,'SSH-ключ изменился; требуется независимая сверка') from exc
    except paramiko.AuthenticationException as exc: raise HTTPException(502,'SSH: авторизация не прошла; проверьте учётные данные и права') from exc
    except Exception as exc: raise HTTPException(502,'SFTP недоступен; проверьте SSH, доверенный ключ, права и Firewall') from exc


@router.get('/{device_id}/management/account-permissions')
def management_account_permissions(device_id: int, db: Session = Depends(get_db), user: User = Depends(require_role('admin'))):
    """Read the actual controller account and local group, never disclose credentials."""
    d = _security_device(db, device_id)
    try:
        with routeros_session(_creds(d)) as api:
            accounts = [r for r in api.path('user') if r.get('name') == d.username]
            if len(accounts) != 1:
                raise HTTPException(409, 'Локальная учётная запись контроллера не найдена; возможно, используется RADIUS')
            account = accounts[0]
            group = account.get('group')
            groups = [r for r in api.path('user', 'group') if r.get('name') == group]
            if len(groups) != 1 or groups[0].get('policy') is None:
                raise HTTPException(409, 'Не удалось однозначно определить права группы')
            raw = groups[0]['policy']
            policies = sorted({str(p).strip() for p in (raw if isinstance(raw, (list, tuple)) else str(raw).split(',')) if str(p).strip()})
            return {'username': d.username, 'group': group, 'policies': policies,
                    'missing': [p for p in ('ssh', 'ftp', 'read', 'write') if p not in policies],
                    'disabled': mg.truth(account.get('disabled')), 'address': account.get('address') or ''}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, 'Не удалось прочитать права учётной записи через API; проверьте разрешение policy') from exc


# Import the model before init_db and mount the persistent management queue.
from ...services import management_jobs
router.include_router(management_jobs.router)


# Inventory is local metadata: no Vault, RouterOS connection or credential writes.
from ...schemas.device import DeviceInventory
from ...core.device_inventory import normalize_inventory


@router.patch("/{device_id}/inventory", response_model=DeviceOut)
def update_inventory(device_id: int, body: DeviceInventory, db: Session=Depends(get_db), user: User=Depends(require_role("admin", "operator"))):
    d = management_lock(db, device_id)
    changes = normalize_inventory(body.model_dump(exclude_unset=True))
    changed = [k for k,v in changes.items() if getattr(d,k)!=v]
    for k in changed: setattr(d,k,changes[k])
    if changed: record_management(db,d,user,"inventory-edit",", ".join(changed))
    db.commit()
    db.refresh(d)
    return d


class InventoryLocationBatch(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=500)
    location: str | None = Field(max_length=256)


@router.post("/inventory/location")
def bulk_inventory_location(body: InventoryLocationBatch, db: Session=Depends(get_db), user: User=Depends(require_role("admin", "operator"))):
    ids = sorted(set(body.ids))
    rows = db.execute(select(Device).where(Device.id.in_(ids)).order_by(Device.id).with_for_update()).scalars().all()
    if len(rows)!=len(ids): raise HTTPException(404,"Часть устройств не найдена; ничего не изменено")
    location = normalize_inventory({"location":body.location})["location"]
    for d in rows:
        if d.location!=location:
            d.location=location
            record_management(db,d,user,"inventory-edit","location (bulk)")
    db.commit()
    return {"count":len(rows)}
