from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from ...core.db import get_db
from ...core.security import decrypt_secret
from ...models.backup import DeviceBackup
from ...models.device import Device
from ...models.user import User
from ...schemas.backup import BackupOut
from ...services.routeros.backup import create_and_download_backup
from ...services.security_manager import backup_options
from ...services.routeros.client import RouterOSCredentials, RouterOSError
from ...services.backup_ftp_server import detect_push_host
from ...core.config import get_settings
from ..deps import get_current_user, require_role

router = APIRouter()

MAX_BACKUPS_PER_DEVICE = 10


def retention_policy(db: Session) -> dict:
    from ...services.settings import get_settings_dict
    cfg=get_settings_dict(db).get('backup_retention',{})
    try:
        pairs=max(1,min(100,int(cfg.get('pairs',10))))
        days=max(0,min(3650,int(cfg.get('days',0))))
    except (TypeError,ValueError,AttributeError):
        pairs,days=10,0
    return {'pairs':pairs,'days':days}


def _creds(d: Device) -> RouterOSCredentials:
    return RouterOSCredentials(
        host=d.host,
        username=d.username,
        password=decrypt_secret(d.password_enc),
        port=d.port,
        use_tls=d.use_tls, tls_fingerprint=getattr(d, "tls_fingerprint", None),
        timeout=15.0,
    )


def _rotate(db: Session, device_id: int) -> None:
    """Удаляет старые записи, если их больше MAX_BACKUPS_PER_DEVICE.
    Считаем по уникальному base_name (.backup и .rsc — одна пара)."""
    rows = (
        db.query(DeviceBackup)
        .filter(DeviceBackup.device_id == device_id)
        .order_by(DeviceBackup.created_at.desc())
        .all()
    )
    from datetime import datetime, timezone, timedelta
    policy=retention_policy(db)
    cutoff=datetime.now(timezone.utc)-timedelta(days=policy['days']) if policy['days'] else None
    seen: set[str] = set()
    keep_ids: set[int] = set()
    for r in rows:
        base = r.filename.rsplit(".", 1)[0]
        stamp=r.created_at
        if stamp is not None and stamp.tzinfo is None: stamp=stamp.replace(tzinfo=timezone.utc)
        if base in seen or (len(seen)<policy['pairs'] and (not seen or cutoff is None or (stamp is not None and stamp>=cutoff))):
            seen.add(base)
            keep_ids.add(r.id)
    for r in rows:
        if r.id not in keep_ids:
            db.delete(r)
    db.commit()


@router.get("/backup-health")
def backup_health(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    from ...services.backup_health import inventory
    return inventory(db)


@router.get("/devices/{device_id}/backups", response_model=list[BackupOut])
def list_backups(
    device_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[DeviceBackup]:
    if not db.get(Device, device_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    return (
        db.query(DeviceBackup)
        .filter(DeviceBackup.device_id == device_id)
        .order_by(DeviceBackup.created_at.desc())
        .all()
    )


@router.post(
    "/devices/{device_id}/backups",
    response_model=list[BackupOut],
    status_code=status.HTTP_201_CREATED,
)
def create_backup(
    device_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
) -> list[DeviceBackup]:
    """Создать бэкап (binary + text), скачать через SFTP, сохранить в БД."""
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")

    from datetime import datetime, timezone
    import re

    # router id = identity устройства (как оно зовётся в RouterOS),
    # fallback: name из БД, потом host. Чистим до [A-Za-z0-9_-].
    raw_id = (d.identity or d.name or d.host or "device").strip()
    safe_id = re.sub(r"[^A-Za-z0-9_-]+", "_", raw_id).strip("_") or "device"
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    base = f"{safe_id}-{ts}"

    cfg = get_settings()
    push_host = cfg.backup_push_host or detect_push_host()
    push_port = cfg.backup_ftp_port

    try:
        files = create_and_download_backup(
            _creds(d), base, push_host=push_host, push_port=push_port, **backup_options(db,d),
        )
    except RouterOSError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc

    rec_bin = DeviceBackup(
        device_id=d.id, filename=files.binary_name, fmt="binary",
        size=len(files.binary_data), content=files.binary_data,
    )
    rec_txt = DeviceBackup(
        device_id=d.id, filename=files.text_name, fmt="text",
        size=len(files.text_data), content=files.text_data,
    )
    db.add(rec_bin)
    db.add(rec_txt)
    db.commit()
    db.refresh(rec_bin)
    db.refresh(rec_txt)

    from ...services.backup_health import safe_inspect
    safe_inspect(db, d.id, rec_txt.id)
    _rotate(db, d.id)

    return (
        db.query(DeviceBackup)
        .filter(DeviceBackup.device_id == device_id)
        .order_by(DeviceBackup.created_at.desc())
        .all()
    )


@router.get("/backups/{backup_id}/download")
def download_backup(
    backup_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> Response:
    rec = db.get(DeviceBackup, backup_id)
    if not rec:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "backup not found")
    media_type = "application/octet-stream" if rec.fmt == "binary" else "text/plain; charset=utf-8"
    return Response(
        content=rec.content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{rec.filename}"'},
    )


@router.delete("/backups/{backup_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
def delete_backup(
    backup_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_role("admin")),
) -> Response:
    rec = db.get(DeviceBackup, backup_id)
    if not rec:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "backup not found")
    db.delete(rec)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def run_auto_backups() -> None:
    """Плановый бэкап всех доступных устройств (вызывается планировщиком).

    Повторяет логику create_backup: те же имена файлов, push-доставка через
    FTP контроллера и ротация. Недоступные устройства пропускаются, ошибка
    одного устройства не останавливает остальные."""
    from datetime import datetime, timezone
    import re

    from loguru import logger

    from ...core.db import SessionLocal
    from ...services.vault import VaultLocked

    cfg = get_settings()
    push_host = cfg.backup_push_host or detect_push_host()
    push_port = cfg.backup_ftp_port

    db = SessionLocal()
    ok = failed = 0
    try:
        devices = db.query(Device).filter(Device.status == "up").order_by(Device.id).all()
        logger.info("auto backup: starting for {} device(s)", len(devices))
        for d in devices:
            try:
                raw_id = (d.identity or d.name or d.host or "device").strip()
                safe_id = re.sub(r"[^A-Za-z0-9_-]+", "_", raw_id).strip("_") or "device"
                ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
                files = create_and_download_backup(
                    _creds(d), f"{safe_id}-{ts}", push_host=push_host, push_port=push_port, **backup_options(db,d),
                )
                db.add(DeviceBackup(
                    device_id=d.id, filename=files.binary_name, fmt="binary",
                    size=len(files.binary_data), content=files.binary_data,
                ))
                rec_txt = DeviceBackup(
                    device_id=d.id, filename=files.text_name, fmt="text",
                    size=len(files.text_data), content=files.text_data,
                )
                db.add(rec_txt)
                db.commit()
                from ...services.backup_health import safe_inspect
                safe_inspect(db, d.id, rec_txt.id)
                _rotate(db, d.id)
                ok += 1
            except VaultLocked:
                db.rollback()
                logger.warning("auto backup: vault is locked, run aborted (unlock it in Settings)")
                return
            except Exception as exc:
                db.rollback()
                failed += 1
                logger.warning("auto backup failed for {} ({}): {}", d.name, d.host, exc)
        logger.info("auto backup: done, ok={} failed={}", ok, failed)
    finally:
        db.close()
