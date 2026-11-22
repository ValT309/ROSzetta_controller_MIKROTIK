from __future__ import annotations

import hashlib
import os.path
import re

import httpx
from pydantic import BaseModel
from fastapi import APIRouter, Depends, File, Form, HTTPException, Response, UploadFile, status
from sqlalchemy.orm import Session

from ...core.db import get_db
from ...models.firmware import Firmware
from ...models.user import User
from ...schemas.firmware import (
    FirmwareBulkImportIn,
    FirmwareBulkOut,
    FirmwareBulkResult,
    FirmwareImportIn,
    FirmwareOut,
    FirmwareUpdateIn,
)
from ...services.firmware_check import CHANNELS, check_and_alert, get_state
from ..deps import get_current_user, require_role

router = APIRouter()

MAX_FIRMWARE_SIZE = 200 * 1024 * 1024  # 200 MiB лимит

# Известные архитектуры RouterOS v7 для bulk-импорта.
KNOWN_ARCHITECTURES = [
    "arm64", "arm", "mipsbe", "mmips", "mipsle", "smips",
    "tile", "ppc", "x86", "x86_64",
]


@router.get("", response_model=list[FirmwareOut])
def list_firmware(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[Firmware]:
    return db.query(Firmware).order_by(Firmware.created_at.desc()).all()


@router.post("/check")
def manual_check(
    db: Session = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
) -> dict:
    """Ручная проверка наличия новых версий RouterOS по всем каналам."""
    state = check_and_alert(db)
    if not state:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "upstream check failed")
    # Для совместимости со старым UI возвращаем top-level stable.
    stable = state.get("stable") or {}
    return {
        "latest_version": stable.get("version", ""),
        "released_at": stable.get("released_at", ""),
        "channels": state,
    }


@router.get("/channels")
def list_channels(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> dict:
    """Текущее состояние по каждому каналу + список известных архитектур."""
    return {
        "channels": get_state(db),
        "available_channels": list(CHANNELS.keys()),
        "architectures": KNOWN_ARCHITECTURES,
    }


@router.post("/import", response_model=FirmwareOut, status_code=status.HTTP_201_CREATED)
def import_firmware(
    payload: FirmwareImportIn,
    db: Session = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
) -> Firmware:
    """Скачать прошивку с указанного URL и сохранить во внутреннем репозитории.

    Если прошивка с таким же `source_url` или (`version`+`architecture`) уже
    есть — повторно не скачивается, возвращается существующая запись (HTTP 200
    с тем же телом, как и для свежесозданной).
    """
    url = str(payload.url)

    # 1) Дедуп по URL источника.
    existing = db.query(Firmware).filter(Firmware.source_url == url).first()
    if existing:
        return existing

    # One RouterOS release can contain several distinct packages per architecture.
    # Do not deduplicate package records on version+architecture alone.
    if payload.version and payload.architecture:
        existing = db.query(Firmware).filter(
            Firmware.version == payload.version,
            Firmware.architecture == payload.architecture,
            Firmware.name == (payload.name or os.path.basename(url.split("?")[0])),
        ).first()
        if existing:
            return existing

    try:
        with httpx.stream("GET", url, follow_redirects=True, timeout=120.0) as resp:
            resp.raise_for_status()
            chunks: list[bytes] = []
            total = 0
            for chunk in resp.iter_bytes(chunk_size=64 * 1024):
                total += len(chunk)
                if total > MAX_FIRMWARE_SIZE:
                    raise HTTPException(
                        status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        f"firmware exceeds {MAX_FIRMWARE_SIZE} bytes",
                    )
                chunks.append(chunk)
            data = b"".join(chunks)
    except httpx.HTTPError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"download failed: {exc}") from exc

    name = payload.name or os.path.basename(url.split("?")[0]) or "firmware.bin"
    sha = hashlib.sha256(data).hexdigest()

    # 3) Дедуп по sha256 (на случай разных URL с тем же содержимым).
    existing = db.query(Firmware).filter(Firmware.sha256 == sha).first()
    if existing:
        return existing

    rec = Firmware(
        name=name,
        version=payload.version,
        architecture=payload.architecture,
        channel=payload.channel,
        size=len(data),
        sha256=sha,
        source_url=url,
        content=data,
    )
    db.add(rec)
    db.commit()
    db.refresh(rec)
    return rec


def _download_firmware_url(url: str) -> bytes:
    with httpx.stream("GET", url, follow_redirects=True, timeout=180.0) as resp:
        resp.raise_for_status()
        chunks: list[bytes] = []
        total = 0
        for chunk in resp.iter_bytes(chunk_size=64 * 1024):
            total += len(chunk)
            if total > MAX_FIRMWARE_SIZE:
                raise HTTPException(
                    status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    f"firmware exceeds {MAX_FIRMWARE_SIZE} bytes",
                )
            chunks.append(chunk)
        return b"".join(chunks)


@router.post("/import-bulk", response_model=FirmwareBulkOut)
def import_bulk(
    payload: FirmwareBulkImportIn,
    db: Session = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
) -> FirmwareBulkOut:
    """Загрузить .npk для указанной версии по списку архитектур одним вызовом."""
    results: list[FirmwareBulkResult] = []
    base = "https://download.mikrotik.com/routeros"
    for arch in payload.architectures:
        url = f"{base}/{payload.version}/routeros-{payload.version}-{arch}.npk"
        # Дедуп по URL или (version+architecture+имя пакета).
        existing = (
            db.query(Firmware)
            .filter(
                (Firmware.source_url == url)
                | ((Firmware.version == payload.version) & (Firmware.architecture == arch) & (Firmware.name == os.path.basename(url)))
            )
            .first()
        )
        if existing:
            results.append(FirmwareBulkResult(
                architecture=arch, ok=True, firmware_id=existing.id, skipped=True,
            ))
            continue
        try:
            data = _download_firmware_url(url)
            sha = hashlib.sha256(data).hexdigest()
            # Дедуп по содержимому.
            existing = db.query(Firmware).filter(Firmware.sha256 == sha).first()
            if existing:
                results.append(FirmwareBulkResult(
                    architecture=arch, ok=True, firmware_id=existing.id, skipped=True,
                ))
                continue
            rec = Firmware(
                name=os.path.basename(url),
                version=payload.version,
                architecture=arch,
                channel=payload.channel,
                size=len(data),
                sha256=sha,
                source_url=url,
                content=data,
            )
            db.add(rec)
            db.commit()
            db.refresh(rec)
            results.append(FirmwareBulkResult(architecture=arch, ok=True, firmware_id=rec.id))
        except HTTPException as exc:
            results.append(FirmwareBulkResult(architecture=arch, ok=False, error=str(exc.detail)))
        except httpx.HTTPError as exc:
            results.append(FirmwareBulkResult(architecture=arch, ok=False, error=str(exc)))
    return FirmwareBulkOut(version=payload.version, channel=payload.channel, results=results)


# Typical names: routeros-7.20.1-arm64.npk, wifi-qcom-7.20.1-arm64.npk.
_FW_NAME_RE = re.compile(
    r"^(?P<package>[a-z][a-z0-9-]*)-(?P<version>7\.\d{1,3}(?:\.\d{1,3})?)-(?P<arch>[a-z0-9_]+)\.npk$",
    re.IGNORECASE,
)


def _guess_meta(filename: str) -> tuple[str | None, str | None]:
    m = _FW_NAME_RE.fullmatch(filename.strip().lower())
    if not m:
        return None, None
    return m.group("version"), m.group("arch")


@router.get("/packages")
def list_packages(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[dict]:
    """Index NPK packages available locally; do not imply that installation is supported."""
    result = []
    for item in db.query(Firmware).order_by(Firmware.created_at.desc()).all():
        m = _FW_NAME_RE.fullmatch(item.name.lower())
        if m and item.content and item.sha256 and item.size == len(item.content):
            result.append({
                "id": item.id, "package": m.group("package"),
                "version": m.group("version"), "architecture": m.group("arch"),
                "channel": item.channel, "size": item.size,
            })
    return result


class OfficialMissingPackageIn(BaseModel):
    package: str
    version: str
    architecture: str
    channel: str


@router.post("/import-official-missing")
def import_official_missing(
    payload: OfficialMissingPackageIn,
    db: Session = Depends(get_db),
    _: User = Depends(require_role("admin")),
) -> dict:
    """Fetch a pinned official extra NPK to ROSzetta database ONLY.

    No RouterOS API, FTP/SFTP or reboot requests are issued here.
    """
    from ...services.firmware_official import (
        OfficialPackageError, package_spec, fetch_official_package,
    )
    if payload.channel != "long-term":
        raise HTTPException(422, "Недопустимый канал RouterOS")
    try:
        name, url, expected = package_spec(payload.package, payload.version, payload.architecture)
    except OfficialPackageError as ex:
        raise HTTPException(422, str(ex)) from ex

    existing = db.query(Firmware).filter(Firmware.name == name).all()
    if existing:
        if len(existing) != 1:
            raise HTTPException(409, "В репозитории есть конфликтующие записи пакета")
        record = existing[0]
        if (record.version != payload.version or record.architecture != payload.architecture
                or record.channel not in (None, "", payload.channel)
                or record.sha256 is None or record.sha256.lower() != expected
                or record.size != len(record.content)
                or hashlib.sha256(record.content).hexdigest() != expected):
            raise HTTPException(409, "Уже есть пакет с таким именем, но другая версия/канал/SHA256")
        return {"id": record.id, "name": name, "sha256": expected, "skipped": True}

    try:
        downloaded_name, downloaded_url, sha, body = fetch_official_package(
            payload.package, payload.version, payload.architecture)
    except OfficialPackageError as ex:
        raise HTTPException(502, str(ex)) from ex
    # Database constraint can vary across deployments; never overwrite conflicting bytes.
    duplicate = db.query(Firmware).filter(Firmware.sha256 == sha).first()
    if duplicate:
        if (duplicate.name != name or duplicate.version != payload.version
                or duplicate.architecture != payload.architecture
                or duplicate.channel not in (None, "", payload.channel)
                or duplicate.size != len(duplicate.content)
                or hashlib.sha256(duplicate.content).hexdigest() != expected):
            raise HTTPException(409, "Контрольная сумма уже занята другим пакетом")
        return {"id": duplicate.id, "name": name, "sha256": sha, "skipped": True}
    record = Firmware(name=downloaded_name, version=payload.version,
                      architecture=payload.architecture, channel=payload.channel,
                      size=len(body), sha256=sha, source_url=downloaded_url, content=body)
    db.add(record)
    try:
        db.commit()
        db.refresh(record)
    except Exception:
        db.rollback()
        raise HTTPException(409, "Пакет был добавлен параллельно или БД отклонила запись") from None
    return {"id": record.id, "name": name, "sha256": sha, "skipped": False}


@router.post("/upload", response_model=FirmwareOut, status_code=status.HTTP_201_CREATED)
async def upload_firmware(
    file: UploadFile = File(..., description=".npk файл прошивки RouterOS"),
    name: str | None = Form(None),
    version: str | None = Form(None),
    architecture: str | None = Form(None),
    channel: str | None = Form(None),
    db: Session = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
) -> Firmware:
    """Загрузка прошивки вручную с диска пользователя (multipart/form-data).

    Если `version`/`architecture` не указаны — попытка распарсить из имени файла
    (формат `routeros-<version>-<arch>.npk`). Дедуп по sha256 / (version+architecture).
    """
    fname = (name or file.filename or "firmware.bin").strip()
    if not fname.lower().endswith(".npk"):
        # Не блокируем строго, но предупреждаем — RouterOS принимает только .npk.
        # Разрешаем — пусть админ сам решает.
        pass

    # Читаем тело с лимитом
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_FIRMWARE_SIZE:
            raise HTTPException(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                f"firmware exceeds {MAX_FIRMWARE_SIZE} bytes",
            )
        chunks.append(chunk)
    data = b"".join(chunks)
    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "empty file")

    # Автоопределение метаданных из имени файла
    if not version or not architecture:
        guessed_ver, guessed_arch = _guess_meta(fname)
        version = version or guessed_ver
        architecture = architecture or guessed_arch

    sha = hashlib.sha256(data).hexdigest()

    # Дедуп: по sha256 → возвращаем существующую запись
    existing = db.query(Firmware).filter(Firmware.sha256 == sha).first()
    if existing:
        return existing
    # Дедуп по (version, architecture, package filename)
    if version and architecture:
        existing = (
            db.query(Firmware)
            .filter(
                Firmware.version == version,
                Firmware.architecture == architecture,
                Firmware.name == fname,
            )
            .first()
        )
        if existing:
            return existing

    rec = Firmware(
        name=fname,
        version=version,
        architecture=architecture,
        channel=channel,
        size=len(data),
        sha256=sha,
        source_url=None,
        content=data,
    )
    db.add(rec)
    db.commit()
    db.refresh(rec)
    return rec


@router.patch("/{firmware_id}", response_model=FirmwareOut)
def update_firmware(
    firmware_id: int,
    payload: FirmwareUpdateIn,
    db: Session = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
) -> Firmware:
    rec = db.get(Firmware, firmware_id)
    if not rec:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "firmware not found")
    for k, v in payload.model_dump(exclude_unset=True).items():
        setattr(rec, k, v)
    db.commit()
    db.refresh(rec)
    return rec


@router.get("/{firmware_id}/download")
def download_firmware(
    firmware_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> Response:
    rec = db.get(Firmware, firmware_id)
    if not rec:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "firmware not found")
    return Response(
        content=rec.content,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{rec.name}"'},
    )


@router.delete("/{firmware_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
def delete_firmware(
    firmware_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_role("admin")),
) -> Response:
    rec = db.get(Firmware, firmware_id)
    if not rec:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "firmware not found")
    db.delete(rec)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
