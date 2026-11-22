"""Vendor-pinned package downloads; NO interaction with routers.

Extend TRUSTED_SHA256 only after verifying a checksum on mikrotik.com/download.
No caller-supplied URL, redirects, DNS names or unchecked hashes.
"""
from __future__ import annotations
import hashlib
import re
import httpx

MAX_PACKAGE_BYTES = 200 * 1024 * 1024
PACKAGE_RE = re.compile(r"^[a-z][a-z0-9-]{0,60}$")
VERSION_RE = re.compile(r"^7\.\d{1,3}\.\d{1,3}$")
ARCHES = frozenset(("arm64", "arm", "mipsbe", "mmips", "smips", "ppc", "tile", "x86", "x86_64"))
# Published at https://mikrotik.com/download/routeros?architecture=arm64
# Not a general live release manifest. Only explicitly verified checksums are trusted.
TRUSTED_SHA256: dict[tuple[str, str, str], str] = {
    ("wifi-qcom", "7.24.6", "arm64"):
        "d4b0c6c245ecbb7011d6c21853ff5ce6cc4efe8b642178262ead46db51ecdb22",
}

class OfficialPackageError(ValueError):
    pass


def package_spec(package: str, version: str, architecture: str):
    if not PACKAGE_RE.fullmatch(package) or not VERSION_RE.fullmatch(version) or architecture not in ARCHES:
        raise OfficialPackageError("Недопустимое имя пакета, версия или архитектура")
    expected = TRUSTED_SHA256.get((package, version, architecture))
    if not expected:
        raise OfficialPackageError("Для пакета нет подтверждённой SHA256 на официальном сайте; автоматическая загрузка недоступна")
    filename = f"{package}-{version}-{architecture}.npk"
    url = f"https://download.mikrotik.com/routeros/{version}/{filename}"
    return filename, url, expected


def fetch_official_package(package: str, version: str, architecture: str):
    name, url, expected = package_spec(package, version, architecture)
    result = bytearray()
    digest = hashlib.sha256()
    try:
        # Redirects are not followed, to prevent departing the pinned vendor origin.
        with httpx.stream("GET", url, timeout=httpx.Timeout(100.0, connect=12.0),
                          follow_redirects=False, trust_env=False) as response:
            if response.status_code != 200:
                raise OfficialPackageError(f"Сервер MikroTik вернул HTTP {response.status_code}")
            ctype = response.headers.get("content-type", "").lower()
            if "text/html" in ctype or "application/json" in ctype:
                raise OfficialPackageError("Получен не бинарный пакет MikroTik")
            for chunk in response.iter_bytes(chunk_size=65536):
                if len(result) + len(chunk) > MAX_PACKAGE_BYTES:
                    raise OfficialPackageError("NPK превышает допустимый размер")
                result.extend(chunk)
                digest.update(chunk)
    except (httpx.HTTPError, TimeoutError) as ex:
        raise OfficialPackageError("Не удалось скачать пакет с официального сервера MikroTik") from ex
    if not result or digest.hexdigest() != expected:
        raise OfficialPackageError("SHA256 не совпадает с опубликованной MikroTik; файл не сохранён")
    return name, url, expected, bytes(result)
