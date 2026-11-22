"""Safe, one-shot RouterOS 7 updates for the durable device-manager queue.

No passwords in job JSON; no automatic retry once install may have been sent.
Only the official device-side package updater is supported here.
"""
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
import re
import time
import hashlib
import os
import hashlib
import os
import hashlib
import os
import hashlib
import os


class FirmwareBlocked(RuntimeError):
    """A safe, user-facing reason, without raw device/API exceptions."""


class FirmwareUnconfirmed(FirmwareBlocked):
    """A command may have been sent; manual reconciliation is required."""


def release(value):
    m = re.fullmatch(r'(7\.\d{1,3}(?:\.\d{1,3})?)(?:\s+\([^)]*\))?', str(value or '').strip())
    return m.group(1) if m else None


def numeric(value):
    v = release(value)
    if v is None:
        raise FirmwareBlocked('Не подтверждена стабильная версия RouterOS 7')
    return tuple((list(map(int, v.split('.'))) + [0, 0])[:3])


def valid_target(value):
    return isinstance(value, str) and release(value) == value and all(str(int(x)) == x for x in value.split('.'))


def uptime_seconds(value):
    s = str(value or '').strip()
    if re.fullmatch(r'(?:\d+[wdhms])+', s):
        units = dict(w=604800, d=86400, h=3600, m=60, s=1)
        return sum(int(v) * units[u] for v, u in re.findall(r'(\d+)([wdhms])', s))
    if re.fullmatch(r'\d+:\d{2}:\d{2}', s):
        h, m, sec = map(int, s.split(':'))
        if m < 60 and sec < 60:
            return h * 3600 + m * 60 + sec
    return None


def timing(scheduled, now, minutes):
    if scheduled is None or scheduled.tzinfo is None or scheduled <= now:
        raise FirmwareBlocked('Укажите будущую дату и время с часовым поясом')
    return scheduled.astimezone(timezone.utc), scheduled.astimezone(timezone.utc) + timedelta(minutes=minutes)


def approved(entry, now):
    if entry.get('firmware_confirmed') is not True or not valid_target(entry.get('expected_version')):
        raise FirmwareBlocked('Нет явного подтверждения целевой версии; создайте новое задание')
    try:
        deadline = datetime.fromisoformat(entry['deadline'])
        start = datetime.fromisoformat(entry['scheduled_at'])
        if deadline.tzinfo is None or start.tzinfo is None or deadline <= start:
            raise ValueError()
    except (KeyError, ValueError, TypeError):
        raise FirmwareBlocked('Не задано окно обслуживания') from None
    if now < start or now >= deadline:
        raise FirmwareBlocked('Окно обслуживания закрыто; требуется новое задание')


def endpoint(d):
    # Only non-secret metadata; no credentials copied to the queue.
    return dict(host=d.host, port=d.port, use_tls=bool(d.use_tls),
                tls_fingerprint=d.tls_fingerprint or None, identity=d.identity or None,
                serial=d.serial or None)


def verify_endpoint(d, entry):
    if d is None or endpoint(d) != entry.get('endpoint'):
        raise FirmwareBlocked('Устройство или его параметры изменились; проверьте и создайте новое задание')
    if d.use_tls and not re.fullmatch(r'[0-9a-fA-F]{64}', d.tls_fingerprint or ''):
        raise FirmwareBlocked('TLS без закреплённого отпечатка')
    if not d.identity and not d.serial:
        raise FirmwareBlocked('Не подтверждена идентификация устройства; выполните опрос')


@dataclass(frozen=True)
class Snapshot:
    version: str
    uptime: int
    identity: str
    serial: str | None
    architecture: str
    free_disk: int
    packages: frozenset[str]


def snapshot(api, expected):
    resources = list(api.path('system', 'resource'))
    identities = list(api.path('system', 'identity'))
    if len(resources) != 1 or len(identities) != 1:
        raise FirmwareBlocked('Не получено состояние или имя устройства')
    r = resources[0]
    name = str(identities[0].get('name') or '')
    try:
        boards = list(api.path('system', 'routerboard'))
        serial = (str(boards[0].get('serial-number') or '') or None) if boards else None
    except Exception:
        serial = None
    if not name or (expected.get('identity') and name != expected['identity']) or (expected.get('serial') and serial != expected['serial']):
        raise FirmwareBlocked('Identity или серийный номер не совпадает')
    v, up = release(r.get('version')), uptime_seconds(r.get('uptime'))
    arch = str(r.get('architecture-name') or '')
    try:
        disk = int(r.get('free-hdd-space'))
    except (ValueError, TypeError):
        disk = -1
    packages = list(api.path('system', 'package'))
    if any(str(p.get('scheduled') or '').strip().lower() not in ('', 'no', 'false', 'none') for p in packages):
        raise FirmwareBlocked('Есть ожидающие изменения пакетов; требуется ручная проверка')
    enabled = frozenset(str(p.get('name')) for p in packages if p.get('name') and str(p.get('disabled') or 'false').lower() not in ('yes','true','1'))
    if v is None or up is None or not arch or not enabled or 'routeros' not in enabled:
        raise FirmwareBlocked('Не подтверждены RouterOS 7, uptime, архитектура или основной пакет')
    if any(release(p.get('version')) != v for p in packages if p.get('name') in enabled):
        raise FirmwareBlocked('Версии активных пакетов не совпадают с RouterOS; требуется ручная проверка')
    return Snapshot(v, up, name, serial, arch, disk, enabled)


# Only repository files with a canonical RouterOS v7 NPK name may be installed.
NPK_NAME = re.compile(r'(?P<package>[a-z][a-z0-9-]*)-(?P<version>7\.\d{1,3}(?:\.\d{1,3})?)-(?P<architecture>[a-z0-9_]+)\.npk')


def local_manifest(records, before, target, channel):
    """Select a complete, unambiguous installed-package set; no network writes."""
    matches = {}
    for obj in records:
        name = str(obj.name or '').lower()
        m = NPK_NAME.fullmatch(name)
        if not m or m['version'] != target or m['architecture'] != before.architecture:
            continue
        if obj.channel not in (None, '', channel):
            continue
        if m['package'] not in before.packages:
            continue
        if m['package'] in matches:
            raise FirmwareBlocked('В репозитории несколько файлов одного пакета; удалите дубли: ' + m['package'])
        if not isinstance(obj.content, bytes) or not obj.content or obj.size != len(obj.content) or not obj.sha256 or hashlib.sha256(obj.content).hexdigest() != obj.sha256.lower():
            raise FirmwareBlocked('Размер или SHA256 локального пакета не подтверждены: ' + name)
        matches[m['package']] = obj
    missing = sorted(before.packages - matches.keys())
    if missing:
        raise FirmwareBlocked('В локальном репозитории отсутствуют пакеты ' + ', '.join(missing) + f' для {target}/{before.architecture}')
    total = sum(obj.size for obj in matches.values())
    if before.free_disk < total + 4 * 1024 * 1024:
        raise FirmwareBlocked(f'Недостаточно свободного места для {len(matches)} NPK (нужно не меньше {total + 4 * 1024 * 1024} байт)')
    return [matches[name] for name in sorted(matches)]


# Only repository files with a canonical RouterOS v7 NPK name may be installed.
NPK_NAME = re.compile(r'(?P<package>[a-z][a-z0-9-]*)-(?P<version>7\.\d{1,3}(?:\.\d{1,3})?)-(?P<architecture>[a-z0-9_]+)\.npk')


def local_manifest(records, before, target, channel):
    """Select a complete, unambiguous installed-package set; no network writes."""
    matches = {}
    for obj in records:
        name = str(obj.name or '').lower()
        m = NPK_NAME.fullmatch(name)
        if not m or m['version'] != target or m['architecture'] != before.architecture:
            continue
        if obj.channel not in (None, '', channel):
            continue
        if m['package'] not in before.packages:
            continue
        if m['package'] in matches:
            raise FirmwareBlocked('В репозитории несколько файлов одного пакета; удалите дубли: ' + m['package'])
        if not isinstance(obj.content, bytes) or not obj.content or obj.size != len(obj.content) or not obj.sha256 or hashlib.sha256(obj.content).hexdigest() != obj.sha256.lower():
            raise FirmwareBlocked('Размер или SHA256 локального пакета не подтверждены: ' + name)
        matches[m['package']] = obj
    missing = sorted(before.packages - matches.keys())
    if missing:
        raise FirmwareBlocked('В локальном репозитории отсутствуют пакеты ' + ', '.join(missing) + f' для {target}/{before.architecture}')
    total = sum(obj.size for obj in matches.values())
    if before.free_disk < total + 4 * 1024 * 1024:
        raise FirmwareBlocked(f'Недостаточно свободного места для {len(matches)} NPK (нужно не меньше {total + 4 * 1024 * 1024} байт)')
    return [matches[name] for name in sorted(matches)]


# Only repository files with a canonical RouterOS v7 NPK name may be installed.
NPK_NAME = re.compile(r'(?P<package>[a-z][a-z0-9-]*)-(?P<version>7\.\d{1,3}(?:\.\d{1,3})?)-(?P<architecture>[a-z0-9_]+)\.npk')


def local_manifest(records, before, target, channel):
    """Select a complete, unambiguous installed-package set; no network writes."""
    matches = {}
    for obj in records:
        name = str(obj.name or '').lower()
        m = NPK_NAME.fullmatch(name)
        if not m or m['version'] != target or m['architecture'] != before.architecture:
            continue
        if obj.channel not in (None, '', channel):
            continue
        if m['package'] not in before.packages:
            continue
        if m['package'] in matches:
            raise FirmwareBlocked('В репозитории несколько файлов одного пакета; удалите дубли: ' + m['package'])
        if not isinstance(obj.content, bytes) or not obj.content or obj.size != len(obj.content) or not obj.sha256 or hashlib.sha256(obj.content).hexdigest() != obj.sha256.lower():
            raise FirmwareBlocked('Размер или SHA256 локального пакета не подтверждены: ' + name)
        matches[m['package']] = obj
    missing = sorted(before.packages - matches.keys())
    if missing:
        raise FirmwareBlocked('В локальном репозитории отсутствуют пакеты ' + ', '.join(missing) + f' для {target}/{before.architecture}')
    total = sum(obj.size for obj in matches.values())
    if before.free_disk < total + 4 * 1024 * 1024:
        raise FirmwareBlocked(f'Недостаточно свободного места для {len(matches)} NPK (нужно не меньше {total + 4 * 1024 * 1024} байт)')
    return [matches[name] for name in sorted(matches)]


# Only repository files with a canonical RouterOS v7 NPK name may be installed.
NPK_NAME = re.compile(r'(?P<package>[a-z][a-z0-9-]*)-(?P<version>7\.\d{1,3}(?:\.\d{1,3})?)-(?P<architecture>[a-z0-9_]+)\.npk')


def local_manifest(records, before, target, channel):
    """Select a complete, unambiguous installed-package set; no network writes."""
    matches = {}
    for obj in records:
        name = str(obj.name or '').lower()
        m = NPK_NAME.fullmatch(name)
        if not m or m['version'] != target or m['architecture'] != before.architecture:
            continue
        if obj.channel not in (None, '', channel):
            continue
        if m['package'] not in before.packages:
            continue
        if m['package'] in matches:
            raise FirmwareBlocked('В репозитории несколько файлов одного пакета; удалите дубли: ' + m['package'])
        if not isinstance(obj.content, bytes) or not obj.content or obj.size != len(obj.content) or not obj.sha256 or hashlib.sha256(obj.content).hexdigest() != obj.sha256.lower():
            raise FirmwareBlocked('Размер или SHA256 локального пакета не подтверждены: ' + name)
        matches[m['package']] = obj
    missing = sorted(before.packages - matches.keys())
    if missing:
        raise FirmwareBlocked('В локальном репозитории отсутствуют пакеты ' + ', '.join(missing) + f' для {target}/{before.architecture}')
    total = sum(obj.size for obj in matches.values())
    if before.free_disk < total + 4 * 1024 * 1024:
        raise FirmwareBlocked(f'Недостаточно свободного места для {len(matches)} NPK (нужно не меньше {total + 4 * 1024 * 1024} байт)')
    return [matches[name] for name in sorted(matches)]


def same_device(a, b):
    return (a.identity, a.serial, a.architecture) == (b.identity, b.serial, b.architecture)


def preflight(info, before, channel, target):
    if info.get('channel') != channel or release(info.get('installed-version')) != before.version:
        raise FirmwareBlocked('Канал или установленная версия не подтверждены')
    if numeric(target) <= numeric(before.version):
        raise FirmwareBlocked('Понижение или повторная установка запрещены')
    if release(info.get('latest-version')) != target:
        raise FirmwareBlocked('Доступная версия отличается от согласованной; создайте новое задание')
    if 'new version is available' not in str(info.get('status') or '').lower():
        raise FirmwareBlocked('RouterOS не подтвердил наличие обновления')
    if before.free_disk < 1024 * 1024:
        raise FirmwareBlocked('Меньше 1 МиБ подтверждённого свободного места; проверьте устройство')


def fresh_pair(backups, old_ids, device_id):
    fresh = [b for b in backups if b.id not in old_ids and b.device_id == device_id and b.size > 0 and b.content and len(b.content) == b.size]
    for b in fresh:
        if b.fmt != 'binary' or not b.filename.endswith('.backup'):
            continue
        for t in fresh:
            if t.fmt == 'text' and t.filename == b.filename[:-7] + '.rsc':
                return [b.id, t.id]
    raise FirmwareBlocked('Новая полная пара .backup/.rsc не подтверждена; установка не начата')


def confirmed_boot(before, after, target, elapsed):
    return (same_device(before, after) and after.version == target
            and before.version != target and after.uptime <= elapsed + 30
            and before.packages <= after.packages)


def wait_for_boot(read, before, target, *, started, clock=time.monotonic, sleep=time.sleep, timeout=720):
    # Never issue another write on timeout or dropped API response.
    deadline = started + timeout
    while clock() < deadline:
        sleep(min(10, max(0, deadline - clock())))
        if clock() >= deadline:
            break
        try:
            after = read()
        except Exception:
            continue
        if confirmed_boot(before, after, target, clock() - started):
            return after
    raise FirmwareUnconfirmed('Команда установки могла быть отправлена; новая версия, пакеты или возврат связи не подтверждены. Проверьте устройство вручную')


def run_update(*, entry, channel, connect, guard, backup, publish, validate, local_prepare=None, local_upload=None, clock=time.monotonic, sleep=time.sleep):
    """Callbacks keep DB and network adapters separate for deterministic tests."""
    target = entry['expected_version']
    source = entry.get('firmware_source', 'internet')
    if source == 'local':
        return run_local_update(entry=entry, channel=channel, connect=connect, guard=guard, backup=backup, publish=publish, validate=validate, local_prepare=local_prepare, local_upload=local_upload, clock=clock, sleep=sleep)
    if source != 'internet':
        raise FirmwareBlocked('Неизвестный источник обновления')
    expected = entry['endpoint']
    def read():
        with connect() as api:
            return snapshot(api, expected)
    def check(api, before):
        mode = guard(api)
        if mode.get('status') != 'ok':
            raise FirmwareBlocked('Device Mode не получен; обновление требует ручной проверки')
        pending = list(api.path('file'))
        if any(str(f.get('name') or '').lower().endswith('.npk') for f in pending):
            raise FirmwareBlocked('На устройстве уже есть NPK; ручная проверка перед обновлением')
        # Fail early with a specific, non-secret diagnostic when RouterOS has no DNS.
        try:
            dns_rows = list(api.path('ip', 'dns'))
        except Exception:
            raise FirmwareBlocked('Не удалось проверить DNS на MikroTik; интернет-обновление отменено') from None
        if len(dns_rows) != 1:
            raise FirmwareBlocked('Не получена конфигурация DNS на MikroTik')
        dns = dns_rows[0]
        if not any(str(dns.get(key) or '').strip() for key in ('servers', 'dynamic-servers', 'use-doh-server')):
            raise FirmwareBlocked('На MikroTik не настроены DNS-серверы. Добавьте DNS вручную или используйте локальный репозиторий после включения локальной установки')
        path = api.path('system','package','update')
        rows = list(path)
        if len(rows) != 1:
            raise FirmwareBlocked('Не получены настройки обновления')
        if rows[0].get('channel') != channel:
            raise FirmwareBlocked('Канал на MikroTik отличается от выбранного; измените канал вручную и создайте новое задание')
        # Do not swallow a check-for-updates failure and use stale metadata.
        try:
            tuple(api(cmd='/system/package/update/check-for-updates'))
        except Exception:
            raise FirmwareBlocked('MikroTik не смог проверить обновления через интернет: проверьте DNS, маршрут, доступ к серверам MikroTik и канал') from None
        rows = list(path)
        if len(rows) != 1:
            raise FirmwareBlocked('Не получен ответ проверки обновлений')
        preflight(rows[0], before, channel, target)
    validate()
    publish('Проверка текущей версии и доступности')
    with connect() as api:
        before = snapshot(api, expected)
        if before.version == target:
            return f'Уже установлена {target}; перезагрузка не нужна'
        check(api, before)
    validate()
    publish(f'Создание резервной копии перед {before.version} → {target}')
    entry['backup_ids'] = backup()
    validate()
    publish('Резервная копия подтверждена; повторная проверка версии')
    with connect() as api:
        current = snapshot(api, expected)
        if not same_device(before, current) or current.version != before.version or current.packages != before.packages:
            raise FirmwareBlocked('Устройство или пакеты изменились после бэкапа; установка отменена')
        check(api, current)
        validate()
        # Persist the write intent before network I/O. If process dies, existing queue recovery marks unknown.
        entry['install_intent'] = True
        try:
            publish(f'Отправка команды установки {target}; остановка только после текущего устройства')
        except FirmwareBlocked:
            entry.pop('install_intent', None)
            raise
        started = clock()
        try:
            tuple(api(cmd='/system/package/update/install'))
        except Exception:
            # A disconnect may mean that installation/reboot has started. Verify, never re-send.
            pass
    publish(f'Ожидание перезагрузки и подтверждения {target}')
    after = wait_for_boot(read, current, target, started=started, clock=clock, sleep=sleep)
    return f'Подтверждено {before.version} → {after.version}; API доступен, пакеты сохранены'


def run_local_update(*, entry, channel, connect, guard, backup, publish, validate,
                     local_prepare, local_upload, clock=time.monotonic, sleep=time.sleep):
    """Local NPK installation, single attempt. Strict checks before file transfer."""
    if local_prepare is None or local_upload is None:
        raise FirmwareBlocked('Локальная установка не настроена')
    target = entry['expected_version']
    expected = entry['endpoint']

    def read():
        with connect() as api:
            return snapshot(api, expected)

    def check(api, snap):
        if guard(api).get('status') != 'ok':
            raise FirmwareBlocked('Device Mode не подтверждён')
        if numeric(target) <= numeric(snap.version):
            raise FirmwareBlocked('Локальное понижение или повторная установка не поддерживаются')
        if any(str(r.get('name') or '').lower().endswith('.npk') for r in api.path('file')):
            raise FirmwareBlocked('На MikroTik уже есть NPK; требуется ручная проверка')
        return local_prepare(snap, target, channel)

    validate()
    publish('Проверка набора NPK, архитектуры и места на MikroTik')
    with connect() as api:
        before = snapshot(api, expected)
        if before.version == target:
            return f'Уже установлена {target}; перезагрузка не нужна'
        check(api, before)
    validate()
    publish(f'Создание резервной копии перед {before.version} → {target}')
    entry['backup_ids'] = backup()
    validate()
    publish('Повторная проверка устройства и полного набора пакетов')
    with connect() as api:
        current = snapshot(api, expected)
        if not same_device(before, current) or current.version != before.version or current.packages != before.packages:
            raise FirmwareBlocked('Устройство или пакеты изменились после бэкапа')
        packages = check(api, current)
    validate()
    # Persist transfer intent before any remote write. On crash, never retry automatically.
    entry['transfer_intent'] = True
    publish('Начата передача локальных NPK; повторная отправка запрещена')
    try:
        local_upload(packages, current)
    except Exception:
        raise FirmwareUnconfirmed('Передача NPK не подтверждена. Проверьте файлы на MikroTik вручную; перезагрузка не отправлялась') from None
    validate()
    # Commit reboot intent before command; dropped connection may mean reboot started.
    entry['install_intent'] = True
    publish('Отправка команды перезагрузки для установки NPK')
    started = clock()
    try:
        with connect() as api:
            tuple(api(cmd='/system/reboot'))
    except Exception:
        pass
    publish(f'Ожидание RouterOS {target} после локального обновления')
    after = wait_for_boot(read, current, target, started=started, clock=clock, sleep=sleep)
    return f'Локальное обновление подтверждено: {before.version} → {after.version}; пакеты сохранены'


def run_local_update(*, entry, channel, connect, guard, backup, publish, validate,
                     local_prepare, local_upload, clock=time.monotonic, sleep=time.sleep):
    """Local NPK installation, single attempt. Strict checks before file transfer."""
    if local_prepare is None or local_upload is None:
        raise FirmwareBlocked('Локальная установка не настроена')
    target = entry['expected_version']
    expected = entry['endpoint']

    def read():
        with connect() as api:
            return snapshot(api, expected)

    def check(api, snap):
        if guard(api).get('status') != 'ok':
            raise FirmwareBlocked('Device Mode не подтверждён')
        if numeric(target) <= numeric(snap.version):
            raise FirmwareBlocked('Локальное понижение или повторная установка не поддерживаются')
        if any(str(r.get('name') or '').lower().endswith('.npk') for r in api.path('file')):
            raise FirmwareBlocked('На MikroTik уже есть NPK; требуется ручная проверка')
        return local_prepare(snap, target, channel)

    validate()
    publish('Проверка набора NPK, архитектуры и места на MikroTik')
    with connect() as api:
        before = snapshot(api, expected)
        if before.version == target:
            return f'Уже установлена {target}; перезагрузка не нужна'
        check(api, before)
    validate()
    publish(f'Создание резервной копии перед {before.version} → {target}')
    entry['backup_ids'] = backup()
    validate()
    publish('Повторная проверка устройства и полного набора пакетов')
    with connect() as api:
        current = snapshot(api, expected)
        if not same_device(before, current) or current.version != before.version or current.packages != before.packages:
            raise FirmwareBlocked('Устройство или пакеты изменились после бэкапа')
        packages = check(api, current)
    validate()
    # Persist transfer intent before any remote write. On crash, never retry automatically.
    entry['transfer_intent'] = True
    publish('Начата передача локальных NPK; повторная отправка запрещена')
    try:
        local_upload(packages, current)
    except Exception:
        raise FirmwareUnconfirmed('Передача NPK не подтверждена. Проверьте файлы на MikroTik вручную; перезагрузка не отправлялась') from None
    validate()
    # Commit reboot intent before command; dropped connection may mean reboot started.
    entry['install_intent'] = True
    publish('Отправка команды перезагрузки для установки NPK')
    started = clock()
    try:
        with connect() as api:
            tuple(api(cmd='/system/reboot'))
    except Exception:
        pass
    publish(f'Ожидание RouterOS {target} после локального обновления')
    after = wait_for_boot(read, current, target, started=started, clock=clock, sleep=sleep)
    return f'Локальное обновление подтверждено: {before.version} → {after.version}; пакеты сохранены'


def run_local_update(*, entry, channel, connect, guard, backup, publish, validate,
                     local_prepare, local_upload, clock=time.monotonic, sleep=time.sleep):
    """Local NPK installation, single attempt. Strict checks before file transfer."""
    if local_prepare is None or local_upload is None:
        raise FirmwareBlocked('Локальная установка не настроена')
    target = entry['expected_version']
    expected = entry['endpoint']

    def read():
        with connect() as api:
            return snapshot(api, expected)

    def check(api, snap):
        if guard(api).get('status') != 'ok':
            raise FirmwareBlocked('Device Mode не подтверждён')
        if numeric(target) <= numeric(snap.version):
            raise FirmwareBlocked('Локальное понижение или повторная установка не поддерживаются')
        if any(str(r.get('name') or '').lower().endswith('.npk') for r in api.path('file')):
            raise FirmwareBlocked('На MikroTik уже есть NPK; требуется ручная проверка')
        return local_prepare(snap, target, channel)

    validate()
    publish('Проверка набора NPK, архитектуры и места на MikroTik')
    with connect() as api:
        before = snapshot(api, expected)
        if before.version == target:
            return f'Уже установлена {target}; перезагрузка не нужна'
        check(api, before)
    validate()
    publish(f'Создание резервной копии перед {before.version} → {target}')
    entry['backup_ids'] = backup()
    validate()
    publish('Повторная проверка устройства и полного набора пакетов')
    with connect() as api:
        current = snapshot(api, expected)
        if not same_device(before, current) or current.version != before.version or current.packages != before.packages:
            raise FirmwareBlocked('Устройство или пакеты изменились после бэкапа')
        packages = check(api, current)
    validate()
    # Persist transfer intent before any remote write. On crash, never retry automatically.
    entry['transfer_intent'] = True
    publish('Начата передача локальных NPK; повторная отправка запрещена')
    try:
        local_upload(packages, current)
    except Exception:
        raise FirmwareUnconfirmed('Передача NPK не подтверждена. Проверьте файлы на MikroTik вручную; перезагрузка не отправлялась') from None
    validate()
    # Commit reboot intent before command; dropped connection may mean reboot started.
    entry['install_intent'] = True
    publish('Отправка команды перезагрузки для установки NPK')
    started = clock()
    try:
        with connect() as api:
            tuple(api(cmd='/system/reboot'))
    except Exception:
        pass
    publish(f'Ожидание RouterOS {target} после локального обновления')
    after = wait_for_boot(read, current, target, started=started, clock=clock, sleep=sleep)
    return f'Локальное обновление подтверждено: {before.version} → {after.version}; пакеты сохранены'


def run_local_update(*, entry, channel, connect, guard, backup, publish, validate,
                     local_prepare, local_upload, clock=time.monotonic, sleep=time.sleep):
    """Local NPK installation, single attempt. Strict checks before file transfer."""
    if local_prepare is None or local_upload is None:
        raise FirmwareBlocked('Локальная установка не настроена')
    target = entry['expected_version']
    expected = entry['endpoint']

    def read():
        with connect() as api:
            return snapshot(api, expected)

    def check(api, snap):
        if guard(api).get('status') != 'ok':
            raise FirmwareBlocked('Device Mode не подтверждён')
        if numeric(target) <= numeric(snap.version):
            raise FirmwareBlocked('Локальное понижение или повторная установка не поддерживаются')
        if any(str(r.get('name') or '').lower().endswith('.npk') for r in api.path('file')):
            raise FirmwareBlocked('На MikroTik уже есть NPK; требуется ручная проверка')
        return local_prepare(snap, target, channel)

    validate()
    publish('Проверка набора NPK, архитектуры и места на MikroTik')
    with connect() as api:
        before = snapshot(api, expected)
        if before.version == target:
            return f'Уже установлена {target}; перезагрузка не нужна'
        check(api, before)
    validate()
    publish(f'Создание резервной копии перед {before.version} → {target}')
    entry['backup_ids'] = backup()
    validate()
    publish('Повторная проверка устройства и полного набора пакетов')
    with connect() as api:
        current = snapshot(api, expected)
        if not same_device(before, current) or current.version != before.version or current.packages != before.packages:
            raise FirmwareBlocked('Устройство или пакеты изменились после бэкапа')
        packages = check(api, current)
    validate()
    # Persist transfer intent before any remote write. On crash, never retry automatically.
    entry['transfer_intent'] = True
    publish('Начата передача локальных NPK; повторная отправка запрещена')
    try:
        local_upload(packages, current)
    except Exception:
        raise FirmwareUnconfirmed('Передача NPK не подтверждена. Проверьте файлы на MikroTik вручную; перезагрузка не отправлялась') from None
    validate()
    # Commit reboot intent before command; dropped connection may mean reboot started.
    entry['install_intent'] = True
    publish('Отправка команды перезагрузки для установки NPK')
    started = clock()
    try:
        with connect() as api:
            tuple(api(cmd='/system/reboot'))
    except Exception:
        pass
    publish(f'Ожидание RouterOS {target} после локального обновления')
    after = wait_for_boot(read, current, target, started=started, clock=clock, sleep=sleep)
    return f'Локальное обновление подтверждено: {before.version} → {after.version}; пакеты сохранены'
