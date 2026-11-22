"""Strict SFTP NPK upload with known-host verification; no configuration edits."""
from contextlib import closing
import hashlib
import os
from pathlib import Path
import paramiko
from .backup_pull import KNOWN_HOSTS
from ..firmware_scheduler import FirmwareBlocked, FirmwareUnconfirmed


def local_enabled():
    return os.environ.get('ROSZETTA_ENABLE_LOCAL_FIRMWARE') == '1' and Path(os.environ.get('ROSZETTA_SFTP_KNOWN_HOSTS', KNOWN_HOSTS)).is_file()


def upload_packages(creds, packages, before):
    if not local_enabled():
        raise FirmwareBlocked('Для локальной установки требуется ROSZETTA_ENABLE_LOCAL_FIRMWARE=1 и known_hosts')
    path = Path(os.environ.get('ROSZETTA_SFTP_KNOWN_HOSTS', KNOWN_HOSTS))
    with closing(paramiko.SSHClient()) as ssh:
        ssh.load_host_keys(str(path))
        ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
        if not ssh.get_host_keys().lookup(creds.host):
            raise FirmwareBlocked('SFTP: доверенный SSH host key не найден')
        try:
            ssh.connect(creds.host, port=22, username=creds.username, password=creds.password,
                        look_for_keys=False, allow_agent=False, timeout=15, auth_timeout=15, banner_timeout=15)
            sftp = ssh.open_sftp()
        except Exception:
            raise FirmwareBlocked('SFTP: соединение, проверка ключа или аутентификация не удались') from None
        with closing(sftp):
            sftp.get_channel().settimeout(45)
            for item in packages:
                name = item.name.lower()
                # Local preflight already checked exact, safe names and SHA256.
                try:
                    sftp.stat(name)
                except FileNotFoundError:
                    pass
                else:
                    raise FirmwareUnconfirmed('SFTP: файл уже присутствует на устройстве: '+name)
                try:
                    with sftp.open(name, 'xb') as output:
                        output.write(item.content)
                    if int(sftp.stat(name).st_size) != item.size:
                        raise ValueError('size mismatch')
                    digest = hashlib.sha256()
                    with sftp.open(name, 'rb') as inp:
                        while True:
                            chunk=inp.read(65536)
                            if not chunk: break
                            digest.update(chunk)
                    if digest.hexdigest() != item.sha256.lower():
                        raise ValueError('checksum mismatch')
                except Exception:
                    raise FirmwareUnconfirmed('SFTP: размер/контрольная сумма не подтверждены: ' + name) from None
