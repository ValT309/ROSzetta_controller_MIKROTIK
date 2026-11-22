"""SFTP pull using explicitly trusted host keys; never changes device-mode or SSH settings."""
from contextlib import closing
from pathlib import Path
import os
import uuid
import paramiko
from .client import RouterOSError, routeros_session

KNOWN_HOSTS = '/app/app/roszetta_sftp_known_hosts'
MAX_FILE = 32 * 1024 * 1024


def download_exact(sftp, name, expected):
    if not 0 < expected <= MAX_FILE:
        raise RouterOSError('SFTP PULL: invalid file size')
    with sftp.open(name, 'rb') as stream:
        data = stream.read(expected + 1)
    if len(data) != expected:
        raise RouterOSError('SFTP PULL: file size mismatch')
    return data


def create_backup_via_pull(creds, base_name, trusted_key=None):
    from .backup import BackupFiles, _exec_path, _wait_file, _delete_file, _list_files
    # Unique temporary names prevent removing a pre-existing backup on the router.
    remote = 'rz-pull-' + uuid.uuid4().hex
    names = [remote + '.backup', remote + '.rsc']
    path = Path(os.environ.get('ROSZETTA_SFTP_KNOWN_HOSTS', KNOWN_HOSTS))
    if trusted_key is None and not path.is_file():
        raise RouterOSError('SFTP PULL: trusted host key required (known_hosts)')
    with closing(paramiko.SSHClient()) as ssh:
        try:
            if trusted_key is not None:
                ssh.get_host_keys().add(creds.host, trusted_key.get_name(), trusted_key)
            else:
                ssh.load_host_keys(str(path))
            ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
            if not ssh.get_host_keys().lookup(creds.host):
                raise RouterOSError('SFTP PULL: trusted host key required (known_hosts)')
            ssh.connect(creds.host, port=22, username=creds.username, password=creds.password,
                        look_for_keys=False, allow_agent=False, timeout=15, auth_timeout=15, banner_timeout=15)
        except RouterOSError:
            raise
        except Exception:
            raise RouterOSError('SFTP PULL: SSH connection, authentication or host key verification failed') from None
        try:
            sftp = ssh.open_sftp()
        except Exception:
            raise RouterOSError('SFTP PULL: SFTP subsystem unavailable') from None
        with closing(sftp):
            sftp.get_channel().settimeout(20)
            with routeros_session(creds) as api:
                if any(row.get('name') in names for row in _list_files(api)):
                    raise RouterOSError('SFTP PULL: temporary file collision')
                try:
                    _exec_path(api, 'system', 'backup', 'save', name=remote)
                    _exec_path(api, 'export', file=remote)
                    data = []
                    for name in names:
                        row = _wait_file(api, name)
                        if not row:
                            raise RouterOSError('SFTP PULL: file not appeared')
                        data.append(download_exact(sftp, name, int(row.get('size') or 0)))
                    return BackupFiles(base_name+'.backup', data[0], base_name+'.rsc', data[1])
                except RouterOSError:
                    raise
                except Exception:
                    raise RouterOSError('SFTP PULL: creation or transfer failed; check API permissions and SSH') from None
                finally:
                    for name in names:
                        _delete_file(api, name)
