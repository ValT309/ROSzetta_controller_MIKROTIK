ROSzetta v0.9.0.3 Stage 2: experimental LOCAL NPK delivery; disabled by default.
Never test on production MikroTik.
Set ROSZETTA_ENABLE_LOCAL_FIRMWARE=1 in backend container environment and provide pinned /app/app/roszetta_sftp_known_hosts.
RouterOS device must accept SSH/SFTP using the same credentials as API; SSH host key must match known_hosts.
Selected installed packages must be present as <package>-<version>-<architecture>.npk in repository, one per package.
All NPK hashes are checked before upload and verified by SFTP readback. No RouterBOOT action.
For any transfer uncertainty, job state unknown; clean NPKs manually after inspection.
Local functionality is not production-validated on actual hardware.
