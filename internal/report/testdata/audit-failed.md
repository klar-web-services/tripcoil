⛔ Run incomplete: the vulnerability database was built 73 hours ago, which is older than audit.maxDatabaseAgeHours (48) (DB_STALE) (3 coverage gaps)

**web-1** · debian 12 · kernel 6.1.0-28-amd64 · run 20261114T061500Z-3fa2, 2026-11-14 06:15 UTC

## Errors

- Audit, `DB_STALE`: the vulnerability database was built 73 hours ago, which is older than audit.maxDatabaseAgeHours (48)

## Restart or reboot needed

- Reboot: the running kernel 6.1.0-28-amd64 is not the newest installed (a newer kernel package is installed: linux-image-6.1.0-31-amd64 6.1.128-1).
- Restart nginx.service: it still runs replaced files: /usr/lib/x86\_64-linux-gnu/libssl.so.3.

## Coverage gaps

- `ORIGIN_UNRESOLVED` lxd: /snap/lxd/123/bin/lxd: it runs from a snap, and snaps are not audited in v1
- `APPDIR_NOT_FOUND` python3.11 (/usr/bin/python3.11): no app directory was found, so only the interpreter is audited
- `IMAGE_ONLY` container shop-web-1: only the image is audited, not bind-mounted code or changes made in the running container

## Data freshness

- Vulnerability database built 2026-11-11 05:15 UTC (Grype 0.121.2).
