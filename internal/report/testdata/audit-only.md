⚠️ Audit only (the AI review is not part of this build): 1 critical, 1 high, 1 medium, 1 low findings (4 coverage gaps)

**web-1** · debian 12 · kernel 6.1.0-28-amd64 · run 20261114T061500Z-3fa2, 2026-11-14 06:15 UTC

## Upgrades

- Upgrade lodash in /srv/shop to 4.18.0 to clear all 4 of its findings.

## Critical risk (1)

- [CVE-2026-2000](https://security-tracker.debian.org/tracker/CVE-2026-2000) in linux-image-6.1.0-28-amd64 6.1.119-1 (kernel): severity High, known exploited (CISA KEV).
  Upgrade the kernel to 6.1.123-1 or later (apt-get dist-upgrade), then reboot.

## High risk (1)

- [CVE-2026-1234](https://security-tracker.debian.org/tracker/CVE-2026-1234) in libssl3 3.0.15-1\~deb12u1 (nginx, node, python3.11): severity High, EPSS 41.0%.
  Upgrade libssl3 to 3.0.16-1\~deb12u1 (apt-get install --only-upgrade libssl3), then restart nginx.service, shop.service, python3.11.

## Medium risk (1)

- [GHSA-35jh-r3h4-6jhm](https://security-tracker.debian.org/tracker/GHSA-35jh-r3h4-6jhm) in lodash 4.17.20 (node): severity High, EPSS 0.2%.
  Upgrade lodash in /srv/shop to 4.17.21, then restart shop.service.

## Low risk (1)

- [CVE-2026-3000](https://security-tracker.debian.org/tracker/CVE-2026-3000) in zlib1g 1:1.2.13.dfsg-1 (shop-web-1): severity Low.
  No fix is known for zlib1g 1:1.2.13.dfsg-1 yet.

## Restart or reboot needed

- Reboot: the running kernel 6.1.0-28-amd64 is not the newest installed (a newer kernel package is installed: linux-image-6.1.0-31-amd64 6.1.128-1).
- Restart nginx.service: it still runs replaced files: /usr/lib/x86\_64-linux-gnu/libssl.so.3.

## Coverage gaps

- `ORIGIN_UNRESOLVED` lxd: /snap/lxd/123/bin/lxd: it runs from a snap, and snaps are not audited in v1
- `ORIGIN_UNIDENTIFIED` api: /opt/api/api: no packages were identified in it
- `APPDIR_NOT_FOUND` python3.11 (/usr/bin/python3.11): no app directory was found, so only the interpreter is audited
- `IMAGE_ONLY` container shop-web-1: only the image is audited, not bind-mounted code or changes made in the running container

## Data freshness

- Vulnerability database built 2026-11-14 03:12 UTC (Grype 0.121.2).
