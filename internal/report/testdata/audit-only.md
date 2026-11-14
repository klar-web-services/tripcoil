⚠️ Audit only (the AI review is not part of this build): 1 critical, 2 high, 3 medium, 1 low findings (4 coverage gaps)

**web-1** · debian 12 · kernel 6.1.0-28-amd64 · run 20261114T061500Z-3fa2, 2026-11-14 06:15 UTC

## Upgrades

- Upgrade lodash 4.17.20 in /srv/shop to 4.18.0 to clear all 4 of its findings.

## Critical risk (1)

- [CVE-2026-2000](https://security-tracker.debian.org/tracker/CVE-2026-2000): severity High, known exploited (CISA KEV).
  - linux-image-6.1.0-28-amd64 6.1.119-1 in kernel: Upgrade the kernel to 6.1.123-1 or later (apt-get dist-upgrade), then reboot.

## High risk (2)

- [CVE-2026-1234](https://security-tracker.debian.org/tracker/CVE-2026-1234): severity High, EPSS 41.0%.
  - libssl3 3.0.15-1\~deb12u1 in nginx, node, python3.11: Upgrade libssl3 to 3.0.16-1\~deb12u1 (apt-get install --only-upgrade libssl3), then restart nginx.service, shop.service, python3.11.
  - libssl3 3.0.11-1\~deb12u2 in shop-web-1: Rebuild ghcr.io/acme/shop:2026.11.3 or pull a newer image with libssl3 3.0.16-1\~deb12u1 or later, then recreate the container shop-web-1.

## Medium risk (3)

- 1 in the app directory /srv/shop (node); all in lodash (1)
- 1 in the container shop-web-1 (ghcr.io/acme/shop:2026.11.3); all in libssl3 (1)
- 1 in this host's packages (1 package); all in libssl3 (1)

Every medium risk finding, with its remediation, is in audit.json.

## Low risk (1)

- 1 in the container shop-web-1 (ghcr.io/acme/shop:2026.11.3); all in zlib1g (1)

Every low risk finding, with its remediation, is in audit.json.

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
