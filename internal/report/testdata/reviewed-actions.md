🔴 2 things to fix now, 1 to fix this week, 1 not assessed (4 coverage gaps)

**web-1** · debian 12 · kernel 6.1.0-28-amd64 · run 20261114T061500Z-3fa2, 2026-11-14 06:15 UTC · reviewed by claude 2.1.309, model opus

## Summary

nginx's TLS is exploitable from the internet now. The kernel CVE needs a local user, and this host has untrusted ones.

- The container's bind-mounted code was not reviewed.

## Actions

### Do now (2)

- **Update libssl3** (System packages): libssl3 3.0.15-1\~deb12u1 → 3.0.17-1\~deb12u1
  - Also: Close port 8443 in the firewall
  - Step 1: Upgrade the package: `apt-get update && apt-get install --only-upgrade libssl3`
  - Step 2: Restart nginx and the shop: `systemctl restart nginx shop`
  - Step 3: Check that it answers: `curl -fsS https://localhost/ | head -1 > ~/tls_check.txt`
  - Upstream: bookworm-security has 3.0.17-1\~deb12u1 (https://security-tracker.debian.org/tracker/CVE-2026-1234).
- **Fix CVE-2026-9999 in api**
  - Step 1: rebuild /opt/api/api with Go 1.27.4

### Do this week (1)

- **Update the kernel and reboot** (Linux kernel): linux-image-6.1.0-28-amd64 6.1.119-1 → 9.9
  - Step 1: Upgrade the kernel: `apt-get update && apt-get dist-upgrade`
  - Step 2: Reboot
  - Not reviewed: these are the default steps.

### Not assessed (1)

- **Update the shop-web-1 image**: libssl3 3.0.11-1\~deb12u2, fixed in 9.9; zlib1g 1:1.2.13.dfsg-1, no fix yet
  - What the newer image holds was not checked.
  - Step 1: Pull or rebuild ghcr.io/acme/shop:2026.11.3
  - Step 2: Recreate the container shop-web-1
  - Not reviewed: these are the default steps.

## Exploitable now (2)

- **[CVE-2026-1234](https://security-tracker.debian.org/tracker/CVE-2026-1234) in libssl3 3.0.15-1\~deb12u1 (nginx, node, python3.11), high risk, priority now**: nginx listens on 0.0.0.0:443 and the firewall allows 443 from anywhere.
  - Evidence: facts/network.json: 0.0.0.0:443 nginx; facts/firewall.txt: tcp dport 443 accept
  - Fix: apt-get install --only-upgrade libssl3
  - Fix: systemctl restart nginx shop
  - Sources: https://security-tracker.debian.org/tracker/CVE-2026-1234
- **CVE-2026-9999 in api (added by the review), priority now**: The api binary embeds an old Go net/http; it listens on 0.0.0.0:8080.
  - Fix: rebuild /opt/api/api with Go 1.27.4
  - Sources: https://go.dev/issue/1

## Exploitable under conditions (1)

- **[CVE-2026-2000](https://security-tracker.debian.org/tracker/CVE-2026-2000) in linux-image-6.1.0-28-amd64 6.1.119-1 (kernel), critical risk, priority soon**: Needs a local user; alice and bob can log in.
  - Fix: apt-get dist-upgrade
  - Fix: reboot

## Not assessed (3)

The review could not tell whether these are exploitable here:

- **[CVE-2026-1234](https://security-tracker.debian.org/tracker/CVE-2026-1234) in libssl3 3.0.11-1\~deb12u2 (shop-web-1), high risk, priority scheduled**: The image's libssl3 is not loaded by the shop process, as far as the image shows.
  - Corrected package.version: 3.0.11-1\~deb12u2 → 3.0.11-1\~deb12u3 (the image's dpkg status says so)
  - Fix: rebuild the image

The review did not address 2 findings:

### Medium risk (2)

- 1 in this host's packages (1 package); all in libssl3 (1)
- 1 in the container shop-web-1 (ghcr.io/acme/shop:2026.11.3); all in libssl3 (1)

Every medium risk finding, with its remediation, is in audit.json.

## Restart or reboot needed

- Reboot: the running kernel 6.1.0-28-amd64 is not the newest installed (a newer kernel package is installed: linux-image-6.1.0-31-amd64 6.1.128-1).
- Restart nginx.service: it still runs replaced files: /usr/lib/x86\_64-linux-gnu/libssl.so.3.

## Not exploitable here (1)

<details>
<summary>1 finding</summary>

- **[GHSA-35jh-r3h4-6jhm](https://security-tracker.debian.org/tracker/GHSA-35jh-r3h4-6jhm) in lodash 4.17.20 (node), medium risk, priority none**: The shop never calls lodash's template function.

</details>

## Discarded (1)

<details>
<summary>1 finding</summary>

- **[CVE-2026-3000](https://security-tracker.debian.org/tracker/CVE-2026-3000) in zlib1g 1:1.2.13.dfsg-1 (shop-web-1), low risk**: Debian fixed it in 1:1.2.13.dfsg-1 (DSA-5000-1).

</details>

## Coverage gaps

- `ORIGIN_UNRESOLVED` lxd: /snap/lxd/123/bin/lxd: it runs from a snap, and snaps are not audited in v1
- `ORIGIN_UNIDENTIFIED` api: /opt/api/api: no packages were identified in it
- `APPDIR_NOT_FOUND` python3.11 (/usr/bin/python3.11): no app directory was found, so only the interpreter is audited
- `IMAGE_ONLY` container shop-web-1: only the image is audited, not bind-mounted code or changes made in the running container

## Data freshness

- Vulnerability database built 2026-11-14 03:12 UTC (Grype 0.121.2).
