# Grype fixtures

Real output of Grype 0.121.2 (database v6.1.10 built 2026-11-14T06:19:25Z), recorded while Plan 2
was written. Local paths were replaced with `/var/lib/tripcoil/cache/...`; nothing else was changed.

- `report.json`: the top level of a `dir:` scan with four real matches put into its `matches`:
  log4j-core 2.14.1 (KEV and EPSS), Debian's libc6 (CVSS only in the related NVD record), Rocky's
  libgcc (KEV) and Debian's kernel package after its SBOM entry was given source `linux` and
  version 6.1.76-1.
- `debian12-staging.cdx.json`: the SBOM of a staging root with Debian 12's os-release,
  debian_version and dpkg status.
- `rocky9-packages.cdx.json`: Rocky Linux 9's staging-root SBOM, cut to three packages, one with
  an epoch.
- `pop22-staging.cdx.json`: Pop!_OS 22.04's staging-root SBOM, cut to four packages (adduser,
  bash, libc6, passwd), the operating system and the dpkg status file, with the dependencies
  among them and without its vulnerabilities. Its purls carry `distro=pop-22.04`, which Grype
  does not know: matching the whole SBOM unchanged found none of the 71 matches its scan found.
- `go-binary.cdx.json`: a Go binary linking golang.org/x/text v0.3.5.
- `stripped-c-binary.cdx.json`: a stripped C binary, in which Grype finds nothing.
- `debian-kernel.cdx.json`: Debian 12's `linux-image-6.1.0-54-amd64` 6.1.190-1 as Grype catalogs
  it (source `linux-signed-amd64` 6.1.190+1); `debian-kernel-rewritten-component.json` is that
  entry as rewritten for the matches in `report.json`.
- `dbsearch-nvd.json`: `grype db search vuln CVE-2024-1086 --provider nvd -o json`.
