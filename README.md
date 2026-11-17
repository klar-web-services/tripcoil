# Tripcoil

Tripcoil watches a running Linux server: it finds what is running, audits the running versions for
known vulnerabilities, and has an AI agent judge which findings can be exploited on that machine.
It runs as a service (systemd, or OpenRC on Alpine) and writes an evidence folder per run.

## Install

As root, on Linux (amd64 or arm64):

```sh
curl -fsSL https://tools.klar.ws/tripcoil/install.sh | sudo sh
```

The installer puts the binary into `/usr/local/bin` and verifies its checksum. Environment
variables: `TRIPCOIL_VERSION` (pin a version), `TRIPCOIL_INSTALL_DIR` (default `/usr/local/bin`),
`TRIPCOIL_BASE_URL`. Releases are also on GitHub.

## Use

```sh
sudo tripcoil setup     # the agent's user, /etc/tripcoil/tripcoil.yaml and the service
sudo tripcoil doctor    # checks the setup, the agent CLI and its sandbox
sudo tripcoil run       # one run now; the service runs every 6 hours
sudo tripcoil report    # the latest report
sudo tripcoil status    # the service, the last and next run
```

`setup` asks which agent CLI reviews the runs (Claude Code, Codex, or none) and ends by printing
how to install it system-wide and give it credentials. Claude Code reviews run on your Claude
subscription through a `claude setup-token` token; Codex needs an OpenAI API key, billed per use.
The review runs the CLI as the unprivileged user `tripcoil-agent` in an OS-enforced sandbox; on
systemd it needs systemd 247 or later.

## Configuration

`/etc/tripcoil/tripcoil.yaml`, which `setup` writes with the defaults:

```yaml
version: 1
interval: 6h
review:
  agent: claude            # claude | codex | none
  command: ""              # path to the CLI; empty: look it up on the system path
  model: ""                # passed to the CLI when set
  extraArgs: []            # appended to the CLI's arguments
  timeout: 60m
  maxAge: 168h             # re-review after this long even without changes
  envFile: /etc/tripcoil/agent.env # root-only KEY=value lines for the CLI, such as its token
  memoryMax: 2G
  cpuQuota: 100%           # of one CPU
  allowAddresses: []       # private or local addresses the agent may reach (proxy, model gateway)
audit:
  maxDatabaseAgeHours: 48
retention:
  keepRuns: 30             # the last reviewed run is always kept as well
```

Unknown fields and invalid values are errors that name the line. `interval` is at least `15m`.
`review.envFile` must be owned by root and readable by nobody else. After a change, reload the
service (`sudo systemctl reload tripcoil`, or `sudo rc-service tripcoil reload`).

## License

MIT, see [LICENSE](LICENSE).
