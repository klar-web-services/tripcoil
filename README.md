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
sudo tripcoil doctor    # checks the setup, the agent CLI and its sandbox, and the Zosia secret
sudo tripcoil run       # one run now; the service runs every 6 hours
sudo tripcoil report    # the latest report
sudo tripcoil status    # the service, the last and next run, the last report sent to Zosia
sudo tripcoil zosia connect # optional: send the reports to Zosia (see below)
sudo tripcoil update    # the latest release, then restarts the service
sudo tripcoil uninstall # removes Tripcoil; Node.js and Claude Code stay
```

As root, run the commands without `sudo`. `setup` asks which agent CLI reviews the runs (Claude
Code, Codex, or none). For Claude Code it offers to install Node.js 22 and Claude Code (with apt,
dnf, pacman or apk; on older Debian, Ubuntu and RHEL from NodeSource's repository), then runs
`claude setup-token`, saves the token it prints to `/etc/tripcoil/agent.env` and checks the host.
Claude Code reviews run on your Claude subscription (Pro or Max), not API billing. For Codex,
`setup` prints how to install it and give it an OpenAI API key, billed per use.
The review runs the CLI as the unprivileged user `tripcoil-agent` in an OS-enforced sandbox; on
systemd it needs systemd 247 or later.

`update` replaces the binary, in the folder it is installed in, with the latest release, or says
that it is already up to date. It runs the installer that came with your version, checksum check
included, and then restarts a running service. When a run is in progress it asks before it
interrupts it; without an answer it leaves the service alone and prints the restart command.
Releases before 1.1.0 have no `update`: run the installer again instead.

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
zosia:
  secretFile: /etc/tripcoil/zosia.secret # reports go to Zosia when this file exists; "" turns sending off
  url: ""                  # for testing only: another Zosia
  key: ""                  # for testing only: that Zosia's report key
```

Unknown fields and invalid values are errors that name the line. `interval` is at least `15m`.
`review.envFile` and `zosia.secretFile` must be owned by root and readable by nobody else. After a change, reload the
service (`sudo systemctl reload tripcoil`, or `sudo rc-service tripcoil reload`).

## Zosia (optional)

[Zosia](https://zosiasec.com) is a dashboard for every machine Tripcoil watches and every repository Shearbolt gates. Tripcoil works the same without it.

When `/etc/tripcoil/zosia.secret` exists, Tripcoil sends each finished run's report (what `tripcoil report --json` prints, without the advisory texts) to Zosia after the run. It is encrypted to Zosia's public key and bound to your secret, so only Zosia can read it and only into your account. Sending never changes a run's result; `tripcoil status` shows the last send.

`sudo tripcoil zosia connect` connects the machine: it shows a code, you approve it in your browser at https://zosiasec.com/app/connect, and Tripcoil stores the secret it receives. `sudo tripcoil setup` offers the same. On a host set up by a script, make a secret at https://zosiasec.com/app/secrets and write it yourself:

    sudo install -m 600 -o root -g root /dev/null /etc/tripcoil/zosia.secret
    echo 'zosia_…' | sudo tee /etc/tripcoil/zosia.secret >/dev/null

To disconnect, delete the file (or the secret in Zosia). Zosia names the machine by a key derived from `/etc/machine-id` without sending it; give cloned machines a new machine ID (`systemd-machine-id-setup` after removing `/etc/machine-id`), or they show up as one.

## License

MIT, see [LICENSE](LICENSE).
