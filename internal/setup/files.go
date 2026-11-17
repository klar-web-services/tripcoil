// Package setup configures the host for Tripcoil (tripcoil setup) and checks it (tripcoil doctor):
// the agent's user, the config file and the service (spec sections 3, 9 and 13).
package setup

import (
	"fmt"

	"github.com/klar-web-services/tripcoil/internal/priority"
	"github.com/klar-web-services/tripcoil/internal/sandbox"
)

// Manager is the host's service manager.
type Manager string

const (
	Systemd Manager = "systemd"
	OpenRC  Manager = "openrc"
)

// Paths of the service files.
const (
	UnitPath       = "/etc/systemd/system/tripcoil.service"
	InitScriptPath = "/etc/init.d/tripcoil"
	ConfDPath      = "/etc/conf.d/tripcoil"
)

// File is a file setup writes.
type File struct {
	Path string
	Data string
	Mode uint32
}

// unit is the systemd service. It has no sandboxing of its own on purpose: Tripcoil mounts the
// agent's home where the review's units must see it (no mount namespace), and it needs
// CAP_SYS_ADMIN (map_files, the mount), CAP_NET_ADMIN (nftables) and the host's network.
// OOMPolicy=continue: when the kernel kills a Grype process at MemoryMax, that origin fails and
// the run goes on, instead of systemd stopping the service. Exit 78 is an invalid config, which
// a restart cannot fix; a crash (Go exits 2) is restarted.
const unit = `# Installed by tripcoil setup; running it again rewrites this file.
[Unit]
Description=Tripcoil: audits what runs on this host for known vulnerabilities
Wants=network-online.target
After=network-online.target docker.service

[Service]
Type=simple
ExecStart=%s daemon
ExecReload=/bin/sh -c "kill -HUP $MAINPID"
KillMode=mixed
TimeoutStopSec=2min
Restart=on-failure
RestartSec=30s
RestartPreventExitStatus=78
Nice=%d
IOSchedulingClass=idle
CPUWeight=%d
MemoryMax=%s
OOMPolicy=continue

[Install]
WantedBy=multi-user.target
`

// initScript is the OpenRC service. supervise-daemon restarts the daemon when it dies; the start
// check keeps an invalid config from starting it at all. retry gives a stopped run two minutes to
// write its record and stop the agent, as the systemd unit's TimeoutStopSec (OpenRC's default
// kills it after five seconds).
const initScript = `#!/sbin/openrc-run
# Installed by tripcoil setup; running it again rewrites this file.
description="Tripcoil: audits what runs on this host for known vulnerabilities"
command=%s
command_args="daemon"
supervisor=supervise-daemon
output_log=/var/log/tripcoil.log
error_log=/var/log/tripcoil.log
respawn_delay=30
retry="TERM/120/KILL/5"
supervise_daemon_args="--nicelevel %d --ionice 3"
extra_started_commands="reload"

depend() {
	need net
	after docker
}

start_pre() {
	"$command" daemon --check-config
}

reload() {
	ebegin "Reloading ${RC_SVCNAME}"
	supervise-daemon "${RC_SVCNAME}" --signal HUP
	eend $?
}
`

// confD holds the service's cgroup settings, which OpenRC applies on cgroup v2.
const confD = `# Installed by tripcoil setup; running it again rewrites this file.
rc_cgroup_settings="
cpu.weight %d
memory.max %d
"
`

// ServiceFiles are the service files for the binary at exe.
func ServiceFiles(m Manager, exe string) []File {
	if m == Systemd {
		return []File{{UnitPath, fmt.Sprintf(unit, exe, priority.Nice, priority.CPUWeight, priority.MemoryMax), 0o644}}
	}
	mem, _ := sandbox.Bytes(priority.MemoryMax)
	return []File{
		{InitScriptPath, fmt.Sprintf(initScript, exe, priority.Nice), 0o755},
		{ConfDPath, fmt.Sprintf(confD, priority.CPUWeight, mem), 0o644},
	}
}

// EnvFilePath is the token file the written config names in review.envFile.
const EnvFilePath = "/etc/tripcoil/agent.env"

// defaultConfig is the config setup writes, the defaults of spec section 10 with the chosen agent.
const defaultConfig = `# Tripcoil's configuration. After a change: sudo tripcoil doctor, then restart or reload the service.
version: 1
interval: 6h
review:
  agent: %s            # claude | codex | none
  command: ""              # path to the CLI; empty: look it up on the system path
  model: ""                # passed to the CLI when set
  extraArgs: []            # appended to the CLI's arguments
  timeout: 60m
  maxAge: 168h             # re-review after this long even without changes
  envFile: /etc/tripcoil/agent.env # root-only KEY=value lines for the CLI, such as its token
  memoryMax: 2G
  cpuQuota: 100%%           # of one CPU
  allowAddresses: []       # private or local addresses the agent may reach (proxy, model gateway)
audit:
  maxDatabaseAgeHours: 48
retention:
  keepRuns: 30             # the last reviewed run is always kept as well
`

// DefaultConfig is the config file for agent.
func DefaultConfig(agent string) string { return fmt.Sprintf(defaultConfig, agent) }
