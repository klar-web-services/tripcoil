package cli

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/klar-web-services/tripcoil/internal/agent"
	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/buildinfo"
	"github.com/klar-web-services/tripcoil/internal/config"
	"github.com/klar-web-services/tripcoil/internal/facts"
	"github.com/klar-web-services/tripcoil/internal/grype"
	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/priority"
	"github.com/klar-web-services/tripcoil/internal/probe"
	"github.com/klar-web-services/tripcoil/internal/review"
	"github.com/klar-web-services/tripcoil/internal/setup"
)

const usage = `Tripcoil watches a running Linux server: it finds what is running, audits the
running versions for known vulnerabilities, and has an AI agent judge what is exploitable.

Usage:
  tripcoil setup [flags]   Set this host up: agent user, config, service (as root)
  tripcoil doctor          Check this host's setup, the agent CLI and the sandbox (as root)
  tripcoil run [flags]     Run once now and write an evidence folder (as root)
  tripcoil report [flags]  Print the latest report (as root)
  tripcoil status          Print the service's state and the last and next run (as root)
  tripcoil daemon          The service's entrypoint: a run every interval (as root)
  tripcoil update          Update to the latest release and restart the service (as root)
  tripcoil uninstall       Remove what setup and the installer added (as root)
  tripcoil version         Print version information

Run "tripcoil <command> -h" for a command's flags.
`

const StateDir = "/var/lib/tripcoil"

type deps struct {
	euid          func() int
	sudo          string
	now           func() time.Time
	random        io.Reader
	configPath    string
	stateDir      string
	collect       func(ctx context.Context, cacheDir string) (*inventory.Inventory, error)
	audit         func(ctx context.Context, inv *inventory.Inventory, cacheDir, runDir string, cfg config.Config) *audit.Audit
	facts         func(ctx context.Context, inv *inventory.Inventory, runDir string) (*facts.Index, error)
	agent         func(cfg config.Config) review.Agent
	enterScope    func(args []string) (code int, ran bool, err error)
	lowerPriority func() error
	interrupts    func() (context.Context, context.CancelFunc)
	setup         func(o setup.Options, stdout io.Writer) (ready bool, start func() error, err error)
	service       func() (setup.Service, error)
	holdSignals   func() (release func())
	doctor        doctorHost
	uninstall     func(o setup.UninstallOptions, stdout io.Writer) error
	update        func(stdout, stderr io.Writer) error
	hangups       func() <-chan struct{}
	after         func(time.Duration) <-chan time.Time
}

func defaultDeps() deps {
	return deps{
		euid:          os.Geteuid,
		sudo:          setup.Sudo(os.Geteuid(), os.Getenv("SUDO_USER")),
		now:           time.Now,
		random:        rand.Reader,
		configPath:    config.DefaultPath,
		stateDir:      StateDir,
		collect:       collectHost,
		audit:         auditHost,
		facts:         factsHost,
		agent:         hostAgent,
		enterScope:    enterScope,
		lowerPriority: priority.Lower,
		interrupts: func() (context.Context, context.CancelFunc) {
			return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		},
		setup:       setupHost,
		service:     serviceHost,
		holdSignals: holdSignals,
		doctor:      hostDoctor(StateDir),
		uninstall:   uninstallHost,
		update:      updateHost,
		hangups:     hangups,
		after:       time.After,
	}
}

func holdSignals() func() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP, os.Interrupt, syscall.SIGTERM, syscall.SIGPIPE) // SIGPIPE: a pipe into a tee that died
	return func() { signal.Stop(c) }
}

func hangups() <-chan struct{} {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)
	out := make(chan struct{}, 1)
	go func() {
		for range sig {
			select {
			case out <- struct{}{}:
			default:
			}
		}
	}()
	return out
}

func hostAgent(cfg config.Config) review.Agent {
	return agent.New(cfg, StateDir, filepath.Dir(config.DefaultPath))
}

func Run(args []string, stdout, stderr io.Writer) int {
	return dispatch(args, stdout, stderr, defaultDeps())
}

func dispatch(args []string, stdout, stderr io.Writer, d deps) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "run":
		return runRun(args[1:], stdout, stderr, d)
	case "report":
		return runReport(args[1:], stdout, stderr, d)
	case "daemon":
		return runDaemon(args[1:], stdout, stderr, d)
	case "setup":
		return runSetup(args[1:], stdout, stderr, d)
	case "status":
		return runStatus(args[1:], stdout, stderr, d)
	case "doctor":
		return runDoctor(args[1:], stdout, stderr, d)
	case "uninstall":
		return runUninstall(args[1:], stdout, stderr, d)
	case "update":
		return runUpdate(args[1:], stdout, stderr, d)
	case "sandbox-probe":
		return probe.Main(args[1:], stdout, stderr)
	case "version", "--version":
		fmt.Fprintf(stdout, "tripcoil %s\ngrype %s\nprompt %s\n", buildinfo.Version, grype.Version, review.PromptVersion)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "tripcoil: unknown command %q\n\n%s", args[0], usage)
	return 2
}
