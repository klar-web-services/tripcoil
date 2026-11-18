package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/klar-web-services/tripcoil/internal/agent"
	"github.com/klar-web-services/tripcoil/internal/config"
	"github.com/klar-web-services/tripcoil/internal/dockerapi"
	"github.com/klar-web-services/tripcoil/internal/grype"
	"github.com/klar-web-services/tripcoil/internal/osrel"
	"github.com/klar-web-services/tripcoil/internal/pkgtool"
	"github.com/klar-web-services/tripcoil/internal/problem"
	"github.com/klar-web-services/tripcoil/internal/review"
	"github.com/klar-web-services/tripcoil/internal/run"
	"github.com/klar-web-services/tripcoil/internal/sandbox"
	"github.com/klar-web-services/tripcoil/internal/setup"
)

const doctorUsage = `Usage: tripcoil doctor

Check this host's setup, as root: the config, the service, the package tool, Docker, Grype, and
for the review the agent's user, the CLI, its credentials (a short prompt, which costs a little)
and the sandbox probe. Exits 0 when every check passes, 1 otherwise.
`

type doctorHost struct {
	packages  func(ctx context.Context) error
	docker    func(ctx context.Context) (absent bool, err error)
	grype     func(ctx context.Context) error
	agentUser func() error
	findCLI   func(command, name string) (string, error)
	booted    func() bool
	bwrap     func() error
	check     func(ctx context.Context, cfg config.Config, runDir string) (string, error)
}

func hostDoctor(stateDir string) doctorHost {
	return doctorHost{
		packages: func(ctx context.Context) error {
			rel, err := osrel.Read("/")
			if err != nil {
				return err
			}
			tool := pkgtool.New(rel.Family().PackageType(), pkgtool.Exec)
			if tool == nil {
				return fmt.Errorf("Tripcoil knows no package tool for %s", rel.ID)
			}
			return tool.Check(ctx)
		},
		docker: func(ctx context.Context) (bool, error) {
			socket, err := dockerapi.Socket(os.Getenv("DOCKER_HOST"))
			if err != nil {
				return false, err
			}
			if _, err := os.Stat(socket); errors.Is(err, fs.ErrNotExist) {
				return true, nil
			}
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			return false, dockerapi.New(socket).Ping(ctx)
		},
		grype: func(ctx context.Context) error {
			_, err := grype.NewInstaller(filepath.Join(stateDir, "cache")).Ensure(ctx)
			return err
		},
		agentUser: func() error { _, err := agent.LookupUser(); return err },
		findCLI:   agent.FindCLI,
		booted:    sandbox.Booted,
		bwrap:     func() error { _, err := agent.LookPath("bwrap"); return err },
		check: func(ctx context.Context, cfg config.Config, runDir string) (string, error) {
			return agent.New(cfg, stateDir, filepath.Dir(config.DefaultPath)).Check(ctx, runDir)
		},
	}
}

func runDoctor(args []string, stdout, stderr io.Writer, d deps) int {
	fs := flag.NewFlagSet("tripcoil doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, doctorUsage) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tripcoil doctor: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if d.euid() != 0 {
		fmt.Fprintln(stderr, "tripcoil doctor must run as root (try: sudo tripcoil doctor)")
		return 2
	}
	return doctor(stdout, d, false)
}

func doctor(stdout io.Writer, d deps, starting bool) int {
	failed := false
	pass := func(msg string) { fmt.Fprintf(stdout, "✓ %s\n", msg) }
	failCheck := func(msg, fix string) {
		failed = true
		fmt.Fprintf(stdout, "✗ %s\n", oneLine(msg))
		if fix != "" {
			fmt.Fprintf(stdout, "  Fix: %s\n", fix)
		}
	}
	verdict := func() int {
		if failed {
			fmt.Fprintln(stdout, "Some checks failed.")
			return 1
		}
		fmt.Fprintln(stdout, "Every check passed.")
		return 0
	}

	cfg, err := config.Load(d.configPath)
	if err != nil {
		failCheck(fmt.Sprintf("%s: %v", problem.ConfigInvalid, err), "correct "+d.configPath+"; the other checks need a valid config")
		return verdict()
	}
	if cfg.Missing {
		pass(d.configPath + " does not exist, so the defaults apply.")
	} else {
		pass(d.configPath + " is valid.")
	}

	switch svc, err := d.service(); {
	case err != nil:
		failCheck(err.Error(), "")
	case !svc.Installed:
		failCheck("The tripcoil service is not installed.", d.sudo+"tripcoil setup")
	case !svc.Running && starting:
		fmt.Fprintln(stdout, "· The tripcoil service is installed and starts after the checks.")
	case !svc.Running && svc.Manager == setup.Systemd:
		failCheck("The tripcoil service is installed but not running.", d.sudo+"systemctl start tripcoil; its log: journalctl -u tripcoil")
	case !svc.Running:
		failCheck("The tripcoil service is installed but not running.", d.sudo+"rc-service tripcoil start; its log: /var/log/tripcoil.log")
	default:
		pass(fmt.Sprintf("The tripcoil service is running (%s).", svc.Manager))
	}

	ctx, stop := d.interrupts()
	defer stop()
	if err := d.doctor.packages(ctx); err != nil {
		failCheck("The package tool: "+err.Error(), "repair the distribution's package manager; without it, no running file is tied to its package")
	} else {
		pass("The package tool can read the package database.")
	}
	switch absent, err := d.doctor.docker(ctx); {
	case absent:
		pass("Docker is not installed, so there are no containers to audit.")
	case err != nil:
		failCheck("Docker does not answer: "+err.Error(), "start Docker, or check DOCKER_HOST; until then, container items are missing")
	default:
		pass("Docker answers.")
	}

	unlock, err := run.LockContext(ctx, d.stateDir, func() { fmt.Fprintln(stdout, "Waiting for the current run to finish (Ctrl-C stops waiting)...") })
	if err != nil {
		failCheck("Cannot take the run lock: "+err.Error(), "")
		return verdict()
	}
	defer unlock()
	if err := d.doctor.grype(ctx); err != nil {
		failCheck("Grype: "+err.Error(), "allow downloads from github.com (Grype's releases); the audit needs Grype")
	} else {
		pass(fmt.Sprintf("Grype %s is ready.", grype.Version))
	}

	if cfg.Review.Agent == "none" {
		pass("review.agent is none, so there is no review to check.")
		return verdict()
	}
	ready := true
	if err := d.doctor.agentUser(); err != nil {
		ready = false
		failCheck(err.Error(), d.sudo+"tripcoil setup")
	} else {
		pass("The agent's user " + agent.UserName + " exists.")
	}
	if cli, err := d.doctor.findCLI(cfg.Review.Command, cfg.Review.Agent); err != nil {
		ready = false
		failCheck("The agent CLI: "+err.Error(), "install it system-wide, owned by root; "+d.sudo+"tripcoil setup prints how")
	} else {
		pass("The agent CLI " + cli + " is safely owned.")
	}
	if cfg.Review.Agent == "codex" && d.doctor.booted() {
		if err := d.doctor.bwrap(); err != nil {
			failCheck("bubblewrap is not installed, and Codex's own sandbox needs it.", "install the bubblewrap package")
		} else {
			pass("bubblewrap is installed for Codex's own sandbox.")
		}
	}
	if !ready {
		return verdict()
	}
	dir := filepath.Join(d.stateDir, "runs", ".doctor")
	os.RemoveAll(dir)
	if _, err := run.CreateFolder(d.stateDir, ".doctor"); err != nil {
		failCheck("Cannot create "+dir+": "+err.Error(), "")
		return verdict()
	}
	defer os.RemoveAll(dir)
	cli, err := d.doctor.check(ctx, cfg, dir)
	var f *review.Failure
	switch {
	case err == nil:
		pass("The sandbox holds, and " + cli + " answered with its credentials.")
	case errors.As(err, &f) && f.Code == problem.ReviewUnsupported:
		fmt.Fprintf(stdout, "! %s: reports are audit-only.\n", f.Message)
	case errors.As(err, &f) && f.Code == problem.AgentAuth:
		failCheck(f.Code+": "+f.Message, "give the CLI credentials in review.envFile; "+d.sudo+"tripcoil setup prints how")
	case errors.As(err, &f):
		failCheck(f.Code+": "+f.Message, "")
	default:
		failCheck(err.Error(), "")
	}
	return verdict()
}
