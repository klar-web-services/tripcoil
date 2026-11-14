// Package cli implements the tripcoil command line.
package cli

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/buildinfo"
	"github.com/klar-web-services/tripcoil/internal/config"
	"github.com/klar-web-services/tripcoil/internal/grype"
	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/priority"
)

const usage = `Tripcoil watches a running Linux server: it finds what is running, audits the
running versions for known vulnerabilities, and has an AI agent judge what is exploitable.

Usage:
  tripcoil run [flags]     Run once now and write an evidence folder (as root)
  tripcoil report [flags]  Print the latest report (as root)
  tripcoil version         Print version information

Run "tripcoil <command> -h" for a command's flags.
`

// StateDir holds run folders, the cache and the run lock (spec section 4.3).
const StateDir = "/var/lib/tripcoil"

// deps holds everything the commands take from the outside world, so tests can replace it.
type deps struct {
	euid       func() int
	now        func() time.Time
	random     io.Reader
	configPath string
	stateDir   string
	collect    func(ctx context.Context, cacheDir string) (*inventory.Inventory, error)
	audit      func(ctx context.Context, inv *inventory.Inventory, cacheDir, runDir string, cfg config.Config) *audit.Audit
	// lowerPriority makes the run as light on the host as a scheduled one (spec section 13).
	lowerPriority func() error
	// interrupts returns a context that is cancelled by Ctrl-C or SIGTERM.
	interrupts func() (context.Context, context.CancelFunc)
}

func defaultDeps() deps {
	return deps{
		euid:          os.Geteuid,
		now:           time.Now,
		random:        rand.Reader,
		configPath:    config.DefaultPath,
		stateDir:      StateDir,
		collect:       collectHost,
		audit:         auditHost,
		lowerPriority: priority.Lower,
		interrupts: func() (context.Context, context.CancelFunc) {
			return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		},
	}
}

// Run executes the command line and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	return dispatch(args, stdout, stderr, defaultDeps())
}

// dispatch is named so that it cannot clash with the internal/run package.
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
	case "version", "--version":
		fmt.Fprintf(stdout, "tripcoil %s\ngrype %s\n", buildinfo.Version, grype.Version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "tripcoil: unknown command %q\n\n%s", args[0], usage)
	return 2
}
