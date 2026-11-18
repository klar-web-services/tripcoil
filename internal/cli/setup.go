package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/klar-web-services/tripcoil/internal/setup"
)

const setupUsage = `Usage: tripcoil setup [--agent claude|codex|none] [--yes]

Set this host up, as root: the agent's user, /etc/tripcoil/tripcoil.yaml and the tripcoil service
(systemd or OpenRC), which it starts. Running it again changes nothing that is already set up.

Flags:
`

func runSetup(args []string, stdout, stderr io.Writer, d deps) int {
	fs := flag.NewFlagSet("tripcoil setup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	agentFlag := fs.String("agent", "", "the agent CLI that reviews the runs: claude, codex or none (default: ask; claude with --yes)")
	yes := fs.Bool("yes", false, "accept the defaults instead of asking")
	fs.Usage = func() {
		fmt.Fprint(stderr, setupUsage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tripcoil setup: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	switch *agentFlag {
	case "", "claude", "codex", "none":
	default:
		fmt.Fprintf(stderr, "tripcoil setup: --agent must be claude, codex or none, found %q\n", *agentFlag)
		return 2
	}
	if d.euid() != 0 {
		fmt.Fprintln(stderr, "tripcoil setup must run as root (try: sudo tripcoil setup)")
		return 2
	}
	ready, err := d.setup(setup.Options{Agent: *agentFlag, Yes: *yes}, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "tripcoil setup: %v\n", err)
		return 2
	}
	if !ready {
		return 0
	}
	fmt.Fprintln(stdout, "\nChecking the host (tripcoil doctor):")
	return runDoctor(nil, stdout, stderr, d)
}

// setupHost sets this machine up, for the binary that runs now, and reports whether the review
// is ready to check.
func setupHost(o setup.Options, stdout io.Writer) (bool, error) {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return false, fmt.Errorf("cannot find Tripcoil's own binary: %v", err)
	}
	return setup.NewHost(exe, os.Stdin, stdout).Setup(o)
}
