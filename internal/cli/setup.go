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
(systemd or OpenRC), which it starts. For Claude Code it offers to install Node.js 22 and Claude
Code, and to create the token with claude setup-token; then it runs tripcoil doctor, before the
service starts. Running it again changes nothing that is already set up.

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
	ready, start, err := d.setup(setup.Options{Agent: *agentFlag, Yes: *yes}, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "tripcoil setup: %v\n", err)
		return 2
	}
	if !ready {
		return 0
	}
	if start != nil {
		defer d.holdSignals()()
	}
	fmt.Fprintln(stdout, "\nChecking the host (tripcoil doctor):")
	code := doctor(stdout, d, start != nil)
	if start != nil {
		if err := start(); err != nil {
			fmt.Fprintf(stderr, "tripcoil setup: %v\n", err)
			return 2
		}
	}
	return code
}

func setupHost(o setup.Options, stdout io.Writer) (bool, func() error, error) {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return false, nil, fmt.Errorf("cannot find Tripcoil's own binary: %v", err)
	}
	return setup.NewHost(exe, os.Stdin, stdout).Setup(o)
}
