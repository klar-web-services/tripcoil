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

const uninstallUsage = `Usage: tripcoil uninstall [--yes]

Remove Tripcoil from this host, as root: the service, /etc/tripcoil, /var/lib/tripcoil, the agent's
user, NodeSource's repository if setup added it, and the binary. Node.js, npm, Claude Code and
bubblewrap stay installed.

Flags:
`

func runUninstall(args []string, stdout, stderr io.Writer, d deps) int {
	fs := flag.NewFlagSet("tripcoil uninstall", flag.ContinueOnError)
	fs.SetOutput(stderr)
	yes := fs.Bool("yes", false, "remove without asking")
	fs.Usage = func() {
		fmt.Fprint(stderr, uninstallUsage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tripcoil uninstall: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if d.euid() != 0 {
		fmt.Fprintf(stderr, "tripcoil uninstall must run as root (try: sudo tripcoil uninstall)\n")
		return 2
	}
	if err := d.uninstall(setup.UninstallOptions{Yes: *yes, StateDir: d.stateDir}, stdout); err != nil {
		fmt.Fprintf(stderr, "tripcoil uninstall: %v\n", err)
		return 1
	}
	return 0
}

func uninstallHost(o setup.UninstallOptions, stdout io.Writer) error {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return fmt.Errorf("cannot find Tripcoil's own binary: %v", err)
	}
	return setup.NewHost(exe, os.Stdin, stdout).Uninstall(o)
}
