// Package cli implements the tripcoil command line.
package cli

import (
	"fmt"
	"io"

	"github.com/klar-web-services/tripcoil/internal/buildinfo"
)

const usage = `Tripcoil watches a running Linux server: it finds what is running, audits the
running versions for known vulnerabilities, and has an AI agent judge what is exploitable.

Usage:
  tripcoil run [flags]    Run once now and write an evidence folder (as root)
  tripcoil version        Print version information

Run "tripcoil run -h" for its flags.
`

// deps holds everything the commands take from the outside world, so tests can replace it.
// Task 14 adds the fields `tripcoil run` needs.
type deps struct{}

func defaultDeps() deps { return deps{} }

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
	case "version", "--version":
		fmt.Fprintf(stdout, "tripcoil %s\n", buildinfo.Version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "tripcoil: unknown command %q\n\n%s", args[0], usage)
	return 2
}
