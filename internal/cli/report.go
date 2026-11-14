package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
)

const reportUsage = `Usage: tripcoil report [--run <run ID>]

Print the report of the latest finished run, or of the given run, as root.

Flags:
`

var runIDPattern = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{4}$`)

func runReport(args []string, stdout, stderr io.Writer, d deps) int {
	flags := flag.NewFlagSet("tripcoil report", flag.ContinueOnError)
	flags.SetOutput(stderr)
	id := flags.String("run", "", "the run ID, such as 20261114T061500Z-3fa2 (default: the latest finished run)")
	flags.Usage = func() {
		fmt.Fprint(stderr, reportUsage)
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "tripcoil report: unexpected argument %q\n", flags.Arg(0))
		return 2
	}
	if d.euid() != 0 {
		fmt.Fprintln(stderr, "tripcoil report must run as root (try: sudo tripcoil report)")
		return 2
	}
	name := "latest"
	if *id != "" {
		if !runIDPattern.MatchString(*id) {
			fmt.Fprintf(stderr, "tripcoil report: %q is not a run ID, such as 20261114T061500Z-3fa2\n", *id)
			return 2
		}
		name = *id
	}
	runs := filepath.Join(d.stateDir, "runs")
	data, err := os.ReadFile(filepath.Join(runs, name, "report.md"))
	switch {
	case errors.Is(err, fs.ErrNotExist) && *id == "":
		if _, lerr := os.Lstat(filepath.Join(runs, "latest")); lerr != nil {
			fmt.Fprintln(stderr, "No run has finished yet. Start one with: sudo tripcoil run")
			return 2
		}
		target, _ := os.Readlink(filepath.Join(runs, "latest"))
		fmt.Fprintf(stderr, "The latest run (%s) has no report.\n", filepath.Base(target))
		return 2
	case errors.Is(err, fs.ErrNotExist):
		fmt.Fprintf(stderr, "Run %s has no report.\n", *id)
		return 2
	case err != nil:
		fmt.Fprintf(stderr, "tripcoil report: %v\n", err)
		return 2
	}
	if _, err := stdout.Write(data); err != nil {
		return 2
	}
	return 0
}
