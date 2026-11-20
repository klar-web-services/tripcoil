package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/facts"
	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/report"
	"github.com/klar-web-services/tripcoil/internal/review"
	"github.com/klar-web-services/tripcoil/internal/run"
)

const reportUsage = `Usage: tripcoil report [--run <run ID>] [--json]

Print the report of the latest finished run, or of the given run, as root. With --json, print the
run, its findings with their review entries, the added findings, coverage gaps and errors as JSON.

Flags:
`

var runIDPattern = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{4}$`)

func runReport(args []string, stdout, stderr io.Writer, d deps) int {
	flags := flag.NewFlagSet("tripcoil report", flag.ContinueOnError)
	flags.SetOutput(stderr)
	id := flags.String("run", "", "the run ID, such as 20261114T061500Z-3fa2 (default: the latest finished run)")
	asJSON := flags.Bool("json", false, "print JSON instead of report.md")
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
	if *asJSON {
		return printJSONReport(stdout, stderr, d.sudo, filepath.Join(runs, name), *id)
	}
	data, err := os.ReadFile(filepath.Join(runs, name, "report.md"))
	switch {
	case errors.Is(err, fs.ErrNotExist) && *id == "":
		if _, lerr := os.Lstat(filepath.Join(runs, "latest")); lerr != nil {
			fmt.Fprintf(stderr, "No run has finished yet. Start one with: %stripcoil run\n", d.sudo)
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

func printJSONReport(stdout, stderr io.Writer, sudo, dir, id string) int {
	rec, err := run.ReadRecord(dir)
	if err != nil {
		switch {
		case errors.Is(err, fs.ErrNotExist) && id == "":
			fmt.Fprintf(stderr, "No run has finished yet, or the latest run has no run.json. Start one with: %stripcoil run\n", sudo)
		case errors.Is(err, fs.ErrNotExist):
			fmt.Fprintf(stderr, "Run %s has no run.json.\n", id)
		default:
			fmt.Fprintf(stderr, "tripcoil report: %v\n", err)
		}
		return 2
	}
	in := report.Input{Run: rec}
	var inv inventory.Inventory
	if readOptional(filepath.Join(dir, "inventory.json"), &inv) {
		in.Inventory = &inv
	}
	var aud audit.Audit
	if readOptional(filepath.Join(dir, "audit.json"), &aud) {
		in.Audit = &aud
	}
	var idx facts.Index
	if readOptional(filepath.Join(dir, "facts", "index.json"), &idx) {
		in.Facts = &idx
	}
	if rev, err := review.Load(dir); err == nil {
		in.Review = rev
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	out := report.JSON(in)
	if out.Verdict.Line == "" {
		if md, err := os.ReadFile(filepath.Join(dir, "report.md")); err == nil {
			out.Verdict.Line, _, _ = strings.Cut(string(md), "\n")
		}
	}
	if err := enc.Encode(out); err != nil {
		return 2
	}
	return 0
}

func readOptional(path string, v any) bool {
	data, err := os.ReadFile(path)
	return err == nil && json.Unmarshal(data, v) == nil
}
