package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/buildinfo"
	"github.com/klar-web-services/tripcoil/internal/config"
	"github.com/klar-web-services/tripcoil/internal/dockerapi"
	"github.com/klar-web-services/tripcoil/internal/grype"
	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/kernelcna"
	"github.com/klar-web-services/tripcoil/internal/osrel"
	"github.com/klar-web-services/tripcoil/internal/pkgtool"
	"github.com/klar-web-services/tripcoil/internal/problem"
	"github.com/klar-web-services/tripcoil/internal/procfs"
	"github.com/klar-web-services/tripcoil/internal/report"
	"github.com/klar-web-services/tripcoil/internal/run"
)

const runUsage = `Usage: tripcoil run [--json]

Run once now, as root, and write an evidence folder to /var/lib/tripcoil/runs/<run ID>/.
This build runs the Inventory and the Audit; the AI Review comes in a later build.

Flags:
`

// noReview says why reports are audit-only in this build.
const noReview = "the AI review is not part of this build"

// collectHost inventories the real host.
func collectHost(ctx context.Context, cacheDir string) (*inventory.Inventory, error) {
	rel, err := osrel.Read("/")
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	return inventory.Collect(ctx, inventory.Deps{
		Root:       "/",
		Proc:       procfs.FS{Root: "/"},
		Release:    rel,
		Tool:       pkgtool.New(rel.Family().PackageType(), pkgtool.Exec),
		DockerHost: os.Getenv("DOCKER_HOST"),
		Connect:    func(socket string) inventory.DockerAPI { return dockerapi.New(socket) },
		CacheDir:   cacheDir,
		Hostname:   host,
		Arch:       runtime.GOARCH,
	})
}

func runRun(args []string, stdout, stderr io.Writer, d deps) int {
	fs := flag.NewFlagSet("tripcoil run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "print run.json to stdout (logs go to stderr)")
	fs.Usage = func() {
		fmt.Fprint(stderr, runUsage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tripcoil run: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if d.euid() != 0 {
		fmt.Fprintln(stderr, "tripcoil run must run as root (try: sudo tripcoil run)")
		return 2
	}
	// As light on the host as a scheduled run, and so are the Grype processes it starts.
	if err := d.lowerPriority(); err != nil {
		fmt.Fprintf(stderr, "tripcoil: cannot lower the run's priority: %s\n", strings.ReplaceAll(err.Error(), "\n", "; "))
	}
	cfg, err := config.Load(d.configPath)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", problem.ConfigInvalid, err)
		return 2
	}
	if cfg.Missing {
		fmt.Fprintf(stderr, "%s does not exist yet, so the defaults apply.\n", cfg.Path)
	}
	unlock, err := run.Lock(d.stateDir, func() { fmt.Fprintln(stderr, "Waiting for another tripcoil run to finish...") })
	if err != nil {
		fmt.Fprintf(stderr, "cannot take the run lock in %s: %v\n", d.stateDir, err)
		return 2
	}
	defer unlock()
	// Signals are caught only after the lock is held: Ctrl-C while waiting for it just ends tripcoil.
	ctx, stop := d.interrupts()
	defer stop()
	go func() { <-ctx.Done(); stop() }() // after the first signal, a second one ends tripcoil at once

	start := d.now()
	id, err := run.NewID(start, d.random)
	if err != nil {
		fmt.Fprintf(stderr, "cannot make a run ID: %v\n", err)
		return 2
	}
	dir, err := run.CreateFolder(d.stateDir, id)
	if err != nil {
		fmt.Fprintf(stderr, "%s: cannot create the run folder: %v\n", problem.RunFolderUnwritable, err)
		return 2
	}
	rec := run.NewRecord(id, start, "manual", map[string]string{"tripcoil": buildinfo.Version, "grype": grype.Version})
	cacheDir := filepath.Join(d.stateDir, "cache")
	write := func(name string, v any) error {
		err := run.WriteJSON(filepath.Join(dir, name), v, 0o640)
		if err != nil {
			rec.Add(problem.New(problem.Error, problem.RunFolderUnwritable, "", "cannot write %s: %v", name, err))
		}
		return err
	}

	inv, err := d.collect(ctx, cacheDir)
	switch {
	case ctx.Err() != nil:
		rec.Interrupt(d.now(), "inventory")
		if inv != nil { // what was raised before the signal still counts
			rec.Add(inv.Errors...)
			rec.Add(inv.Warnings...)
			rec.Add(inv.Notices...)
		}
		rec.Stages["audit"] = run.StageSkipped
	case err != nil:
		rec.Stages["inventory"] = run.StageFailed
		rec.Add(problem.New(problem.Error, problem.InventoryFailed, "inventory", "cannot inventory the host: %v", err))
	default:
		rec.Stages["inventory"] = inv.Status()
		rec.Add(inv.Errors...)
		rec.Add(inv.Warnings...)
		rec.Add(inv.Notices...)
	}
	if inv != nil {
		rec.Counts["items"], rec.Counts["origins"] = len(inv.Items), len(inv.Origins)
		if write("inventory.json", inv) != nil && rec.Status != run.Interrupted {
			rec.Stages["inventory"] = run.StageFailed
		}
	}

	var aud *audit.Audit
	switch {
	case rec.Status == run.Interrupted:
	case inv == nil:
		rec.Stages["audit"] = run.StageSkipped
	default:
		aud = d.audit(ctx, inv, cacheDir, dir, cfg)
		if ctx.Err() != nil {
			rec.Interrupt(d.now(), "audit")
			for _, e := range aud.Errors {
				if e.Code != problem.Interrupted { // rec.Interrupt added one for the run
					rec.Add(e)
				}
			}
			rec.Add(aud.Warnings...)
		} else {
			rec.Stages["audit"] = auditStage(aud.Status)
			rec.Add(aud.Errors...)
			rec.Add(aud.Warnings...)
		}
		countFindings(rec, aud)
		if write("audit.json", aud) != nil && rec.Status != run.Interrupted {
			rec.Stages["audit"] = run.StageFailed
		}
	}
	rec.Counts["coverageGaps"] = len(report.Gaps(inv, aud))

	if rec.Status != run.Interrupted {
		rec.Finish(d.now())
	}
	md := report.Render(report.Input{Run: rec, Inventory: inv, Audit: aud, NoReview: noReview})
	if err := run.WriteFile(filepath.Join(dir, "report.md"), []byte(md), 0o640); err != nil {
		rec.Add(problem.New(problem.Error, problem.RunFolderUnwritable, "", "cannot write report.md: %v", err))
		if rec.Status != run.Interrupted {
			rec.Status, rec.ExitCode = run.Failed, 2
		}
	}
	if err := run.WriteJSON(filepath.Join(dir, "run.json"), rec, 0o640); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", problem.RunFolderUnwritable, err)
		return 2
	}
	if rec.Status != run.Interrupted { // latest keeps pointing at the last finished run
		if err := run.UpdateLatest(d.stateDir, "latest", id); err != nil {
			fmt.Fprintf(stderr, "tripcoil: cannot update runs/latest: %v\n", err) // only a pointer; run.json stands
		}
	}
	return printRun(stdout, rec, dir, *jsonOut)
}

// auditHost audits the Inventory with the pinned Grype and the kernel CNA data.
func auditHost(ctx context.Context, inv *inventory.Inventory, cacheDir, runDir string, cfg config.Config) *audit.Audit {
	rel, _ := osrel.Read("/")
	return audit.Run(ctx, audit.Deps{
		Root:     "/",
		CacheDir: cacheDir,
		RunDir:   runDir,
		Family:   rel.Family(),
		MaxAge:   time.Duration(cfg.Audit.MaxDatabaseAgeHours) * time.Hour,
		Now:      time.Now,
		Grype:    audit.NewGrype(cacheDir),
		Kernel:   kernelcna.NewSource(cacheDir),
		Proc:     procfs.FS{Root: "/"},
		Images:   dockerImages(os.Getenv("DOCKER_HOST")),
	}, inv)
}

// dockerImages is the Docker daemon at the socket the Inventory reads (DOCKER_HOST, or the
// default), for the Audit to check that it still has an image before Grype scans it. It is nil
// when DOCKER_HOST is not a unix socket: the Inventory then reads no containers, so there are no
// images to scan.
func dockerImages(dockerHost string) audit.Images {
	socket, err := dockerapi.Socket(dockerHost)
	if err != nil {
		return nil
	}
	return dockerapi.New(socket)
}

func auditStage(status string) string {
	switch status {
	case audit.Complete:
		return run.StageOK
	case audit.Partial:
		return run.StagePartial
	}
	return run.StageFailed
}

func countFindings(rec *run.Record, aud *audit.Audit) {
	rec.Counts["findings"] = len(aud.Findings)
	for _, t := range audit.Tiers {
		rec.Counts["findings"+titleCase(t)] = 0
	}
	for _, f := range aud.Findings {
		rec.Counts["findings"+titleCase(f.Risk)]++
	}
	if !aud.Grype.DBBuilt.IsZero() {
		rec.Versions["grypeDB"] = aud.Grype.DBBuilt.UTC().Format(time.RFC3339)
	}
	if k := aud.KernelData; k != nil {
		rec.Versions["kernelData"] = k.Checked.UTC().Format(time.RFC3339)
		rec.Versions["kernelDataCommit"] = k.Commit
	}
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return string(s[0]-'a'+'A') + s[1:]
}

// printRun prints run.json (--json) or a short summary, and returns the run's exit code.
func printRun(stdout io.Writer, rec *run.Record, dir string, asJSON bool) int {
	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rec); err != nil {
			return 2
		}
		return rec.ExitCode
	}
	fmt.Fprintf(stdout, "Run %s: %s. %s, %s, %s, %s.\n", rec.RunID, rec.Status, plural(rec.Counts["items"], "item"),
		plural(rec.Counts["origins"], "origin"), plural(rec.Counts["findings"], "finding"), plural(rec.Counts["coverageGaps"], "coverage gap"))
	for _, e := range rec.Errors {
		fmt.Fprintf(stdout, "  error %s: %s\n", e.Code, oneLine(e.Message))
	}
	fmt.Fprintf(stdout, "Evidence: %s\nRead the report with: sudo tripcoil report --run %s\n", dir, rec.RunID)
	return rec.ExitCode
}

// oneLine replaces control and Unicode format characters (bidi controls, zero-width characters),
// which text from the host may carry, with spaces.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, s)
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}
