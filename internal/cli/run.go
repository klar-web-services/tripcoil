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
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/buildinfo"
	"github.com/klar-web-services/tripcoil/internal/config"
	"github.com/klar-web-services/tripcoil/internal/dockerapi"
	"github.com/klar-web-services/tripcoil/internal/facts"
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

const runUsage = `Usage: tripcoil run [--json] [--no-review] [--force-review]

Run once now, as root, and write an evidence folder to /var/lib/tripcoil/runs/<run ID>/.

Flags:
`

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
	noReviewFlag := fs.Bool("no-review", false, "skip the AI review; the report is audit-only")
	forceReview := fs.Bool("force-review", false, "review even when nothing changed since the last review")
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
	if *noReviewFlag && *forceReview {
		fmt.Fprintln(stderr, "tripcoil run: --no-review and --force-review exclude each other")
		return 2
	}
	if d.euid() != 0 {
		fmt.Fprintln(stderr, "tripcoil run must run as root (try: sudo tripcoil run)")
		return 2
	}
	if code, ran, err := d.enterScope(args); ran {
		return code
	} else if err != nil {
		fmt.Fprintf(stderr, "tripcoil: cannot move the run into a transient scope, so only its nice level makes it light: %v\n", err)
	}
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
	go func() { <-ctx.Done(); stop() }()

	rec, dir, err := execute(ctx, d, cfg, "manual", *noReviewFlag, *forceReview, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return printRun(stdout, d.sudo, rec, dir, *jsonOut)
}

func execute(ctx context.Context, d deps, cfg config.Config, trigger string, noReview, force bool, stderr io.Writer) (*run.Record, string, error) {
	start := d.now()
	id, err := run.NewID(start, d.random)
	if err != nil {
		return nil, "", fmt.Errorf("cannot make a run ID: %v", err)
	}
	dir, err := run.CreateFolder(d.stateDir, id)
	if err != nil {
		return nil, "", fmt.Errorf("%s: cannot create the run folder: %v", problem.RunFolderUnwritable, err)
	}
	rec := run.NewRecord(id, start, trigger, map[string]string{"tripcoil": buildinfo.Version, "grype": grype.Version})
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
		if inv != nil {
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
				if e.Code != problem.Interrupted {
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
	var idx *facts.Index
	switch {
	case rec.Status == run.Interrupted:
	case inv == nil:
		rec.Stages["facts"] = run.StageSkipped
	default:
		idx, err = d.facts(ctx, inv, dir, cfg)
		switch {
		case ctx.Err() != nil:
			rec.Interrupt(d.now(), "facts")
		case err != nil:
			rec.Stages["facts"] = run.StageFailed
			rec.Add(problem.New(problem.Error, problem.RunFolderUnwritable, "", "cannot write facts/: %v", err))
		default:
			rec.Stages["facts"] = run.StageOK
		}
	}

	rv := reviewRun{d: d, cfg: cfg, rec: rec, dir: dir, inv: inv, aud: aud, idx: idx, noReview: noReview, force: force}
	rev, why := rv.run(ctx)
	rec.Counts["coverageGaps"] = len(report.Gaps(inv, aud, idx))

	if rec.Status != run.Interrupted {
		rec.Finish(d.now())
		if slices.ContainsFunc(rec.Errors, func(e problem.Problem) bool { return e.Code == problem.RunFolderUnwritable }) {
			rec.Status, rec.ExitCode = run.Failed, 2
		}
	}
	in := report.Input{Run: rec, Inventory: inv, Audit: aud, Facts: idx, Review: rev, Reach: rv.reach, NoReview: why, Agent: rv.agentName()}
	md := report.Render(in)
	verdict := report.VerdictOf(in, md)
	rec.Verdict = &verdict
	if err := run.WriteFile(filepath.Join(dir, "report.md"), []byte(md), 0o640); err != nil {
		rec.Add(problem.New(problem.Error, problem.RunFolderUnwritable, "", "cannot write report.md: %v", err))
		if rec.Status != run.Interrupted {
			rec.Status, rec.ExitCode = run.Failed, 2
		}
	}
	if err := run.WriteJSON(filepath.Join(dir, "run.json"), rec, 0o640); err != nil {
		return nil, "", fmt.Errorf("%s: %v", problem.RunFolderUnwritable, err)
	}
	if rec.Status != run.Interrupted {
		if err := run.UpdateLatest(d.stateDir, "latest", id); err != nil {
			fmt.Fprintf(stderr, "tripcoil: cannot update runs/latest: %v\n", err)
		}
		if rec.Reviewed {
			if err := run.UpdateLatest(d.stateDir, "latest-reviewed", id); err != nil {
				fmt.Fprintf(stderr, "tripcoil: cannot update runs/latest-reviewed: %v\n", err)
			}
		}
	}
	st, err := run.ReadState(d.stateDir)
	if err != nil {
		fmt.Fprintf(stderr, "tripcoil: %s is damaged and starts over: %v\n", filepath.Join(d.stateDir, "state.json"), err)
	}
	st.Record(rec)
	if err := run.WriteState(d.stateDir, st); err != nil {
		fmt.Fprintf(stderr, "tripcoil: cannot write state.json: %v\n", err)
	}
	if _, err := run.Prune(d.stateDir, int(cfg.Retention.KeepRuns)); err != nil {
		fmt.Fprintf(stderr, "tripcoil: cannot remove old run folders: %v\n", err)
	}
	if rec.Status != run.Interrupted && ctx.Err() == nil {
		reportToZosia(ctx, d, cfg, in, stderr)
	}
	return rec, dir, nil
}

func factsHost(ctx context.Context, inv *inventory.Inventory, runDir string, cfg config.Config) (*facts.Index, error) {
	d := facts.Deps{Root: "/", Run: facts.Exec, LookPath: facts.LookPath, Interfaces: facts.SystemInterfaces, InternetPorts: cfg.Exposure.Ports()}
	if socket, err := dockerapi.Socket(os.Getenv("DOCKER_HOST")); err == nil {
		d.Docker, d.DockerSocket = dockerapi.New(socket), socket
	}
	return facts.Collect(ctx, d, inv, runDir)
}

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

func printRun(stdout io.Writer, sudo string, rec *run.Record, dir string, asJSON bool) int {
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
	fmt.Fprintf(stdout, "Evidence: %s\nRead the report with: %stripcoil report --run %s\n", dir, sudo, rec.RunID)
	return rec.ExitCode
}

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
