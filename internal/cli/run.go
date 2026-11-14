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

	"github.com/klar-web-services/tripcoil/internal/buildinfo"
	"github.com/klar-web-services/tripcoil/internal/config"
	"github.com/klar-web-services/tripcoil/internal/dockerapi"
	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/osrel"
	"github.com/klar-web-services/tripcoil/internal/pkgtool"
	"github.com/klar-web-services/tripcoil/internal/problem"
	"github.com/klar-web-services/tripcoil/internal/procfs"
	"github.com/klar-web-services/tripcoil/internal/run"
)

const runUsage = `Usage: tripcoil run [--json]

Run once now, as root, and write an evidence folder to /var/lib/tripcoil/runs/<run ID>/.
This build runs the Inventory; the Audit and the AI Review come in later builds.

Flags:
`

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
	rec := run.NewRecord(id, start, "manual", map[string]string{"tripcoil": buildinfo.Version})

	inv, err := d.collect(ctx, filepath.Join(d.stateDir, "cache"))
	if ctx.Err() != nil {
		rec.Interrupt(d.now(), "inventory")
		if err := run.WriteJSON(filepath.Join(dir, "run.json"), rec, 0o640); err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", problem.RunFolderUnwritable, err)
			return 2
		}
		return printRun(stdout, rec, dir, *jsonOut) // latest keeps pointing at the last finished run
	}
	if err != nil {
		rec.Stages["inventory"] = run.StageFailed
		rec.Add(problem.New(problem.Error, problem.InventoryFailed, "inventory", "cannot inventory the host: %v", err))
	} else {
		rec.Stages["inventory"] = inv.Status()
		rec.Counts["items"], rec.Counts["origins"] = len(inv.Items), len(inv.Origins)
		rec.Add(inv.Errors...)
		rec.Add(inv.Warnings...)
		rec.Add(inv.Notices...)
		if err := run.WriteJSON(filepath.Join(dir, "inventory.json"), inv, 0o640); err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", problem.RunFolderUnwritable, err)
			return 2
		}
	}
	rec.Finish(d.now())
	if err := run.WriteJSON(filepath.Join(dir, "run.json"), rec, 0o640); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", problem.RunFolderUnwritable, err)
		return 2
	}
	if err := run.UpdateLatest(d.stateDir, "latest", id); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", problem.RunFolderUnwritable, err)
		return 2
	}
	return printRun(stdout, rec, dir, *jsonOut)
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
	fmt.Fprintf(stdout, "Run %s: %s. %s, %s.\n", rec.RunID, rec.Status, plural(rec.Counts["items"], "item"), plural(rec.Counts["origins"], "origin"))
	for _, e := range rec.Errors {
		fmt.Fprintf(stdout, "  error %s: %s\n", e.Code, e.Message)
	}
	fmt.Fprintf(stdout, "Evidence: %s\n", dir)
	return rec.ExitCode
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}
