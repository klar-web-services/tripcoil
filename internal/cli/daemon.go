package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/klar-web-services/tripcoil/internal/config"
	"github.com/klar-web-services/tripcoil/internal/daemon"
	"github.com/klar-web-services/tripcoil/internal/problem"
	"github.com/klar-web-services/tripcoil/internal/run"
)

const daemonUsage = `Usage: tripcoil daemon [--check-config]

The service's entrypoint, as root: runs once every interval (spec section 13). SIGTERM or SIGINT
stops the current run and exits; SIGHUP reloads /etc/tripcoil/tripcoil.yaml. An invalid config
exits 78, which the service does not restart; a crash (exit 2) is restarted.

Flags:
`

// configExit is the daemon's exit code for an invalid config (EX_CONFIG): the systemd unit's
// RestartPreventExitStatus, so the service is not restarted in a loop. Go itself exits 2 on a
// panic, which the service restarts.
const configExit = 78

func runDaemon(args []string, stdout, stderr io.Writer, d deps) int {
	fs := flag.NewFlagSet("tripcoil daemon", flag.ContinueOnError)
	fs.SetOutput(stderr)
	checkOnly := fs.Bool("check-config", false, "only check the config: exit 0 when it is valid, 78 when not (the OpenRC script's start check)")
	fs.Usage = func() {
		fmt.Fprint(stderr, daemonUsage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tripcoil daemon: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if d.euid() != 0 {
		fmt.Fprintln(stderr, "tripcoil daemon must run as root (it is the service's entrypoint: sudo tripcoil setup installs it)")
		return 2
	}
	cfg, err := config.Load(d.configPath)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", problem.ConfigInvalid, err)
		return configExit
	}
	if *checkOnly {
		return 0
	}
	if cfg.Missing {
		fmt.Fprintf(stdout, "%s does not exist yet, so the defaults apply.\n", cfg.Path)
	}
	if err := d.lowerPriority(); err != nil {
		fmt.Fprintf(stderr, "tripcoil: cannot lower the daemon's priority: %s\n", strings.ReplaceAll(err.Error(), "\n", "; "))
	}
	ctx, stop := d.interrupts()
	defer stop()
	last := func() time.Time {
		st, err := run.ReadState(d.stateDir)
		if err != nil {
			fmt.Fprintf(stderr, "tripcoil: state.json is damaged, so a run is due: %v\n", err)
		}
		return st.LastRunAt
	}
	s := daemon.Scheduler{
		Now:      d.now,
		After:    d.after,
		Interval: func() time.Duration { return cfg.Interval.Std() },
		Last:     last,
		Run: func(ctx context.Context) {
			unlock, err := run.LockContext(ctx, d.stateDir, func() { fmt.Fprintln(stdout, "Waiting for a manual run to finish...") })
			if err != nil {
				if ctx.Err() == nil {
					fmt.Fprintf(stderr, "tripcoil: cannot take the run lock in %s: %v\n", d.stateDir, err)
				}
				return
			}
			defer unlock()
			if daemon.Wait(last(), time.Time{}, cfg.Interval.Std(), d.now()) > 0 {
				return // a manual run finished while this one waited for the lock
			}
			rec, dir, err := execute(ctx, d, cfg, "schedule", false, false, stderr)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return
			}
			printRun(stdout, rec, dir, false)
		},
		Hangup: d.hangups(),
		Reload: func() {
			c, err := config.Load(d.configPath)
			if err != nil {
				fmt.Fprintf(stderr, "%s: %v\nThe configuration stays as it was.\n", problem.ConfigInvalid, err)
				return
			}
			cfg = c
			fmt.Fprintf(stdout, "Reloaded %s.\n", cfg.Path)
		},
		Waiting: func(at time.Time) { fmt.Fprintf(stdout, "Next run at %s.\n", at.UTC().Format(time.RFC3339)) },
	}
	fmt.Fprintf(stdout, "Tripcoil daemon started: a run every %s.\n", cfg.Interval.Std())
	s.Loop(ctx)
	fmt.Fprintln(stdout, "Tripcoil daemon stopped.")
	return 0
}
