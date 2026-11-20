package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/klar-web-services/tripcoil/internal/config"
	"github.com/klar-web-services/tripcoil/internal/daemon"
	"github.com/klar-web-services/tripcoil/internal/problem"
	"github.com/klar-web-services/tripcoil/internal/run"
	"github.com/klar-web-services/tripcoil/internal/setup"
)

const statusUsage = `Usage: tripcoil status

Print the service's state, the last and next run, the last reviewed run, the failures in a row,
the age of the vulnerability data and the agent CLI, as root.
`

func runStatus(args []string, stdout, stderr io.Writer, d deps) int {
	fs := flag.NewFlagSet("tripcoil status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, statusUsage) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tripcoil status: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if d.euid() != 0 {
		fmt.Fprintln(stderr, "tripcoil status must run as root (try: sudo tripcoil status)")
		return 2
	}
	cfg, err := config.Load(d.configPath)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", problem.ConfigInvalid, err)
		return 2
	}
	st, stErr := run.ReadState(d.stateDir)
	now := d.now()
	line := func(k, v string) { fmt.Fprintf(stdout, "%-18s %s\n", k+":", v) }

	svc, err := d.service()
	running := err == nil && svc.Running
	switch {
	case err != nil:
		line("Service", err.Error())
	case running:
		line("Service", fmt.Sprintf("running (%s)", svc.Manager))
	case svc.Installed:
		line("Service", fmt.Sprintf("installed but not running (%s)", svc.Manager))
	default:
		line("Service", "not installed; set it up with: "+d.sudo+"tripcoil setup")
	}

	var last *run.Record
	if stErr != nil {
		line("State", fmt.Sprintf("state.json is damaged and starts over at the next run: %v", stErr))
	}
	if st.LastRun == "" {
		line("Last run", "none yet")
	} else {
		line("Last run", fmt.Sprintf("%s, %s, %s", st.LastRun, st.LastStatus, when(st.LastRunAt, now)))
		last, _ = run.ReadRecord(filepath.Join(d.stateDir, "runs", st.LastRun))
	}
	switch {
	case !running:
		line("Next run", "none: the service is not running")
	case daemon.Wait(st.LastRunAt, time.Time{}, cfg.Interval.Std(), now) <= 0:
		line("Next run", "due now")
	default:
		line("Next run", st.LastRunAt.Add(cfg.Interval.Std()).UTC().Format("2006-01-02 15:04 UTC"))
	}
	if st.LastReviewed == "" {
		line("Last reviewed", "none yet")
	} else {
		line("Last reviewed", fmt.Sprintf("%s, review made %s", st.LastReviewed, when(st.LastReviewedAt, now)))
	}
	line("Failures in a row", fmt.Sprint(st.ConsecutiveFailures))
	if _, connected, err := d.zosiaSecret(cfg.Zosia.SecretFile); !connected {
		line("Zosia", "not connected")
	} else if err != nil {
		line("Zosia", "secret file unusable: "+err.Error())
	} else if z := st.Zosia; z == nil {
		line("Zosia", "connected, no report sent yet")
	} else if z.LastError != nil {
		line("Zosia", fmt.Sprintf("last send failed %s: %s (%s)", when(z.LastAttemptAt, now), z.LastError.Message, z.LastError.Code))
	} else {
		line("Zosia", fmt.Sprintf("last report sent %s (%s)", when(z.LastSentAt, now), z.LastURL))
	}
	if running && !st.LastRunAt.IsZero() && now.Sub(st.LastRunAt) > 2*cfg.Interval.Std() {
		line("Warning", "no run has finished for more than two intervals; see the service's log")
	}

	version := func(key string) string {
		if last == nil {
			return ""
		}
		return last.Versions[key]
	}
	data := func(k, key, verb string) {
		t, err := time.Parse(time.RFC3339, version(key))
		if err != nil {
			line(k, "unknown until a run has used it")
			return
		}
		line(k, fmt.Sprintf("%s %s (as of the last run)", verb, when(t, now)))
	}
	data("Grype database", "grypeDB", "built")
	data("Kernel CNA data", "kernelData", "checked")
	switch cli := version("agentCli"); {
	case cfg.Review.Agent == "none":
		line("Agent CLI", "none (review.agent: none)")
	case cli != "":
		line("Agent CLI", fmt.Sprintf("%s (as of the last run)", cli))
	default:
		line("Agent CLI", fmt.Sprintf("%s, version unknown until a review has run", cfg.Review.Agent))
	}
	return 0
}

func when(t, now time.Time) string {
	age := now.Sub(t)
	var a string
	switch {
	case age < 0:
		a = "in the future"
	case age < time.Hour:
		a = fmt.Sprintf("%dm ago", int(age.Minutes()))
	case age < 48*time.Hour:
		a = fmt.Sprintf("%dh ago", int(age.Hours()))
	default:
		a = fmt.Sprintf("%dd ago", int(age.Hours()/24))
	}
	return fmt.Sprintf("%s (%s)", t.UTC().Format("2006-01-02 15:04 UTC"), a)
}

func serviceHost() (setup.Service, error) {
	return setup.NewHost("", os.Stdin, io.Discard).Service()
}
