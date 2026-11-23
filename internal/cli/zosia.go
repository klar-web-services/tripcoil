package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/klar-web-services/tripcoil/internal/problem"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/klar-web-services/tripcoil/internal/buildinfo"
	"github.com/klar-web-services/tripcoil/internal/config"
	"github.com/klar-web-services/tripcoil/internal/report"
	"github.com/klar-web-services/tripcoil/internal/run"
	"github.com/klar-web-services/tripcoil/internal/zosia"
)

// The send runs inside the run lock, so it is capped well below the unit's TimeoutStopSec.
var zosiaPolicy = zosia.Policy{Total: 90 * time.Second, Attempts: 2, Pause: 5 * time.Second, MaxRetryAfter: 60 * time.Second}

// readZosiaSecret reads the secret file. connected is false when the file does not exist (or
// sending is off); an unsafe or empty file is connected with an error.
func readZosiaSecret(path string, stat config.StatFunc, read func(string) ([]byte, error)) (secret string, connected bool, err error) {
	if path == "" {
		return "", false, nil
	}
	if _, err := stat(path); errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if p := config.CheckRootFile(path, "zosia.secretFile", "", stat); len(p) > 0 {
		return "", true, errors.New(strings.Join(p, "; "))
	}
	data, err := read(path)
	if err != nil {
		return "", true, err
	}
	if secret = strings.TrimSpace(string(data)); secret == "" {
		return "", true, fmt.Errorf("%s is empty", path)
	}
	return secret, true, nil
}

func defaultZosiaSecret(path string) (string, bool, error) {
	return readZosiaSecret(path, config.Stat, os.ReadFile)
}

// settingsTimeout is how long fetching Zosia's settings may take. It never holds up a run for longer.
const settingsTimeout = 15 * time.Second

// settingsCopy is the copy of the last settings fetched, in the state folder.
const settingsCopy = "zosia-settings.json"

// zosiaSettings fetches what Zosia tells this machine, once, before a run. Without a Zosia secret
// there are none. When the fetch fails or its answer is no settings document, the copy of the last
// fetch counts, and the run says so; it never fails a run.
func zosiaSettings(ctx context.Context, d deps, cfg config.Config, rec *run.Record) zosia.Settings {
	secret, connected, err := d.zosiaSecret(cfg.Zosia.SecretFile)
	if !connected || err != nil || d.zosiaSettings == nil {
		return zosia.Settings{}
	}
	now, copyPath := d.now(), filepath.Join(d.stateDir, settingsCopy)
	why := ""
	url, _, err := zosia.Target(cfg.Zosia.URL, cfg.Zosia.Key)
	machine := ""
	if err == nil {
		machine, err = d.machineKey()
	}
	if err == nil {
		ctx, cancel := context.WithTimeout(ctx, settingsTimeout)
		defer cancel()
		var data []byte
		if data, err = d.zosiaSettings(ctx, url, secret, machine); err == nil {
			var s zosia.Settings
			if s, err = zosia.ParseSettings(data, now); err == nil {
				if err := run.WriteFile(copyPath, data, 0o600); err != nil {
					rec.Add(problem.New(problem.Notice, problem.ZosiaSettingsUnreachable, "", "Zosia's settings could not be kept for a run without Zosia: %v", err))
				}
				return s
			}
		}
	}
	why = oneLine(err.Error())
	if data, err := os.ReadFile(copyPath); err == nil {
		if s, err := zosia.ParseSettings(data, now); err == nil {
			rec.Add(problem.New(problem.Notice, problem.ZosiaSettingsUnreachable, "", "Zosia's settings could not be fetched (%s); the copy of the last fetch is used", why))
			return s
		}
	}
	rec.Add(problem.New(problem.Notice, problem.ZosiaSettingsUnreachable, "", "Zosia's settings could not be fetched (%s), and there is no copy of an earlier fetch", why))
	return zosia.Settings{}
}

// reportToZosia sends a finished run's report when the secret file exists. It never changes the
// run: its outcome goes to stderr (one line) and to state.json.
func reportToZosia(ctx context.Context, d deps, cfg config.Config, in report.Input, stderr io.Writer) {
	secret, connected, err := d.zosiaSecret(cfg.Zosia.SecretFile)
	if !connected {
		return
	}
	now := d.now()
	att := run.Zosia{LastAttemptAt: now, LastRun: in.Run.RunID}
	defer func() {
		st, err := run.ReadState(d.stateDir)
		if err != nil {
			return
		}
		if prev := st.Zosia; prev != nil && att.LastError != nil {
			att.LastSentAt, att.LastURL = prev.LastSentAt, prev.LastURL
		}
		st.Zosia = &att
		if err := run.WriteState(d.stateDir, st); err != nil {
			fmt.Fprintf(stderr, "tripcoil: cannot write state.json: %v\n", err)
		}
	}()
	fail := func(code, msg string) {
		att.LastError = &run.ZosiaError{Code: code, Message: msg}
		fmt.Fprintf(stderr, "Zosia: report not sent (%s): %s\n", code, msg)
	}
	if err != nil {
		fail("ZOSIA_SECRET_UNSAFE", err.Error())
		return
	}
	url, key, err := zosia.Target(cfg.Zosia.URL, cfg.Zosia.Key)
	if err != nil {
		fail("ZOSIA_KEY", err.Error())
		return
	}
	machine, err := d.machineKey()
	if err != nil {
		fail("ZOSIA_MACHINE_KEY", err.Error())
		return
	}
	payload := report.Payload(in)
	data, err := json.Marshal(payload)
	if err != nil {
		fail("PAYLOAD", err.Error())
		return
	}
	src := map[string]any{"machineKey": machine, "intervalSeconds": int(cfg.Interval.Std() / time.Second), "settingsVersion": in.SettingsVersion}
	if h := payload.Host; h != nil {
		src["hostname"], src["os"], src["kernel"] = h.Hostname, h.Distro, h.Kernel
	}
	res, err := d.sendZosia(ctx, zosia.Request{URL: url, Key: key, Secret: secret, Client: "tripcoil", Version: buildinfo.Version,
		Kind: "tripcoil", Source: src, Report: data, Now: now})
	var ze *zosia.Error
	switch {
	case errors.As(err, &ze):
		fail(ze.Code, ze.Message)
	case err != nil:
		fail("NETWORK", err.Error())
	default:
		att.LastSentAt, att.LastURL = now, res.URL
		fmt.Fprintf(stderr, "Zosia: report sent: %s\n", res.URL)
	}
}
