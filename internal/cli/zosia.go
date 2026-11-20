package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
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
	src := map[string]any{"machineKey": machine, "intervalSeconds": int(cfg.Interval.Std() / time.Second)}
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
