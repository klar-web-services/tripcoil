package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/config"
	"github.com/klar-web-services/tripcoil/internal/run"
	"github.com/klar-web-services/tripcoil/internal/zosia"
)

const testZosiaKey = "test:X9R2M7XkP8p7rRv75CT-rLF12dTUow8Wbb0wY28LRGs"

func zosiaTestDeps(t *testing.T, send func(context.Context, zosia.Request) (zosia.Result, error)) deps {
	d := testDeps(t, sampleInventory(), nil)
	d.zosiaSecret = func(string) (string, bool, error) { return "zosia_x", true, nil }
	d.machineKey = func() (string, error) { return "0123456789abcdef0123456789abcdef", nil }
	d.sendZosia = send
	return d
}

func writeZosiaConfig(t *testing.T, d deps) {
	t.Helper()
	cfg := "version: 1\nreview:\n  agent: none\nzosia:\n  key: " + testZosiaKey + "\n"
	if err := os.WriteFile(d.configPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRunSendsItsReportToZosia(t *testing.T) {
	var got zosia.Request
	d := zosiaTestDeps(t, func(_ context.Context, r zosia.Request) (zosia.Result, error) {
		got = r
		return zosia.Result{URL: "https://zosiasec.com/app/reports/1"}, nil
	})
	writeZosiaConfig(t, d)
	var out, errb bytes.Buffer
	if code := dispatch([]string{"run"}, &out, &errb, d); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	if !strings.Contains(errb.String(), "Zosia: report sent: https://zosiasec.com/app/reports/1\n") || strings.Contains(out.String(), "Zosia:") {
		t.Fatalf("stdout %q stderr %q", out.String(), errb.String())
	}
	var rep struct {
		Verdict run.Verdict `json:"verdict"`
		Run     run.Record  `json:"run"`
	}
	if err := json.Unmarshal(got.Report, &rep); err != nil {
		t.Fatal(err)
	}
	src := got.Source.(map[string]any)
	if got.Kind != "tripcoil" || got.Secret != "zosia_x" || src["machineKey"] != "0123456789abcdef0123456789abcdef" || src["intervalSeconds"] != 21600 ||
		rep.Verdict.Code != "audit_only" || !strings.HasPrefix(rep.Verdict.Line, "⚠️ Audit only (") || rep.Run.RunID != runID {
		t.Fatalf("request %+v report %+v", got, rep)
	}
	st, _ := run.ReadState(d.stateDir)
	if st.Zosia == nil || st.Zosia.LastURL != "https://zosiasec.com/app/reports/1" || st.Zosia.LastError != nil || st.Zosia.LastRun != runID {
		t.Fatalf("state %+v", st.Zosia)
	}
}

func TestFailedSendChangesNothingButState(t *testing.T) {
	d := zosiaTestDeps(t, func(context.Context, zosia.Request) (zosia.Result, error) {
		return zosia.Result{}, &zosia.Error{Code: "BAD_SECRET", Message: "This secret is unknown or was revoked."}
	})
	writeZosiaConfig(t, d)
	var out, errb bytes.Buffer
	if code := dispatch([]string{"run"}, &out, &errb, d); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if rec := readRecord(t, d.stateDir); rec.Status != run.Complete || len(rec.Errors) != 0 || len(rec.Warnings) != 0 {
		t.Fatalf("run.json %+v", rec)
	}
	if !strings.Contains(errb.String(), "Zosia: report not sent (BAD_SECRET): This secret is unknown or was revoked.\n") || strings.Contains(errb.String(), "zosia_x") {
		t.Fatalf("stderr %q", errb.String())
	}
	if st, _ := run.ReadState(d.stateDir); st.Zosia == nil || st.Zosia.LastError == nil || st.Zosia.LastError.Code != "BAD_SECRET" {
		t.Fatalf("state %+v", st.Zosia)
	}
}

func TestRunWithoutSecretFileSendsNothing(t *testing.T) {
	d := zosiaTestDeps(t, func(context.Context, zosia.Request) (zosia.Result, error) {
		t.Fatal("sent")
		return zosia.Result{}, nil
	})
	d.zosiaSecret = func(string) (string, bool, error) { return "", false, nil }
	var out, errb bytes.Buffer
	dispatch([]string{"run"}, &out, &errb, d)
	if st, _ := run.ReadState(d.stateDir); st.Zosia != nil || strings.Contains(errb.String(), "Zosia:") {
		t.Fatalf("state %+v stderr %q", st.Zosia, errb.String())
	}
}

func TestReadZosiaSecret(t *testing.T) {
	file := func(fi config.FileInfo, err error) config.StatFunc {
		return func(string) (config.FileInfo, error) { return fi, err }
	}
	read := func(s string) func(string) ([]byte, error) {
		return func(string) ([]byte, error) { return []byte(s), nil }
	}
	safe := config.FileInfo{UID: 0, Mode: 0o600, Regular: true}
	for _, c := range []struct {
		name      string
		stat      config.StatFunc
		content   string
		secret    string
		connected bool
		err       string
	}{
		{"missing", file(config.FileInfo{}, fs.ErrNotExist), "", "", false, ""},
		{"safe", file(safe, nil), " zosia_abc\n", "zosia_abc", true, ""},
		{"readable by others", file(config.FileInfo{UID: 0, Mode: 0o644, Regular: true}, nil), "zosia_abc", "", true, "must not be readable by group or others"},
		{"not root's", file(config.FileInfo{UID: 1000, Mode: 0o600, Regular: true}, nil), "zosia_abc", "", true, "must be owned by root"},
		{"empty", file(safe, nil), "\n", "", true, "is empty"},
	} {
		secret, connected, err := readZosiaSecret("/etc/tripcoil/zosia.secret", c.stat, read(c.content))
		if secret != c.secret || connected != c.connected || (c.err == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.err)) {
			t.Errorf("%s: %q %v %v", c.name, secret, connected, err)
		}
	}
	if _, connected, _ := readZosiaSecret("", nil, nil); connected {
		t.Error("an empty secretFile is connected")
	}
}
