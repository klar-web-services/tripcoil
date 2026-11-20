package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/zosia"
)

func connectDeps(t *testing.T, waitErr error) (deps, string) {
	d := testDeps(t, nil, nil)
	d.sudo = "sudo "
	file := filepath.Join(t.TempDir(), "zosia.secret")
	if err := os.WriteFile(d.configPath, []byte("version: 1\nzosia:\n  secretFile: "+file+"\n  url: http://127.0.0.1:3000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d.zosiaSecret = func(path string) (string, bool, error) {
		data, err := os.ReadFile(path)
		return strings.TrimSpace(string(data)), err == nil, nil
	}
	d.hostInfo = func() zosia.HostInfo { return zosia.HostInfo{Hostname: "web-1", OS: "debian 13", Version: "1.2.0"} }
	d.startConnect = func(_ context.Context, url string, host zosia.HostInfo) (zosia.ConnectRequest, error) {
		if url != "http://127.0.0.1:3000" || host.Hostname != "web-1" {
			t.Errorf("started at %s for %+v", url, host)
		}
		return zosia.ConnectRequest{DeviceCode: "device-code", UserCode: "BCDF-GHJK", VerificationURI: url + "/app/connect",
			VerificationURIComplete: url + "/app/connect?code=BCDF-GHJK", ExpiresIn: 600, Interval: 5}, nil
	}
	d.waitConnect = func(_ context.Context, _ string, r zosia.ConnectRequest) (string, string, error) {
		if r.DeviceCode != "device-code" {
			t.Errorf("waited for %+v", r)
		}
		if waitErr != nil {
			return "", "", waitErr
		}
		return "zosia_new", "web-1", nil
	}
	d.pingZosia = func(_ context.Context, _, secret string) (string, error) {
		if secret != "zosia_new" {
			t.Errorf("pinged with %q", secret)
		}
		return "web-1", nil
	}
	return d, file
}

func TestZosiaConnect(t *testing.T) {
	d, file := connectDeps(t, nil)
	var out, errb bytes.Buffer
	if code := dispatch([]string{"zosia", "connect"}, &out, &errb, d); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	want := `Open this page in a browser where you are logged in to Zosia:

    http://127.0.0.1:3000/app/connect?code=BCDF-GHJK

or open http://127.0.0.1:3000/app/connect and enter the code BCDF-GHJK.
Waiting for you to approve (10 minutes at most; Ctrl-C cancels) …
✓ Connected to Zosia as "web-1". The next run sends its report.
`
	if out.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", out.String(), want)
	}
	data, _ := os.ReadFile(file)
	if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0o600 || string(data) != "zosia_new\n" {
		t.Fatalf("secret file %q %v %v", data, fi, err)
	}
	if strings.Contains(out.String()+errb.String(), "zosia_new") || strings.Contains(out.String()+errb.String(), "device-code") {
		t.Fatalf("printed a secret:\n%s%s", out.String(), errb.String())
	}

	out.Reset()
	d.startConnect = func(context.Context, string, zosia.HostInfo) (zosia.ConnectRequest, error) {
		t.Fatal("already connected")
		return zosia.ConnectRequest{}, nil
	}
	if code := dispatch([]string{"zosia", "connect"}, &out, &errb, d); code != 1 ||
		!strings.Contains(errb.String(), "Zosia is already connected ("+file+"). Use --replace to connect again.\n") {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
}

func TestZosiaConnectReplace(t *testing.T) {
	d, file := connectDeps(t, &zosia.Error{Code: "DENIED", Message: "The request was denied in Zosia."})
	os.WriteFile(file, []byte("zosia_old\n"), 0o600)
	var out, errb bytes.Buffer
	if code := dispatch([]string{"zosia", "connect", "--replace"}, &out, &errb, d); code != 1 || !strings.Contains(errb.String(), "Zosia: the request was denied.\n") {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	if data, _ := os.ReadFile(file); string(data) != "zosia_old\n" {
		t.Fatalf("a denied request replaced the secret: %q", data)
	}

	d, file = connectDeps(t, nil)
	os.WriteFile(file, []byte("zosia_old\n"), 0o600)
	out.Reset()
	if code := dispatch([]string{"zosia", "connect", "--replace"}, &out, &errb, d); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	if data, _ := os.ReadFile(file); string(data) != "zosia_new\n" || !strings.HasSuffix(out.String(), "✓ Connected to Zosia as \"web-1\". The next run sends its report.\n"+
		"The secret this replaces stays valid until you revoke it at http://127.0.0.1:3000/app/secrets.\n") {
		t.Fatalf("secret %q, stdout:\n%s", data, out.String())
	}
}

func TestZosiaConnectFailures(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{&zosia.Error{Code: "EXPIRED", Message: "nobody approved the request in time"}, "Zosia: nobody approved in time; run the command again.\n"},
		{&zosia.Error{Code: "PLAN_LIMIT", Message: "The account's plan allows 10 secrets. Revoke one in Zosia, then connect again."},
			"Zosia: The account's plan allows 10 secrets. Revoke one in Zosia, then connect again.\n"},
		{&zosia.Error{Code: "CANCELLED", Message: "cancelled"}, "Zosia: cancelled; nothing changed.\n"},
	} {
		d, file := connectDeps(t, c.err)
		var out, errb bytes.Buffer
		if code := dispatch([]string{"zosia", "connect"}, &out, &errb, d); code != 1 || !strings.HasSuffix(errb.String(), c.want) {
			t.Errorf("exit %d, stderr %q, want %q", code, errb.String(), c.want)
		}
		if _, err := os.Stat(file); err == nil {
			t.Errorf("%v wrote a secret file", c.err)
		}
	}

	d, file := connectDeps(t, nil)
	d.pingZosia = func(context.Context, string, string) (string, error) {
		return "", &zosia.Error{Code: "NETWORK", Message: "cannot reach Zosia: no route to host"}
	}
	var out, errb bytes.Buffer
	if code := dispatch([]string{"zosia", "connect"}, &out, &errb, d); code != 1 ||
		!strings.Contains(errb.String(), "Zosia: the secret is stored in "+file+", but checking it failed: cannot reach Zosia: no route to host\n") {
		t.Errorf("exit %d, stderr %q", code, errb.String())
	}

	d, _ = connectDeps(t, nil)
	os.WriteFile(d.configPath, []byte("version: 1\nzosia:\n  secretFile: \"\"\n"), 0o644)
	errb.Reset()
	if code := dispatch([]string{"zosia", "connect"}, &out, &errb, d); code != 1 || !strings.Contains(errb.String(), "zosia.secretFile is empty") {
		t.Errorf("exit %d, stderr %q", code, errb.String())
	}
}

func TestZosiaConnectRefusals(t *testing.T) {
	d, _ := connectDeps(t, nil)
	var out, errb bytes.Buffer
	for args, msg := range map[string]string{
		"zosia":               "Usage: tripcoil zosia connect",
		"zosia disconnect":    "unknown command \"disconnect\"",
		"zosia connect extra": "unexpected argument",
	} {
		errb.Reset()
		if code := dispatch(strings.Fields(args), &out, &errb, d); code != 2 || !strings.Contains(errb.String(), msg) {
			t.Errorf("%s: exit %d, stderr %q", args, code, errb.String())
		}
	}
	d.euid = func() int { return 1000 }
	errb.Reset()
	if code := dispatch([]string{"zosia", "connect"}, &out, &errb, d); code != 2 || !strings.Contains(errb.String(), "must run as root") {
		t.Fatalf("not root: exit %d, stderr %q", code, errb.String())
	}
}
