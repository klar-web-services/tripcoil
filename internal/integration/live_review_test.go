//go:build live

package integration

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klar-web-services/tripcoil/internal/agent"
	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/config"
	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/probe"
	"github.com/klar-web-services/tripcoil/internal/review"
	"github.com/klar-web-services/tripcoil/internal/run"
)

// The probe runs the binary that runs the review, here this test binary, as "sandbox-probe".
func init() {
	if len(os.Args) == 3 && os.Args[1] == "sandbox-probe" {
		os.Exit(probe.Main(os.Args[2:], os.Stdout, os.Stderr))
	}
}

// liveState makes a state folder of its own, owned by root and outside /home and /tmp like the
// real one, with one run folder that holds a two-finding audit.json.
func liveState(t *testing.T) (state, runDir string, aud *audit.Audit, inv *inventory.Inventory) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, ok := run.AgentGID(); !ok {
		t.Skip("needs the agent's user: useradd --system --user-group --no-create-home --shell /usr/sbin/nologin " + agent.UserName)
	}
	state = "/var/lib/tripcoil-live-test"
	if err := os.RemoveAll(state); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(state) })
	if err := os.MkdirAll(filepath.Join(state, "cache"), 0o700); err != nil {
		t.Fatal(err)
	}
	os.Chmod(state, 0o755)
	runDir, err := run.CreateFolder(state, "20261115T061500Z-0001")
	if err != nil {
		t.Fatal(err)
	}
	aud = &audit.Audit{Findings: []audit.Finding{{ID: "f:0000000000000001", Items: []string{"proc:aaaa"}}, {ID: "f:0000000000000002", Items: []string{"proc:bbbb"}}}}
	aud.Findings[0].Vulnerability.ID, aud.Findings[0].Package.Name, aud.Findings[0].Package.Version = "CVE-2021-44228", "log4j-core", "2.14.1"
	aud.Findings[1].Vulnerability.ID, aud.Findings[1].Package.Name, aud.Findings[1].Package.Version = "CVE-2011-3389", "openssl", "3.0.15"
	inv = &inventory.Inventory{Items: []inventory.Item{{ID: "proc:aaaa"}, {ID: "proc:bbbb"}}}
	if err := run.WriteJSON(filepath.Join(runDir, "audit.json"), aud, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := run.WriteJSON(filepath.Join(runDir, "inventory.json"), inv, 0o640); err != nil {
		t.Fatal(err)
	}
	return state, runDir, aud, inv
}

// TestLiveSandbox runs the stub CLI through the sandbox of the machine it runs on: its systemd
// or bubblewrap, its nftables with the host's own firewall rules, its resolver. Build the stub
// next to the test binary first:
//
//	go build -o stubcli ./internal/integration/testdata/stubcli
//	go test -c -tags live -o live.test ./internal/integration/ && sudo ./live.test -test.v -test.run TestLiveSandbox
func TestLiveSandbox(t *testing.T) {
	state, runDir, aud, inv := liveState(t)
	src := filepath.Join(filepath.Dir(os.Args[0]), "stubcli")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("build the stub first (go build -o stubcli ./internal/integration/testdata/stubcli): %v", err)
	}
	bin := filepath.Join(state, "bin")
	os.Mkdir(bin, 0o755)
	if err := os.WriteFile(filepath.Join(bin, "claude"), data, 0o755); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "0.0.0.0:7777") // 127.0.0.2 is allowed, 127.0.0.1 is not
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	cfg := config.Default()
	cfg.Review.Command, cfg.Review.Timeout, cfg.Review.AllowAddresses = filepath.Join(bin, "claude"), config.Duration(2*time.Minute), []string{"127.0.0.2"}
	out, err := agent.New(cfg, state, "/etc/tripcoil").Review(context.Background(), runDir)
	if err != nil {
		probe, _ := os.ReadFile(filepath.Join(runDir, "agent", "probe.json"))
		t.Fatalf("%v\nprobe: %s", err, probe)
	}
	rev, _, err := review.Validate(out.Data, out.Entries, aud, inv)
	if err != nil {
		t.Fatal(err)
	}
	const want = "write-etc=read-only-file-system marker=absent dns=ok allowed=connected blocked=connection-refused pids="
	if !strings.HasPrefix(rev.Summary, want) || len(rev.Findings) != 2 {
		t.Fatalf("summary %q, %d entries", rev.Summary, len(rev.Findings))
	}
	probe, _ := os.ReadFile(filepath.Join(runDir, "agent", "probe.json"))
	t.Logf("%s: %s; warnings %v\nprobe: %s", out.CLI, rev.Summary, out.Warnings, probe)
}

// TestLiveReview runs the agent configured in /etc/tripcoil/tripcoil.yaml, with its credentials,
// on a two-finding audit. It needs the CLI installed system-wide and costs a little.
//
//	go test -c -tags live -o live.test ./internal/integration/ && sudo ./live.test -test.v -test.run TestLiveReview
func TestLiveReview(t *testing.T) {
	cfg, err := config.Load(config.DefaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Review.Agent == "none" {
		t.Skip("review.agent is none")
	}
	state, runDir, aud, inv := liveState(t)
	start := time.Now()
	out, err := agent.New(cfg, state, filepath.Dir(config.DefaultPath)).Review(context.Background(), runDir)
	if err != nil {
		stderr, _ := os.ReadFile(filepath.Join(runDir, "agent", "stderr"))
		t.Fatalf("%v\nstderr (end): %s", err, stderr[max(0, len(stderr)-2000):])
	}
	rev, warns, err := review.Validate(out.Data, out.Entries, aud, inv)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s in %v: %d entries, not reviewed %v, warnings %v %v\n%s", out.CLI, time.Since(start).Round(time.Second),
		len(rev.Findings), rev.NotReviewed, warns, out.Warnings, rev.Summary)
}
