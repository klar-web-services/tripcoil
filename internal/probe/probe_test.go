package probe

import (
	"bytes"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func setup(t *testing.T) (*Setup, string) {
	state := t.TempDir()
	run := filepath.Join(state, "runs", "20261115T061500Z-3fa2")
	for _, d := range []string{"cache", "etc-tripcoil", run} {
		if err := os.MkdirAll(filepath.Join(state, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Leftovers of a probe a killed Tripcoil did not clean up.
	for _, p := range []string{"etc-tripcoil/.probe-0123456789ab", "cache/.probe-0123456789ab", ".probe-0123456789ab-w/file", "runs/.probe-0123456789ab/run.json"} {
		os.MkdirAll(filepath.Join(state, filepath.Dir(p)), 0o755)
		os.WriteFile(filepath.Join(state, p), nil, 0o644)
	}
	os.MkdirAll(run, 0o755)
	s, err := Prepare(state, filepath.Join(state, "etc-tripcoil"), run, "", os.Getuid(), os.Getgid(),
		[]netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("fe80::1")}, []netip.Addr{netip.MustParseAddr("127.0.0.53"), netip.MustParseAddr("10.53.0.1"), netip.MustParseAddr("1.1.1.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, state
}

// Outside the sandbox the probe reaches everything root prepared: each check it makes inside the
// sandbox is only blocked there (spec section 14).
func TestRunOutsideSandbox(t *testing.T) {
	s, state := setup(t)
	a := s.Args
	for _, p := range []string{"etc-tripcoil/.probe-0123456789ab", "cache/.probe-0123456789ab", ".probe-0123456789ab-w", "runs/.probe-0123456789ab"} {
		if _, err := os.Lstat(filepath.Join(state, p)); err == nil {
			t.Errorf("stale %s not removed", p)
		}
	}
	if len(a.Reads) != 3 || len(a.Writes) != 1 || a.RootPID != os.Getpid() || a.RunID != "20261115T061500Z-3fa2" ||
		!slices.Contains(a.Private, "/tmp/"+filepath.Base(a.Reads[0])) {
		t.Fatalf("args %+v", a)
	}
	port := strings.TrimPrefix(a.TCP[0], "127.0.0.1:")
	wantTCP := []string{"127.0.0.1:" + port, "127.0.0.53:" + port, "169.254.169.254:80"}
	if l, err := net.Listen("tcp6", "[::1]:0"); err == nil {
		l.Close()
		wantTCP = []string{"127.0.0.1:" + port, "[::1]:" + port, "127.0.0.53:" + port, "169.254.169.254:80"}
	}
	// The resolver on the LAN gets UDP only: it would refuse a TCP connect by itself.
	wantUDP := append(slices.Clone(wantTCP[:len(wantTCP)-1]), "10.53.0.1:"+port, "169.254.169.254:80")
	if !slices.Equal(a.TCP, wantTCP) || !slices.Equal(a.UDP, wantUDP) {
		t.Fatalf("tcp %v udp %v, want %v %v", a.TCP, a.UDP, wantTCP, wantUDP)
	}
	if !a.ClearKeyrings {
		t.Error("the agent's keyrings are not cleared")
	}
	a.ClearKeyrings = false      // they are this user's here
	a.TCP = a.TCP[:len(a.TCP)-1] // 169.254.169.254 and the LAN resolver may not answer here
	a.UDP = a.UDP[:len(a.UDP)-2]
	checks := Run(a)
	n := 3 + 1 + len(a.Private) + 1 + 1 + len(a.TCP) + len(a.UDP)
	if len(checks) != n {
		t.Fatalf("got %d checks: %+v", len(checks), checks)
	}
	for _, c := range checks {
		if c.Blocked && !slices.Contains(a.Private, c.Target) {
			t.Errorf("blocked outside the sandbox: %+v", c)
		}
	}
	data, _ := json.Marshal(checks)
	if f := Failures(a, data); len(f) != n-len(a.Private) || !strings.HasPrefix(f[0], "read "+state) || !strings.Contains(f[4], "sees .probe-") {
		t.Errorf("failures %q", f)
	}
	// What it wrote into /tmp shows on the host. A file of another user there does not count:
	// the names are on the probe's command line.
	if l := s.Leaked(); !slices.Contains(l, "write "+a.Private[0]+": it outlived the sandbox") {
		t.Errorf("leaked %q", l)
	}
	s.agentUID++
	if l := s.Leaked(); len(l) != 0 {
		t.Errorf("another user's files count: %q", l)
	}
	s.Close()
	for _, p := range append(append(a.Reads, filepath.Dir(a.Reads[2]), filepath.Dir(a.Writes[0])), a.Private...) {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("%s left behind", p)
		}
	}
}

func TestChecksBlocked(t *testing.T) {
	dir := t.TempDir()
	closed, _ := net.Listen("tcp4", "127.0.0.1:0")
	addr := closed.Addr().String()
	closed.Close() // nothing listens: refused at once, as the table's reset is
	a := Args{Reads: []string{filepath.Join(dir, "missing")}, Writes: []string{filepath.Join(dir, "no/such/dir")},
		Runs: dir, RunID: "", RootPID: 0, TCP: []string{addr}}
	os.Mkdir(filepath.Join(dir, "own"), 0o755)
	a.Runs, a.RunID = dir, "own"
	checks := Run(a)
	for _, c := range checks {
		if !c.Blocked {
			t.Errorf("not blocked: %+v", c)
		}
	}
	data, _ := json.Marshal(checks)
	if f := Failures(a, data); len(f) != 0 {
		t.Errorf("failures %q", f)
	}
}

func TestHomeCheck(t *testing.T) {
	if c := homeCheck("/proc"); c.Blocked || c.Result != "not a tmpfs" {
		t.Errorf("/proc: %+v", c)
	}
	if c := homeCheck("/no/such/home"); c.Blocked || c.Result != "no such file or directory" {
		t.Errorf("missing: %+v", c)
	}
	if c := homeCheck("/dev/shm"); c.Blocked != (c.Result == "a tmpfs it can write to") {
		t.Errorf("/dev/shm: %+v", c)
	}
}

func TestFailures(t *testing.T) {
	a := Args{Reads: []string{"/etc/tripcoil/.probe-1"}, UDP: []string{"127.0.0.1:9"}}
	if f := Failures(a, []byte("bwrap: setting up uid map: Permission denied")); len(f) != 1 || !strings.Contains(f[0], "not readable") {
		t.Errorf("got %q", f)
	}
	out := `[{"check":"read","target":"/etc/tripcoil/.probe-1","result":"no such file or directory","blocked":true}]`
	if f := Failures(a, []byte(out)); len(f) != 1 || f[0] != "the probe made 1 checks, expected 2" {
		t.Errorf("got %q", f)
	}
	out = `[{"check":"read","target":"/etc/tripcoil/.probe-1","result":"succeeded","blocked":false},{"check":"udp","target":"127.0.0.1:9","result":"operation not permitted","blocked":true}]`
	if f := Failures(a, []byte(out)); !slices.Equal(f, []string{"read /etc/tripcoil/.probe-1: succeeded"}) {
		t.Errorf("got %q", f)
	}
}

func TestMainArgs(t *testing.T) {
	var out, errb bytes.Buffer
	if Main(nil, &out, &errb) != 2 || Main([]string{"{"}, &out, &errb) != 2 || out.Len() != 0 || !strings.Contains(errb.String(), "expects one JSON argument") {
		t.Errorf("bad arguments accepted: %q %q", out.String(), errb.String())
	}
}
