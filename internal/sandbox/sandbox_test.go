package sandbox

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func spec(t *testing.T) Spec {
	state := t.TempDir()
	for _, d := range []string{"cache", "runs/20261115T061500Z-3fa2", "agent-home"} {
		if err := os.MkdirAll(filepath.Join(state, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return Spec{Name: "20261115T061500Z-3fa2-agent", StateDir: state, ConfigDir: filepath.Join(state, "etc-tripcoil"),
		RunDir: filepath.Join(state, "runs/20261115T061500Z-3fa2"), User: User{Name: "tripcoil-agent", UID: 990, GID: 990},
		Env: []string{"DISABLE_AUTOUPDATER=1"}, EnvFile: "/etc/tripcoil/agent.env", Timeout: 60 * time.Minute,
		MemoryMax: "2G", CPUQuota: "100%", Command: []string{"/usr/local/bin/claude", "-p", "prompt"}}
}

func TestSystemdArgs(t *testing.T) {
	s := spec(t)
	got := strings.Join(SystemdArgs(s), "\n")
	got = strings.ReplaceAll(got, s.StateDir, "/var/lib/tripcoil")
	want := `--wait
--pipe
--collect
--service-type=exec
--unit=tripcoil-review-20261115T061500Z-3fa2-agent
--uid=tripcoil-agent
--gid=tripcoil-agent
--working-directory=/var/lib/tripcoil/runs/20261115T061500Z-3fa2
-p
ProtectSystem=strict
-p
ProtectHome=yes
-p
PrivateDevices=yes
-p
ProtectProc=invisible
-p
NoNewPrivileges=yes
-p
ReadWritePaths=/var/lib/tripcoil/agent-home
-p
InaccessiblePaths=-/var/lib/tripcoil/etc-tripcoil -/var/lib/tripcoil/cache
-p
TemporaryFileSystem=/var/lib/tripcoil/runs
-p
BindReadOnlyPaths=/var/lib/tripcoil/runs/20261115T061500Z-3fa2
-p
TemporaryFileSystem=/tmp:mode=1777 /var/tmp:mode=1777 /dev/shm:mode=1777
-p
RemoveIPC=yes
-p
ReadOnlyPaths=/run
-p
SystemCallFilter=~@keyring
-p
SystemCallErrorNumber=EPERM
-p
LimitCORE=0
-p
RuntimeMaxSec=3600
-p
MemoryMax=2G
-p
CPUQuota=100%
-p
MemorySwapMax=0
-p
TasksMax=4096
-p
Nice=10
-p
IOSchedulingClass=idle
-p
EnvironmentFile=/etc/tripcoil/agent.env
-E
HOME=/var/lib/tripcoil/agent-home
-E
LANG=C.UTF-8
-E
DISABLE_AUTOUPDATER=1
--
/usr/local/bin/claude
-p
prompt`
	if got != want {
		t.Fatalf("got\n%s", got)
	}
}

func TestBwrapArgs(t *testing.T) {
	s := spec(t)
	if err := os.Mkdir(s.ConfigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(BwrapArgs(s), " ")
	got = strings.ReplaceAll(got, s.StateDir, "/var/lib/tripcoil")
	var home string
	for _, h := range []string{"/home", "/root"} {
		if exists(h) {
			home += " --tmpfs " + h
		}
	}
	want := "--ro-bind / / --dev /dev --proc /proc --tmpfs /tmp" + home +
		" --tmpfs /var/lib/tripcoil/etc-tripcoil --tmpfs /var/lib/tripcoil/cache --tmpfs /var/lib/tripcoil/runs" +
		" --ro-bind /var/lib/tripcoil/runs/20261115T061500Z-3fa2 /var/lib/tripcoil/runs/20261115T061500Z-3fa2" +
		" --bind /var/lib/tripcoil/agent-home /var/lib/tripcoil/agent-home --chdir /var/lib/tripcoil/runs/20261115T061500Z-3fa2" +
		" --unshare-pid --unshare-ipc --die-with-parent --new-session -- /usr/local/bin/claude -p prompt"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	// A hidden path that does not exist is left out: bubblewrap cannot create it on the read-only root.
	os.Remove(s.ConfigDir)
	if a := strings.Join(BwrapArgs(s), " "); strings.Contains(a, "etc-tripcoil") {
		t.Errorf("missing config dir still mounted: %s", a)
	}
}

func TestEnv(t *testing.T) {
	s := spec(t)
	s.EnvFile = filepath.Join(t.TempDir(), "agent.env")
	os.WriteFile(s.EnvFile, []byte("# credentials\nCLAUDE_CODE_OAUTH_TOKEN=\"tok en\"\n\nexport BASE='x'\n"), 0o600)
	got, err := s.env()
	want := []string{"PATH=" + Path, "HOME=" + s.Home(), "LANG=C.UTF-8", "CLAUDE_CODE_OAUTH_TOKEN=tok en", "BASE=x", "DISABLE_AUTOUPDATER=1"}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("%v %v", got, err)
	}
	os.WriteFile(s.EnvFile, []byte("just words\n"), 0o600)
	if _, err := s.env(); err == nil || !strings.Contains(err.Error(), "line 1 is not KEY=value") {
		t.Fatalf("got %v", err)
	}
}

func TestBytes(t *testing.T) {
	for in, want := range map[string]int64{"2G": 2 << 30, "512M": 512 << 20, "100": 100, "1T": 1 << 40, "64K": 64 << 10} {
		if got, err := Bytes(in); err != nil || got != want {
			t.Errorf("Bytes(%q) = %d %v", in, got, err)
		}
	}
	for _, in := range []string{"", "G", "0", "-1M", "1.5G"} {
		if _, err := Bytes(in); err == nil {
			t.Errorf("Bytes(%q) gave no error", in)
		}
	}
}

func TestSystemdVersion(t *testing.T) {
	for out, want := range map[string]int{"systemd 257 (257.13-1)\n+PAM +AUDIT\n": 257, "systemd 247 (247.3-7+deb11u8)\n": 247} {
		if got, err := SystemdVersion([]byte(out)); err != nil || got != want {
			t.Errorf("%q: %d %v", out, got, err)
		}
	}
	if _, err := SystemdVersion([]byte("elogind 252\n")); err == nil {
		t.Error("no error for elogind")
	}
}

// fakeSystemd writes stand-ins for systemd-run and systemctl: systemd-run records its PID and runs
// body, systemctl appends its arguments to a log and, like stopping the unit, ends systemd-run.
func fakeSystemd(t *testing.T, body string) (Systemd, string) {
	dir := t.TempDir()
	log, pid := filepath.Join(dir, "systemctl.log"), filepath.Join(dir, "pid")
	os.WriteFile(filepath.Join(dir, "systemd-run"), []byte("#!/bin/sh\necho $$ > "+pid+"\n"+body), 0o755)
	os.WriteFile(filepath.Join(dir, "systemctl"), []byte("#!/bin/sh\necho \"$@\" >> "+log+"\n[ -s "+pid+" ] && kill $(cat "+pid+")\nexit 0\n"), 0o755)
	return Systemd{SystemdRun: filepath.Join(dir, "systemd-run"), Systemctl: filepath.Join(dir, "systemctl")}, log
}

func TestSystemdRun(t *testing.T) {
	cases := []struct {
		name, body string
		want       Result
	}{
		{"success", "echo out; echo 'Running as unit: x' >&2; echo 'Finished with result: success' >&2; exit 0", Result{}},
		{"failure", "echo 'Finished with result: exit-code' >&2; exit 7", Result{ExitCode: 7}},
		// The command's own output cannot fake the result: systemd-run's line comes last.
		{"timeout", "echo 'Finished with result: success' >&2; echo 'Finished with result: timeout' >&2; exit 1", Result{ExitCode: 1, TimedOut: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, log := fakeSystemd(t, tc.body)
			s := spec(t)
			var stdout, stderr bytes.Buffer
			s.Stdout, s.Stderr = &stdout, &stderr
			got, err := d.Run(context.Background(), s)
			if err != nil || got != tc.want {
				t.Fatalf("got %+v %v, want %+v", got, err, tc.want)
			}
			// The unit is stopped after systemd-run has exited, however it ended.
			if stopped, _ := os.ReadFile(log); string(stopped) != "stop tripcoil-review-20261115T061500Z-3fa2-agent.service\n" {
				t.Errorf("systemctl got %q", stopped)
			}
			if tc.name == "success" && (stdout.String() != "out\n" || !strings.Contains(stderr.String(), "Running as unit")) {
				t.Errorf("stdout %q stderr %q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestSystemdRunCancelStopsUnit(t *testing.T) {
	d, log := fakeSystemd(t, "exec sleep 30")
	s := spec(t)
	s.Stdout, s.Stderr = new(bytes.Buffer), new(bytes.Buffer)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	_, err := d.Run(ctx, s)
	if err != context.Canceled {
		t.Fatalf("got %v", err)
	}
	stopped, _ := os.ReadFile(log)
	if want := strings.Repeat("stop tripcoil-review-20261115T061500Z-3fa2-agent.service\n", 2); string(stopped) != want {
		t.Fatalf("systemctl got %q", stopped)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatalf("took %v", time.Since(start))
	}
}

// A cancelled review starts no unit.
func TestSystemdRunCancelledBeforeStart(t *testing.T) {
	d, log := fakeSystemd(t, "exit 0")
	s := spec(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.Run(ctx, s); err != context.Canceled {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(log), "pid")); err == nil {
		t.Error("systemd-run was started")
	}
}

func TestStopLeftovers(t *testing.T) {
	d, log := fakeSystemd(t, "")
	if err := d.StopLeftovers(); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(log); string(got) != "stop tripcoil-review-*.service\n" {
		t.Fatalf("systemctl got %q", got)
	}
}
