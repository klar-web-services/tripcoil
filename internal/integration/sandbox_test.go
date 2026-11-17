//go:build integration

package integration

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// systemdImages are the systemd versions the review's sandbox is tested on, and one too old for it.
var systemdImages = map[string]string{
	"debian11": `FROM debian:11
RUN printf 'deb http://archive.debian.org/debian bullseye main\ndeb http://archive.debian.org/debian-security bullseye-security main\n' > /etc/apt/sources.list && \
    apt-get -o Acquire::Check-Valid-Until=false update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd systemd-sysv >/dev/null && rm -rf /var/lib/apt/lists/*
CMD ["/lib/systemd/systemd"]
`,
	"ubuntu2204": `FROM ubuntu:22.04
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd systemd-sysv >/dev/null && rm -rf /var/lib/apt/lists/*
CMD ["/lib/systemd/systemd"]
`,
	"rocky9": `FROM rockylinux/rockylinux:9
RUN dnf -y -q install systemd shadow-utils >/dev/null && dnf clean all >/dev/null
CMD ["/usr/lib/systemd/systemd"]
`,
	"debian13": `FROM debian:13
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd systemd-sysv >/dev/null && rm -rf /var/lib/apt/lists/*
CMD ["/lib/systemd/systemd"]
`,
	"ubuntu2004": `FROM ubuntu:20.04
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd systemd-sysv >/dev/null && rm -rf /var/lib/apt/lists/*
CMD ["/lib/systemd/systemd"]
`,
}

// sandboxScript sets up the agent's user, a stub CLI, a local DNS forwarder on 127.0.0.1 and a
// listener on 0.0.0.0:7777 (127.0.0.2 is in review.allowAddresses), then runs Tripcoil and prints
// "CHECK <name> <exit code> <detail>" lines. $FULL=0 makes only the first run.
const sandboxScript = `set -u
B=/opt/tripcoil
R=/var/lib/tripcoil/runs/latest
if [ -d /run/systemd/system ]; then
	useradd --system --user-group --no-create-home --shell /usr/sbin/nologin tripcoil-agent
	leftovers() { systemctl list-units 'tripcoil-review-*' --all --no-legend | wc -l; }
	running() { systemctl is-active -q "tripcoil-review-*-agent.service"; }
else
	apk add -q bubblewrap >/dev/null
	addgroup -S tripcoil-agent && adduser -S -D -H -s /sbin/nologin -G tripcoil-agent tripcoil-agent
	# A container's cgroup namespace root holds its processes; the agent's group needs a parent without them.
	mkdir -p /sys/fs/cgroup/init
	for p in $(cat /sys/fs/cgroup/cgroup.procs); do echo $p > /sys/fs/cgroup/init/cgroup.procs; done 2>/dev/null
	leftovers() { echo $(( $(ls -d /sys/fs/cgroup/tripcoil-agent 2>/dev/null | wc -l) + $(ps -o args | grep -c '[c]laude -p') )); }
	running() { ps -o args | grep -q '[c]laude -p'; }
fi
config() {
	cp $B/stubcli /usr/local/bin/$1 && chmod 755 /usr/local/bin/$1
	mkdir -p /etc/tripcoil
	printf 'version: 1\nreview:\n  agent: %s\n  timeout: %s\n  allowAddresses: ["127.0.0.2"]\n' $1 $2 > /etc/tripcoil/tripcoil.yaml
	echo $3 > /etc/tripcoil-stub
}
up=$(awk '/^nameserver/ {print $2; exit}' /etc/resolv.conf)
$B/stubcli dns 127.0.0.1:53 $up:53 >/dev/null 2>&1 &
echo nameserver 127.0.0.1 > /etc/resolv.conf
$B/stubcli listen 0.0.0.0:7777 >/dev/null 2>&1 &
sleep 1
summary() { sed -n 's/.*"summary": "\([^"]*\)".*/\1/p' $R/review.json 2>/dev/null; }
run() { $B/tripcoil run "$@" >/tmp/run.out 2>&1; echo $?; }

config claude 60s ok
echo "CHECK first $(run) $(summary) | $(head -1 $R/report.md)"
[ "$FULL" = 1 ] || exit 0
echo "CHECK probe 0 $(grep -o '"blocked":true' $R/agent/probe.json | wc -l) blocked, $(grep -o '"blocked":false' $R/agent/probe.json | wc -l) not"
echo "CHECK again $(run --force-review) $(summary) |"
config claude 5s sleep
echo "CHECK timeout $(run --force-review) $(head -1 $R/report.md) | leftovers $(leftovers)"
config claude 60s auth
echo "CHECK auth $(run --force-review) $(head -1 $R/report.md)"
config claude 60s sleep
$B/tripcoil run --force-review >/tmp/run.out 2>&1 &
p=$!
for i in $(seq 1 120); do running && break; sleep 1; done
kill -INT $p
wait $p
code=$?
echo "CHECK interrupt $code leftovers $(leftovers), home $(ls -d /var/lib/tripcoil/agent-home 2>/dev/null | wc -l)"
config codex 60s ok
echo "CHECK codex $(run --force-review) $(summary) | $(grep -o '"agentCli": "[^"]*"' $R/run.json)"
`

// TestSandbox runs reviews with a stub agent CLI through the real sandbox: transient units on
// systemd 247, 249, 252 and 257, bubblewrap with cgroup v2 on Alpine, and the agent's nftables
// table on each (spec section 14, AC-8, AC-11, AC-13). The containers are privileged, with their
// own network namespace, so the table and the units stay inside them.
func TestSandbox(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	dir := t.TempDir()
	if err := os.Rename(buildBinary(t), filepath.Join(dir, "tripcoil")); err != nil {
		t.Fatal(err)
	}
	stub := exec.Command("go", "build", "-o", filepath.Join(dir, "stubcli"), "./testdata/stubcli")
	stub.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := stub.CombinedOutput(); err != nil {
		t.Fatalf("go build stubcli: %v\n%s", err, out)
	}
	cache := preparedCache(t)
	const done = "write-etc=read-only-file-system marker=absent dns=ok allowed=connected blocked=connection-refused pids="
	cases := []struct {
		name, image string
		full        bool
		first       string // in the first run's CHECK line
	}{
		{"systemd-247", "debian11", true, done},
		{"systemd-249", "ubuntu2204", true, done},
		{"systemd-252", "rocky9", true, done},
		{"systemd-257", "debian13", true, done},
		{"systemd-245", "ubuntu2004", false, "⚠️ Audit only (no AI review: systemd 245 is older than 247, which the review's sandbox needs)"},
		{"bubblewrap", "alpine:3.21", true, done},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			image := tc.image
			args := []string{"run", "-d", "--name", fmt.Sprintf("tripcoil-it-sandbox-%d-%d", os.Getpid(), i), "--privileged",
				"-v", dir + ":/opt/tripcoil:ro", "-v", cache + ":/var/lib/tripcoil/cache"}
			if df, ok := systemdImages[image]; ok {
				image = "tripcoil-it-systemd-" + image
				build := exec.CommandContext(interrupt, "docker", "build", "-q", "-t", image, "-")
				build.Stdin = strings.NewReader(df)
				if out, err := build.CombinedOutput(); err != nil {
					t.Fatalf("docker build: %v\n%s", err, out)
				}
				args = append(args, image)
			} else {
				args = append(args, "--init", image, "sleep", "infinity") // docker-init reaps what bubblewrap leaves
			}
			name := args[3]
			t.Cleanup(func() {
				exec.Command("docker", "rm", "-f", name).Run()
				chown := `chown -R "$(stat -c %u:%g /var/lib/tripcoil/cache)" /var/lib/tripcoil/cache`
				if out, err := exec.Command("docker", "run", "--rm", "--pull=never", "-v", cache+":/var/lib/tripcoil/cache", "debian:13",
					"sh", "-c", chown).CombinedOutput(); err != nil {
					t.Errorf("give the cache back: %v\n%s", err, out)
				}
			})
			if out, err := exec.CommandContext(interrupt, "docker", args...).CombinedOutput(); err != nil {
				t.Fatalf("docker run: %v\n%s", err, out)
			}
			if strings.HasPrefix(image, "tripcoil-it-systemd-") {
				waitForSystemd(t, name)
			}
			full := "0"
			if tc.full {
				full = "1"
			}
			ctx, cancel := context.WithTimeout(interrupt, 10*time.Minute)
			defer cancel()
			var stdout, stderr bytes.Buffer
			cmd := exec.CommandContext(ctx, "docker", "exec", "-e", "FULL="+full, name, "sh", "-c", sandboxScript)
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("script: %v\n%s\n%s", err, stdout.Bytes(), stderr.Bytes())
			}
			t.Logf("%s", stdout.Bytes())
			checks := map[string]string{}
			sc := bufio.NewScanner(&stdout)
			for sc.Scan() {
				if k, v, ok := strings.Cut(strings.TrimPrefix(sc.Text(), "CHECK "), " "); ok && strings.HasPrefix(sc.Text(), "CHECK ") {
					checks[k] = v
				}
			}
			want := map[string][]string{"first": {"0 ", tc.first}}
			if tc.full {
				for k, v := range map[string][]string{
					"probe":     {" blocked, 0 not"},
					"again":     {"0 " + done}, // the marker the first review wrote is gone (AC-13)
					"timeout":   {"1 ⚠️ Audit only (AI review failed: AGENT_TIMEOUT)", "leftovers 0"},
					"auth":      {"1 ⚠️ Audit only (AI review failed: AGENT_AUTH)"},
					"interrupt": {"2 leftovers 0, home 0"},
					"codex":     {"0 " + done, `"agentCli": "codex 0.154.0"`},
				} {
					want[k] = v
				}
			}
			for k, parts := range want {
				got, ok := checks[k]
				if !ok {
					t.Errorf("no %s check", k)
					continue
				}
				for _, p := range parts {
					if !strings.Contains(got, p) {
						t.Errorf("%s: got %q, want it to contain %q", k, got, p)
					}
				}
			}
			for _, k := range []string{"first", "again", "codex"} {
				if tc.full && !strings.Contains(checks[k], "pids=1 ") && !strings.Contains(checks[k], "pids=2 ") { // bubblewrap's own init counts
					t.Errorf("%s: the agent sees other processes: %q", k, checks[k])
				}
				if tc.full && (strings.Contains(checks[k], "keyring=present") || !strings.Contains(checks[k], "keyring=")) {
					t.Errorf("%s: a key from the last review is still there: %q", k, checks[k])
				}
			}
		})
	}
}

func waitForSystemd(t *testing.T, name string) {
	t.Helper()
	for range 60 {
		out, _ := exec.Command("docker", "exec", name, "systemctl", "is-system-running").Output()
		if s := strings.TrimSpace(string(out)); s == "running" || s == "degraded" {
			return
		}
		time.Sleep(time.Second)
	}
	logs, _ := exec.Command("docker", "logs", "--tail", "40", name).CombinedOutput()
	t.Fatalf("systemd did not start:\n%s", logs)
}
