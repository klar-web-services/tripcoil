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

const openrcImage = `FROM alpine:3.21
RUN apk add -q openrc >/dev/null && \
    sed -i 's/^#rc_sys=""/rc_sys="docker"/; s/^#rc_cgroup_mode=.*/rc_cgroup_mode="unified"/' /etc/rc.conf && \
    mkdir -p /run/openrc && touch /run/openrc/softlevel
CMD ["/sbin/init"]
`

const serviceScript = `set -u
B=/opt/tripcoil
S=/var/lib/tripcoil
install -m 755 $B/tripcoil /usr/local/bin/tripcoil
install -m 755 $B/stubcli /usr/local/bin/claude
if [ -d /run/systemd/system ]; then
	svc() { systemctl "$1" tripcoil; }
	log() { journalctl -u tripcoil --no-pager; }
	running() { systemctl is-active -q "tripcoil-review-*-agent.service"; }
	leftovers() { systemctl list-units 'tripcoil-review-*' --all --no-legend | wc -l; }
else
	# A container's cgroup namespace root holds its processes; a real host's root cgroup is exempt.
	mkdir -p /sys/fs/cgroup/init
	for p in $(cat /sys/fs/cgroup/cgroup.procs); do echo $p > /sys/fs/cgroup/init/cgroup.procs; done 2>/dev/null
	for c in cpu memory pids; do echo +$c > /sys/fs/cgroup/cgroup.subtree_control; done
	svc() { rc-service tripcoil "$1" >/dev/null 2>&1; }
	log() { cat /var/log/tripcoil.log; }
	running() { ps -o args | grep -q '[c]laude -p'; }
	leftovers() { echo $(( $(ls -d /sys/fs/cgroup/tripcoil-agent 2>/dev/null | wc -l) + $(ps -o args | grep -c '[c]laude -p') )); }
fi
lastrun() { sed -n 's/.*"lastRun": "\([^"]*\)".*/\1/p' $S/state.json 2>/dev/null; }
waitnew() { for i in $(seq 1 600); do l=$(lastrun); [ -n "$l" ] && [ "$l" != "$1" ] && return 0; sleep 1; done; return 1; }

mkdir -p /etc/tripcoil
install -m 600 /dev/null /etc/tripcoil/agent.env
echo CLAUDE_CODE_OAUTH_TOKEN=stub >/etc/tripcoil/agent.env
tripcoil setup --agent claude --yes >/tmp/setup.out 2>&1
echo "CHECK setup $? $(sed '/^Checking the host/q' /tmp/setup.out | grep -c '^✓') $(cat /etc/tripcoil/tripcoil.yaml | grep -c 'agent: claude')" \
	"$(grep -c '^Waiting' /tmp/setup.out) $(grep -c '^· The tripcoil service is installed and starts after the checks.$' /tmp/setup.out) $(tail -1 /tmp/setup.out)"
waitnew "" || log
R=$S/runs/$(lastrun)
echo "CHECK first $(grep -o '"trigger": "[a-z]*"' $R/run.json) $(grep -o '"reviewed": [a-z]*' $R/run.json) | $(head -1 $R/report.md)"
echo "CHECK status $(tripcoil status | tr '\n' '|')"
tripcoil doctor >/tmp/doctor.out 2>&1
echo "CHECK doctor $? $(grep -c '^✗' /tmp/doctor.out)"; grep -A1 '^✗' /tmp/doctor.out
echo "CHECK again $(tripcoil setup --yes 2>&1 | grep -c '^Nothing changed.$')"
cp /etc/tripcoil/tripcoil.yaml /tmp/good.yaml
echo "version: 2" > /etc/tripcoil/tripcoil.yaml
svc reload; sleep 2
echo "CHECK reload $(log | grep -c 'The configuration stays as it was.') $(svc status >/dev/null 2>&1; echo $?)"
cp /tmp/good.yaml /etc/tripcoil/tripcoil.yaml
if [ -d /run/systemd/system ]; then
	tripcoil run --no-review >/dev/null 2>&1
	echo "CHECK scope $? $(journalctl --no-pager | grep -c 'tripcoil-run-[0-9]*.scope')"
else
	echo "CHECK scope 0 n/a"
fi
echo sleep > /etc/tripcoil-stub
rm $S/state.json $S/runs/latest-reviewed # a run is due at once, and it reviews
svc restart
for i in $(seq 1 600); do running && break; sleep 1; done
svc stop
I=$S/runs/$(ls -1 $S/runs | grep '^[0-9]' | tail -1)
echo "CHECK stop $(grep -o '"status": "[a-z]*"' $I/run.json) leftovers $(leftovers) home $(ls -d $S/agent-home 2>/dev/null | wc -l)"
`

func TestService(t *testing.T) {
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
	for i, tc := range []struct{ name, image, manager string }{
		{"systemd-247", "debian11", "systemd"},
		{"systemd-257", "debian13", "systemd"},
		{"openrc", "alpine-openrc", "openrc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			df := systemdImages[tc.image]
			if tc.image == "alpine-openrc" {
				df = openrcImage
			}
			image := "tripcoil-it-service-" + tc.image
			build := exec.CommandContext(interrupt, "docker", "build", "-q", "-t", image, "-")
			build.Stdin = strings.NewReader(df)
			if out, err := build.CombinedOutput(); err != nil {
				t.Fatalf("docker build: %v\n%s", err, out)
			}
			name := fmt.Sprintf("tripcoil-it-service-%d-%d", os.Getpid(), i)
			t.Cleanup(func() {
				exec.Command("docker", "rm", "-f", name).Run()
				chown := `chown -R "$(stat -c %u:%g /var/lib/tripcoil/cache)" /var/lib/tripcoil/cache`
				if out, err := exec.Command("docker", "run", "--rm", "--pull=never", "-v", cache+":/var/lib/tripcoil/cache", "debian:13",
					"sh", "-c", chown).CombinedOutput(); err != nil {
					t.Errorf("give the cache back: %v\n%s", err, out)
				}
			})
			if out, err := exec.CommandContext(interrupt, "docker", "run", "-d", "--name", name, "--privileged",
				"-v", dir+":/opt/tripcoil:ro", "-v", cache+":/var/lib/tripcoil/cache", image).CombinedOutput(); err != nil {
				t.Fatalf("docker run: %v\n%s", err, out)
			}
			if tc.manager == "systemd" {
				waitForSystemd(t, name)
			} else {
				time.Sleep(3 * time.Second)
			}
			ctx, cancel := context.WithTimeout(interrupt, 20*time.Minute)
			defer cancel()
			var stdout, stderr bytes.Buffer
			cmd := exec.CommandContext(ctx, "docker", "exec", name, "sh", "-c", serviceScript)
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
			setupLines := "3 1"
			if tc.manager == "openrc" {
				setupLines = "4 1"
			}
			for k, parts := range map[string][]string{
				"setup":  {"0 " + setupLines + " 0 1 ✓ Started the tripcoil service."},
				"first":  {`"trigger": "schedule" "reviewed": true | `},
				"status": {"Service:           running (" + tc.manager + ")|", "Agent CLI:         claude 2.1.309 (as of the last run)|", "Failures in a row: 0|"},
				"doctor": {"0 0"},
				"again":  {"1"},
				"reload": {"1 0"},
				"scope":  {"0 "},
				"stop":   {`"status": "interrupted" leftovers 0 home 0`},
			} {
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
			if strings.Contains(checks["first"], "Audit only") {
				t.Errorf("the daemon's first run has no review: %q", checks["first"])
			}
			if tc.manager == "systemd" && strings.HasSuffix(checks["scope"], " 0") {
				t.Errorf("the manual run did not run in a tripcoil-run scope: %q", checks["scope"])
			}
		})
	}
}
