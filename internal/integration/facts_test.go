//go:build integration

package integration

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/klar-web-services/tripcoil/internal/facts"
	"github.com/klar-web-services/tripcoil/internal/inventory"
)

// TestFactsTools collects the facts with the real tools: nftables with a ruleset, a running sshd,
// a user with an SSH key, and a process started with a password on its command line (AC-12). The
// container is privileged, so nft can read its own network namespace's ruleset.
func TestFactsTools(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	bin := buildBinary(t)
	cache := preparedCache(t)
	const image = "debian:13"
	name := fmt.Sprintf("tripcoil-it-facts-%d", os.Getpid())
	t.Cleanup(func() {
		exec.Command("docker", "rm", "-f", name).Run()
		chown := `chown -R "$(stat -c %u:%g /var/lib/tripcoil/cache)" /var/lib/tripcoil/cache`
		if out, err := exec.Command("docker", "run", "--rm", "--pull=never", "-v", cache+":/var/lib/tripcoil/cache", image, "sh", "-c", chown).CombinedOutput(); err != nil {
			t.Errorf("give the cache back: %v\n%s", err, out)
		}
	})
	script := `set -e
apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables openssh-server >/dev/null
nft add table inet filter
nft add chain inet filter input '{ type filter hook input priority filter; policy accept; }'
nft add rule inet filter input tcp dport 22 accept
useradd -m -s /bin/bash alice
mkdir -p /home/alice/.ssh && echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample alice@test" > /home/alice/.ssh/authorized_keys
mkdir -p /run/sshd && /usr/sbin/sshd
sh -c 'exec -a "worker --password=hunter2" sleep 600' &
sleep 1
set +e
/usr/local/bin/tripcoil run --no-review >&2; code=$?
tar -C /var/lib/tripcoil/runs/latest -cf - .
exit $code`
	ctx, cancel := context.WithTimeout(interrupt, 8*time.Minute)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--name", name, "--privileged", "-v", bin+":/usr/local/bin/tripcoil:ro",
		"-v", cache+":/var/lib/tripcoil/cache", image, "bash", "-c", script)
	cmd.Cancel = func() error { return exec.Command("docker", "rm", "-f", name).Run() }
	cmd.WaitDelay = time.Minute
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("tripcoil run: %v\n%s", err, stderr.Bytes())
	}
	files := map[string][]byte{}
	tr := tar.NewReader(&stdout)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(tr)
		files[strings.TrimPrefix(h.Name, "./")] = data
	}
	for name, data := range files {
		if bytes.Contains(data, []byte("hunter2")) {
			t.Errorf("%s holds the password", name)
		}
	}
	var idx facts.Index
	if err := json.Unmarshal(files["facts/index.json"], &idx); err != nil {
		t.Fatal(err)
	}
	if len(idx.Collected) != 7 || len(idx.Missing) != 0 {
		t.Fatalf("facts: %+v", idx)
	}
	var inv inventory.Inventory
	if err := json.Unmarshal(files["inventory.json"], &inv); err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for _, it := range inv.Items {
		names[it.ID] = it.Name
	}
	var net facts.Network
	json.Unmarshal(files["facts/network.json"], &net)
	ssh := false
	for _, s := range net.Sockets {
		if s.Proto == "tcp" && s.Port == 22 && s.Address == "0.0.0.0" && len(s.Items) == 1 && names[s.Items[0]] == "sshd" {
			ssh = true
		}
	}
	if !ssh || net.LocalPortRangeStart == 0 {
		t.Errorf("network.json: %s", files["facts/network.json"])
	}
	if fw := string(files["facts/firewall.txt"]); !strings.HasPrefix(fw, "### nft -s list ruleset\n") || !strings.Contains(fw, "tcp dport 22 accept") {
		t.Errorf("firewall.txt:\n%s", fw)
	}
	if sshd := string(files["facts/sshd.txt"]); !strings.Contains(sshd, "\nport 22\n") && !strings.HasPrefix(sshd, "port 22\n") {
		t.Errorf("sshd.txt:\n%.300s", sshd)
	}
	var users []facts.User
	json.Unmarshal(files["facts/users.json"], &users)
	alice := false
	for _, u := range users {
		alice = alice || u.Name == "alice" && u.AuthorizedKeys == 1 && u.Password == "none"
	}
	if !alice || bytes.Contains(files["facts/users.json"], []byte("AAAAC3")) {
		t.Errorf("users.json: %s", files["facts/users.json"])
	}
	var procs facts.Processes
	json.Unmarshal(files["facts/processes.json"], &procs)
	if len(procs.Processes) == 0 {
		t.Errorf("processes.json: %s", files["facts/processes.json"])
	}
	var k facts.Kernel
	json.Unmarshal(files["facts/kernel.json"], &k)
	if k.Cmdline == "" || len(k.Sysctls) == 0 {
		t.Errorf("kernel.json: %s", files["facts/kernel.json"])
	}
	if !bytes.HasPrefix(files["report.md"], []byte("⚠️ Audit only (--no-review)")) {
		t.Errorf("report.md: %.200s", files["report.md"])
	}
}
