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
cp /bin/sleep /usr/local/bin/caddy && cp /bin/sleep /usr/local/bin/nginx
mkdir -p /srv/proxy /etc/nginx
printf ':8080 {\n\treverse_proxy 127.0.0.1:22\n}\n' > /srv/proxy/Caddyfile && chmod 600 /srv/proxy/Caddyfile
printf 'events {}\nhttp { server { location / { proxy_pass http://127.0.0.1:22; } } }\n' > /etc/nginx/nginx.conf && chmod 600 /etc/nginx/nginx.conf
(cd /srv/proxy && setpriv --reuid alice --regid alice --init-groups caddy 600 &)
nginx 600 &
mkdir -p /srv/device && mknod /srv/device/Caddyfile c 1 3 && (cd /srv/device && caddy 601 &)
cp /bin/sleep /usr/local/bin/traefik && mkdir -p /etc/traefik
printf 'providers:\n  file:\n    filename: /etc/traefik/dynamic.yml\n' > /etc/traefik/traefik.yml
printf 'http:\n  services:\n    s:\n      loadBalancer:\n        servers:\n          - url: http://127.0.0.1:22\n' > /etc/traefik/dynamic.yml
chgrp alice /etc/traefik/dynamic.yml && chmod 640 /etc/traefik/dynamic.yml
setpriv --reuid alice --regid alice --init-groups traefik 600 &
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
	if len(idx.Collected) != 10 || len(idx.Missing) != 0 {
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
	// The container's network card has a private address and no public one, so sshd's socket on
	// 0.0.0.0 counts for the LAN. The kinds and classes come from the container's own /sys and
	// netlink. The container sees its host's DMI: on a cloud runner the same socket counts as public.
	var addrs facts.Addresses
	json.Unmarshal(files["facts/addresses.json"], &addrs)
	var reach facts.Reach
	json.Unmarshal(files["facts/reach.json"], &reach)
	lo, private, sshReach := false, false, ""
	for _, i := range addrs.Interfaces {
		lo = lo || i.Kind == facts.KindLoopback && i.Up
		for _, a := range i.Addresses {
			private = private || a.Class == facts.ClassPrivate && i.BehindRouter != addrs.Cloud
		}
	}
	wantReach := "lan"
	if addrs.Cloud {
		wantReach = "internet"
	}
	for _, r := range reach.Items {
		if names[r.Item] == "sshd" && len(r.Sockets) > 0 {
			sshReach = r.Sockets[0].Reach
		}
	}
	if !lo || !private || sshReach != wantReach {
		t.Errorf("addresses.json: %s\nreach.json: %s", files["facts/addresses.json"], files["facts/reach.json"])
	}
	// Processes named like proxies (they are copies of sleep), with configurations that forward to sshd.
	// nginx runs as root and its file is root's alone: Tripcoil reads it. One caddy runs as alice with
	// such a file: Tripcoil reads with her rights, not root's, finds nothing, and says so. The other
	// caddy's file is a device, which is not opened. traefik runs as alice, and its routing file is
	// readable through her group only: Tripcoil reads it, with her user and groups.
	var routes facts.Routes
	json.Unmarshal(files["facts/routes.json"], &routes)
	toSSH := func(p facts.RouteProgram) bool {
		return p.Complete && len(p.Targets) == 1 && p.Targets[0].Target == "127.0.0.1:22" && names[p.Targets[0].Item] == "sshd"
	}
	asRoot, asAlice, refused := false, false, false
	for _, p := range routes.Programs {
		switch gaps := strings.Join(p.Gaps, "; "); p.Program {
		case "nginx":
			asRoot = toSSH(p)
		case "traefik":
			asAlice = toSSH(p)
		case "caddy":
			refused = !p.Complete && len(p.Targets) == 0 && strings.Contains(gaps, "permission denied") && strings.Contains(gaps, "not a regular file")
		}
	}
	// The fake proxies have no socket of their own, so they may listen where Tripcoil cannot see it
	// and count as public: sshd, which they forward to, is reachable from the internet through them.
	// On a cloud runner sshd's own socket is public already, and equally wide counts as direct.
	wantVia := facts.ViaProxy
	if addrs.Cloud {
		wantVia = facts.ViaDirect
	}
	through := false
	for _, r := range reach.Items {
		through = through || names[r.Item] == "sshd" && len(r.Through) == 2 && r.Default == facts.ReachInternet && r.Via == wantVia
	}
	if len(routes.Programs) != 3 || !asRoot || !asAlice || !refused || !through {
		t.Errorf("routes.json: %s\nreach.json: %s", files["facts/routes.json"], files["facts/reach.json"])
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
