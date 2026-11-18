package facts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/klar-web-services/tripcoil/internal/dockerapi"
	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/run"
)

func init() { run.AgentGID = func() (int, bool) { return 0, false } }

func write(t *testing.T, root, name, content string) {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func link(t *testing.T, root, name, target string) {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
}

const tcpHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func fixture(t *testing.T) (string, *inventory.Inventory) {
	root := t.TempDir()
	write(t, root, "proc/net/tcp", tcpHeader+
		"   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1\n"+
		"   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1002 1\n"+
		"   2: 0100007F:1388 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1003 1\n"+
		"   3: 0100007F:01BB 0200007F:D431 01 00000000:00000000 00:00000000 00000000     0        0 1004 1\n"+
		"   4: 0100007F:1770 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1008 1\n"+
		"   5: 00000000:1B58 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1009 1\n"+
		"   6: 00000000:1F40 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1010 1\n")
	write(t, root, "proc/net/tcp6", tcpHeader+
		"   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1005 1\n")
	write(t, root, "proc/net/udp", tcpHeader+
		"   0: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 1006 2\n"+
		"   1: 0100007F:E290 0100007F:0035 01 00000000:00000000 00:00000000 00000000  1000        0 1007 2\n")
	write(t, root, "proc/sys/net/ipv4/ip_local_port_range", "32768\t60999\n")
	link(t, root, "proc/812/fd/3", "socket:[1001]")
	link(t, root, "proc/812/fd/4", "socket:[1005]")
	link(t, root, "proc/812/fd/5", "/var/log/nginx/access.log")
	link(t, root, "proc/813/fd/3", "socket:[1001]")
	link(t, root, "proc/900/fd/3", "socket:[1002]")
	link(t, root, "proc/950/fd/7", "socket:[1006]")
	link(t, root, "proc/960/fd/9", "socket:[1007]")
	link(t, root, "proc/970/fd/3", "socket:[1003]")
	link(t, root, "proc/970/exe", "/usr/sbin/nginx")
	link(t, root, "proc/971/fd/3", "socket:[1008]")
	link(t, root, "proc/971/exe", "/usr/bin/nc")
	link(t, root, "proc/972/fd/3", "socket:[1009]")
	link(t, root, "proc/972/exe", "/usr/sbin/nginx")
	link(t, root, "proc/973/fd/3", "socket:[1010]")
	link(t, root, "proc/973/exe", "/usr/bin/python3.11")
	for pid, ns := range map[int]string{1: "mnt:[4026531841]", 970: "mnt:[4026531841]", 971: "mnt:[4026531841]", 972: "mnt:[4026532999]", 973: "mnt:[4026531841]"} {
		link(t, root, fmt.Sprintf("proc/%d/ns/mnt", pid), ns)
	}
	for pid, st := range map[int]string{
		812: "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\nNoNewPrivs:\t0\nSeccomp:\t0\n",
		813: "Uid:\t33\t33\t33\t33\nGid:\t33\t33\t33\t33\nCapEff:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n",
		900: "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\nNoNewPrivs:\t0\nSeccomp:\t0\n",
	} {
		write(t, root, fmt.Sprintf("proc/%d/status", pid), "Name:\tx\n"+st)
	}
	write(t, root, "proc/cmdline", "BOOT_IMAGE=/vmlinuz root=UUID=x ro quiet\n")
	write(t, root, "sys/kernel/security/lockdown", "none [integrity] confidentiality\n")
	write(t, root, "sys/kernel/security/lsm", "lockdown,capability,landlock,yama,apparmor\n")
	write(t, root, "sys/module/apparmor/parameters/enabled", "Y\n")
	write(t, root, "sys/devices/system/cpu/vulnerabilities/meltdown", "Not affected\n")
	write(t, root, "sys/devices/system/cpu/vulnerabilities/spectre_v2", "Mitigation: Enhanced IBRS\n")
	write(t, root, "proc/sys/kernel/kptr_restrict", "1\n")
	write(t, root, "proc/sys/kernel/yama/ptrace_scope", "1\n")
	write(t, root, "proc/sys/net/ipv4/ip_forward", "1\n")
	write(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"+
		"alice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/sh\nsync:x:4:65534:sync:/bin:/bin/sync\ndeploy:x:1002:1002::/srv/deploy:/bin/bash\n"+
		"carol:x:1003:1003::/home/carol:/bin/bash\ndave:x:1004:1004::/home/dave:/bin/bash\n")
	write(t, root, "etc/shadow", "root:*:19000:0:99999:7:::\ndaemon:*:19000::::::\nalice:$y$j9T$hash:19000:0:99999:7:::\nbob:!$y$j9T$hash:19000:0:99999:7:::\ndeploy::19000:0:99999:7:::\n")
	write(t, root, "etc/shells", "# /etc/shells\n/bin/sh\n/bin/bash\n")
	write(t, root, "root/.ssh/authorized_keys", "# admin keys\nssh-ed25519 AAAAC3Nza root@a\n\nssh-ed25519 AAAAC3Nzb root@b\n")
	write(t, root, "home/alice/.ssh/authorized_keys", "ssh-ed25519 AAAAC3Nzc alice@x\n")
	if err := os.MkdirAll(filepath.Join(root, "home/bob/.ssh"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "home/bob/.ssh/authorized_keys"), 0o644); err != nil {
		t.Fatal(err)
	}
	link(t, root, "home/dave/.ssh", filepath.Join(root, "root/.ssh"))
	inv := &inventory.Inventory{Host: inventory.Host{Init: "systemd"}, Items: []inventory.Item{
		{ID: "kernel", Kind: inventory.KindKernel, Modules: []string{"nf_tables", "overlay"}},
		{ID: "proc:nginx", Kind: inventory.KindProcess, Name: "nginx", Exe: "/usr/sbin/nginx", Units: []string{"nginx.service"}, Processes: []inventory.Process{{PID: 812}, {PID: 813}}},
		{ID: "proc:sshd", Kind: inventory.KindProcess, Name: "sshd", Units: []string{"ssh.service", "bad;unit.service"}, Processes: []inventory.Process{{PID: 900}}},
		{ID: "proc:resolved", Kind: inventory.KindProcess, Name: "systemd-resolved", Processes: []inventory.Process{{PID: 950}}},
		{ID: "proc:client", Kind: inventory.KindProcess, Name: "client", Processes: []inventory.Process{{PID: 960}, {PID: 961}}},
		{ID: "proc:shop", Kind: inventory.KindProcess, Name: "python3.11", Exe: "/usr/bin/python3.11", AppDir: "/opt/shop", Processes: []inventory.Process{{PID: 980}}},
		{ID: "container:web", Kind: inventory.KindContainer, Name: "web", ContainerID: "c1", Ports: []inventory.Port{{IP: "0.0.0.0", HostPort: 8080, ContainerPort: 80}}},
		{ID: "container:gone", Kind: inventory.KindContainer, Name: "gone", ContainerID: "c2"},
	}}
	return root, inv
}

type fakeDocker map[string]dockerapi.Detail

func (f fakeDocker) Inspect(_ context.Context, id string) (dockerapi.Detail, error) {
	d, ok := f[id]
	if !ok {
		return dockerapi.Detail{}, fmt.Errorf("GET /containers/%s/json: %w", id, dockerapi.ErrNotFound)
	}
	return d, nil
}

type brokenDocker struct{ err error }

func (b brokenDocker) Inspect(context.Context, string) (dockerapi.Detail, error) {
	return dockerapi.Detail{}, b.err
}

func fakeRun(t *testing.T, answers map[string]string, calls *[]string) Runner {
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		cmd := strings.Join(append([]string{name}, args...), " ")
		*calls = append(*calls, cmd)
		for k, v := range answers {
			if k == cmd {
				if msg, ok := strings.CutPrefix(v, "ERROR:"); ok {
					return nil, errors.New(msg)
				}
				return []byte(v), nil
			}
		}
		if _, ok := answers[name]; ok {
			return nil, fmt.Errorf("unexpected call %q", cmd)
		}
		return nil, fmt.Errorf("%s: %w", name, errNotFound)
	}
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
}

const sshdT = "port 22\npermitrootlogin without-password\npasswordauthentication no\nauthorizedkeysfile .ssh/authorized_keys /etc/ssh/keys/%u\n"

const showOut = "Id=nginx.service\nUser=\nNoNewPrivileges=no\nProtectSystem=no\nProtectHome=no\nPrivateTmp=no\nCapabilityBoundingSet=cap_chown cap_net_bind_service\nRestrictNamespaces=no\nSystemCallFilter=\n\n" +
	"Id=ssh.service\nUser=\nNoNewPrivileges=no\nProtectSystem=no\nProtectHome=no\nPrivateTmp=no\nCapabilityBoundingSet=cap_chown\nRestrictNamespaces=no\nSystemCallFilter=\n"

const nftOut = "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\ttcp dport { 22, 443 } accept\n\t}\n}\n" +
	"table inet tripcoil {\n\tchain output {\n\t\ttype filter hook output priority filter; policy accept;\n\t}\n}\n"

func TestCollect(t *testing.T) {
	root, inv := fixture(t)
	write(t, root, "etc/ssh/keys/alice", "ssh-rsa AAAAB3 alice@old\n")
	var calls []string
	d := Deps{Root: root, Run: fakeRun(t, map[string]string{
		"nft -s list ruleset": nftOut,
		"sshd -T":             sshdT,
		"systemctl show -p Id,User,NoNewPrivileges,ProtectSystem,ProtectHome,PrivateTmp,CapabilityBoundingSet,RestrictNamespaces,SystemCallFilter -- nginx.service ssh.service": showOut,
		"iptables-legacy-save": "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n",
	}, &calls), LookPath: func(string) (string, error) { return "", errNotFound },
		Docker: fakeDocker{"c1": {HostConfig: dockerapi.HostConfig{Privileged: true, CapAdd: []string{"NET_ADMIN"}, NetworkMode: "bridge", PidMode: "host"},
			Mounts: []dockerapi.Mount{{Type: "bind", Source: "/var/run", Destination: "/var/run", RW: true}, {Type: "volume", Source: "/var/lib/docker/volumes/x/_data", Destination: "/data", RW: true}}}},
		DockerSocket: "/var/run/docker.sock"}
	runDir := t.TempDir()
	idx, err := Collect(context.Background(), d, inv, runDir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"network.json", "firewall.txt", "processes.json", "containers.json", "kernel.json", "sshd.txt", "users.json"}
	if !reflect.DeepEqual(idx.Collected, want) || len(idx.Missing) != 0 {
		t.Fatalf("index %+v", idx)
	}

	var net Network
	readJSON(t, filepath.Join(runDir, "facts/network.json"), &net)
	got := []string{}
	for _, s := range net.Sockets {
		got = append(got, fmt.Sprintf("%s %s:%d connected=%v items=%v pids=%v", s.Proto, s.Address, s.Port, s.Connected, s.Items, s.PIDs))
	}
	wantSocks := []string{
		"tcp 0.0.0.0:22 connected=false items=[proc:sshd] pids=[900]",
		"tcp 0.0.0.0:443 connected=false items=[proc:nginx] pids=[812 813]",
		"tcp :::443 connected=false items=[proc:nginx] pids=[812]",
		"tcp 127.0.0.1:5000 connected=false items=[proc:nginx] pids=[970]",
		"tcp 127.0.0.1:6000 connected=false items=[] pids=[971]",
		"tcp 0.0.0.0:7000 connected=false items=[] pids=[972]",
		"tcp 0.0.0.0:8000 connected=false items=[] pids=[973]",
		"udp 127.0.0.53:53 connected=false items=[proc:resolved] pids=[950]",
		"udp 127.0.0.1:58000 connected=true items=[proc:client] pids=[960]",
	}
	if !reflect.DeepEqual(got, wantSocks) || net.LocalPortRangeStart != 32768 {
		t.Errorf("sockets:\n%s\nport range %d", strings.Join(got, "\n"), net.LocalPortRangeStart)
	}

	fw, _ := os.ReadFile(filepath.Join(runDir, "facts/firewall.txt"))
	if !strings.HasPrefix(string(fw), "### nft -s list ruleset\ntable inet filter {") || strings.Contains(string(fw), "tripcoil") || strings.Contains(string(fw), "legacy") {
		t.Errorf("firewall.txt:\n%s", fw)
	}

	var procs Processes
	readJSON(t, filepath.Join(runDir, "facts/processes.json"), &procs)
	if len(procs.Processes) != 3 || procs.Processes[1].PID != 813 || procs.Processes[1].UID != 33 || !procs.Processes[1].NoNewPrivs || procs.Processes[1].Seccomp != 2 ||
		procs.Processes[0].CapEff != "000001ffffffffff" || procs.Processes[0].Item != "proc:nginx" {
		t.Errorf("processes: %+v", procs.Processes)
	}
	if len(procs.Units) != 2 || procs.Units[0].Unit != "nginx.service" || procs.Units[0].Properties["CapabilityBoundingSet"] != "cap_chown cap_net_bind_service" {
		t.Errorf("units: %+v", procs.Units)
	}

	var conts []Container
	readJSON(t, filepath.Join(runDir, "facts/containers.json"), &conts)
	if len(conts) != 1 || !conts[0].Privileged || !conts[0].DockerSocket || conts[0].PIDMode != "host" || conts[0].HostNetwork || len(conts[0].Ports) != 1 || len(conts[0].Mounts) != 2 {
		t.Errorf("containers: %+v", conts)
	}

	var k Kernel
	readJSON(t, filepath.Join(runDir, "facts/kernel.json"), &k)
	if k.Lockdown != "integrity" || k.AppArmor != "Y" || k.SELinux != "" || len(k.LSMs) != 5 || k.Vulnerabilities["meltdown"] != "Not affected" ||
		k.Sysctls["kernel.kptr_restrict"] != "1" || len(k.Sysctls) != 3 || !reflect.DeepEqual(k.Modules, []string{"nf_tables", "overlay"}) || !strings.Contains(k.Cmdline, "root=UUID=x") {
		t.Errorf("kernel: %+v", k)
	}

	var users []User
	readJSON(t, filepath.Join(runDir, "facts/users.json"), &users)
	gotUsers := []string{}
	for _, u := range users {
		gotUsers = append(gotUsers, fmt.Sprintf("%s %s keys=%d %v", u.Name, u.Password, u.AuthorizedKeys, u.KeyFiles))
	}
	wantUsers := []string{
		"root none keys=2 [/root/.ssh/authorized_keys]",
		"alice set keys=2 [/home/alice/.ssh/authorized_keys /etc/ssh/keys/alice]",
		"bob locked keys=0 []",
		"deploy empty keys=0 []",
		"carol unknown keys=0 []",
		"dave unknown keys=0 []",
	}
	if !reflect.DeepEqual(gotUsers, wantUsers) {
		t.Errorf("users:\n%s", strings.Join(gotUsers, "\n"))
	}
	if len(users[5].KeysUnread) != 1 || users[5].KeysUnread[0] != "/home/dave/.ssh/authorized_keys: /home/dave/.ssh is a symbolic link, which root does not follow here" {
		t.Errorf("dave: %+v", users[5])
	}
	data, _ := os.ReadFile(filepath.Join(runDir, "facts/users.json"))
	if strings.Contains(string(data), "AAAA") || strings.Contains(string(data), "$y$") {
		t.Error("users.json holds keys or hashes")
	}
	var onDisk Index
	readJSON(t, filepath.Join(runDir, "facts/index.json"), &onDisk)
	if !reflect.DeepEqual(onDisk.Collected, want) {
		t.Errorf("index.json %+v", onDisk)
	}
}

func TestCollectMissingFacts(t *testing.T) {
	root, inv := fixture(t)
	os.Remove(filepath.Join(root, "proc/cmdline"))
	os.Remove(filepath.Join(root, "proc/net/tcp"))
	var calls []string
	d := Deps{Root: root, Run: fakeRun(t, map[string]string{
		"nft -s list ruleset": "ERROR:nft: exit status 1: netlink: Error: cache initialization failed: Operation not permitted",
		"sshd -T":             "ERROR:sshd: exit status 255: Missing privilege separation directory: /run/sshd",
		"systemd-run --wait --pipe --quiet --collect -p RuntimeDirectory=sshd -p PrivateNetwork=yes -- /usr/sbin/sshd -T":                                                       sshdT,
		"systemctl show -p Id,User,NoNewPrivileges,ProtectSystem,ProtectHome,PrivateTmp,CapabilityBoundingSet,RestrictNamespaces,SystemCallFilter -- nginx.service ssh.service": "ERROR:systemctl: exit status 1: Failed to connect to bus",
	}, &calls), LookPath: func(name string) (string, error) { return "/usr/sbin/" + name, nil }}
	runDir := t.TempDir()
	idx, err := Collect(context.Background(), d, inv, runDir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(idx.Collected, []string{"processes.json", "sshd.txt", "users.json"}) {
		t.Errorf("collected %v", idx.Collected)
	}
	var procs Processes
	readJSON(t, filepath.Join(runDir, "facts/processes.json"), &procs)
	if len(procs.Processes) != 3 || len(procs.Units) != 0 || !strings.Contains(procs.UnitsError, "Failed to connect to bus") {
		t.Errorf("a failed systemctl must keep the processes: %+v", procs)
	}
	reasons := map[string]string{}
	for _, m := range idx.Missing {
		reasons[m.Fact] = m.Reason
	}
	if len(reasons) != 4 || !strings.Contains(reasons["network.json"], "proc/net/tcp") || !strings.Contains(reasons["firewall.txt"], "Operation not permitted") ||
		!strings.Contains(reasons["containers.json"], "no Docker") || !strings.Contains(reasons["kernel.json"], "cmdline") {
		t.Errorf("missing: %+v", idx.Missing)
	}
	for _, name := range []string{"network.json", "firewall.txt", "kernel.json"} {
		if _, err := os.Stat(filepath.Join(runDir, "facts", name)); err == nil {
			t.Errorf("%s written although it is missing", name)
		}
	}
}

func TestContainersDockerFails(t *testing.T) {
	root, inv := fixture(t)
	var calls []string
	d := Deps{Root: root, Run: fakeRun(t, nil, &calls), LookPath: func(string) (string, error) { return "", errNotFound },
		Docker: brokenDocker{errors.New(`Get "http://docker/containers/c1/json": context deadline exceeded (Client.Timeout exceeded while awaiting headers)`)}}
	runDir := t.TempDir()
	idx, err := Collect(context.Background(), d, inv, runDir)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(idx.Collected, "containers.json") {
		t.Fatalf("containers.json collected although Docker failed: %+v", idx)
	}
	var reason string
	for _, m := range idx.Missing {
		if m.Fact == "containers.json" {
			reason = m.Reason
		}
	}
	if !strings.Contains(reason, "web") || !strings.Contains(reason, "deadline exceeded") {
		t.Errorf("reason %q", reason)
	}
	if _, err := os.Stat(filepath.Join(runDir, "facts/containers.json")); err == nil {
		t.Error("containers.json written although it is missing")
	}
}

func TestFirewallWithoutNft(t *testing.T) {
	root, inv := fixture(t)
	var calls []string
	c := collector{ctx: context.Background(), inv: inv, d: Deps{Root: root, Run: fakeRun(t, map[string]string{
		"iptables-save":         "# Generated by iptables-save v1.8.9\n*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n",
		"ip6tables-save":        "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n",
		"iptables-legacy-save":  "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -s 10.0.0.1/32 -j DROP\nCOMMIT\n",
		"ip6tables-legacy-save": "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n",
	}, &calls)}}
	fw, err := c.firewall()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"### iptables-save\n# Generated", "### ip6tables-save\n*filter", "### iptables-legacy-save\n*filter", "-A INPUT -s 10.0.0.1/32 -j DROP"} {
		if !strings.Contains(fw, want) {
			t.Errorf("firewall.txt lacks %q:\n%s", want, fw)
		}
	}
	if strings.Contains(fw, "ip6tables-legacy-save") || strings.Contains(fw, "No firewall") {
		t.Errorf("firewall.txt:\n%s", fw)
	}
	c.d.Run = fakeRun(t, map[string]string{
		"nft -s list ruleset": "ERROR:nft: exit status 1: Error: Could not process rule: No such file or directory\nmore",
		"iptables-save":       "*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n",
	}, &calls)
	fw, err = c.firewall()
	if err != nil || !strings.HasPrefix(fw, "# nft -s list ruleset failed: nft: exit status 1: Error: Could not process rule: No such file or directory more\n### iptables-save\n") {
		t.Errorf("nft failed, iptables-save works: %v\n%s", err, fw)
	}
	c.d.Run = fakeRun(t, map[string]string{"nft -s list ruleset": "ERROR:nft: netlink: Error: no nf_tables", "iptables-save": "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"}, &calls)
	if fw, _ := c.firewall(); !strings.Contains(fw, "# iptables shows no rules, but nftables could not be read.") || strings.Contains(fw, "No firewall rules") {
		t.Errorf("nft failed, iptables empty:\n%s", fw)
	}
	c.d.Run = fakeRun(t, map[string]string{
		"nft -s list ruleset": "ERROR:nft: exit status 1: netlink: Error: cache initialization failed: Operation not permitted",
		"iptables-save":       "ERROR:iptables-save: exit status 4: Could not fetch rule set generation id: Permission denied (you must be root)",
	}, &calls)
	if _, err := c.firewall(); err == nil || !strings.Contains(err.Error(), "Operation not permitted; iptables-save: exit status 4") {
		t.Errorf("both failed: %v", err)
	}
	c.d.Run = fakeRun(t, map[string]string{"nft -s list ruleset": "table inet tripcoil {\n}\n"}, &calls)
	if fw, _ := c.firewall(); fw != "### nft -s list ruleset\n\n# No firewall rules are loaded.\n" {
		t.Errorf("empty ruleset gives %q", fw)
	}
}

func TestExecTimeoutWithChildHoldingStdout(t *testing.T) {
	defer func(d time.Duration) { waitDelay = d }(waitDelay)
	waitDelay = 100 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Exec(ctx, "sh", "-c", "sleep 5 & sleep 5")
	if err == nil || time.Since(start) > 2*time.Second {
		t.Errorf("returned after %v: %v", time.Since(start), err)
	}
}

func TestExpandKeysFile(t *testing.T) {
	u := User{Name: "alice", UID: 1000, Home: "/home/alice"}
	for spec, want := range map[string]string{
		".ssh/authorized_keys": "/home/alice/.ssh/authorized_keys", "%h/.ssh/k": "/home/alice/.ssh/k", "/etc/ssh/keys/%u": "/etc/ssh/keys/alice",
		"/k/%U": "/k/1000", "/k/%%u": "/k/%u", "/k/%x": "", "none": "", "/k/%": "",
	} {
		if got := expandKeysFile(spec, u); got != want {
			t.Errorf("%q: got %q, want %q", spec, got, want)
		}
	}
}

func TestParseAddr(t *testing.T) {
	for in, want := range map[string]string{
		"0100007F:0050": "127.0.0.1:80", "00000000:01BB": "0.0.0.0:443",
		"00000000000000000000000001000000:0016": "::1:22",
		"0000000000000000FFFF00000100007F:1F90": "127.0.0.1:8080",
		"B80D0120000000000000000001000000:0035": "2001:db8::1:53",
	} {
		a, p, err := parseAddr(in)
		if err != nil || fmt.Sprintf("%s:%d", a, p) != want {
			t.Errorf("%s: %s:%d %v, want %s", in, a, p, err, want)
		}
	}
	if _, _, err := parseAddr("zz:1"); err == nil {
		t.Error("bad address accepted")
	}
}

func TestKeysOnRemoteOrUnknownMounts(t *testing.T) {
	root, inv := fixture(t)
	dir, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	id, ok := mountID(int(dir.Fd()))
	dir.Close()
	if !ok {
		t.Fatal("no mnt_id in /proc/self/fdinfo")
	}
	for table, want := range map[string]string{
		fmt.Sprintf("%d 1 0:50 / / rw - fuse.sshfs alice@box:/ rw\n", id): "is on fuse.sshfs, which root does not read",
		"1 0 8:2 / / rw - ext4 /dev/sda2 rw\n":                            "a mount that appeared after the mount table was read",
		fmt.Sprintf("%d 1 0:50 / / rw - autofs systemd-1 rw\n", id):       "automounted (autofs)",
	} {
		mi := filepath.Join(t.TempDir(), "mountinfo")
		write(t, filepath.Dir(mi), "mountinfo", table)
		c := collector{ctx: context.Background(), inv: inv, d: Deps{Root: root, MountInfo: mi}}
		users, err := c.users()
		if err != nil {
			t.Fatal(err)
		}
		if users[0].Name != "root" || users[0].AuthorizedKeys != 0 || len(users[0].KeysUnread) != 2 || !strings.Contains(users[0].KeysUnread[0], want) {
			t.Errorf("%q: %+v", want, users[0])
		}
	}
}
