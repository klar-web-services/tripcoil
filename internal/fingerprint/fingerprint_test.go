package fingerprint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/facts"
	"github.com/klar-web-services/tripcoil/internal/inventory"
)

// The rulesets in testdata/fingerprint were captured from real tools in throwaway containers:
// Docker 29.9.3 with two published ports, fail2ban 1.1.0 with its nftables and iptables actions,
// and nft 1.1.3 with CrowdSec's documented table layout and a dynamic set.
func load(t *testing.T, name, cmd string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../testdata/fingerprint", name))
	if err != nil {
		t.Fatal(err)
	}
	return "### " + cmd + "\n" + string(data)
}

func same(t *testing.T, what, a, b string) {
	t.Helper()
	if x, y := NormalizeFirewall(a), NormalizeFirewall(b); x != y {
		t.Errorf("%s: the normalized rulesets differ:\n%s\n----\n%s", what, x, y)
	}
}

func differ(t *testing.T, what, a, b string) {
	t.Helper()
	if NormalizeFirewall(a) == NormalizeFirewall(b) {
		t.Errorf("%s: the normalized rulesets are equal", what)
	}
}

func TestNormalizeDocker(t *testing.T) {
	nft := load(t, "docker-nft.txt", "nft -s list ruleset")
	recreated := strings.ReplaceAll(nft, "172.18.0.2", "172.18.0.3") // a recreated container gets a new address
	same(t, "nft, container recreated", nft, recreated)
	moved := strings.Replace(nft, "tcp dport 8080 counter", "tcp dport 8081 counter", 1)
	same(t, "nft, published port changed (covered by the containers' ports)", nft, moved)
	// docker compose down && up: a new bridge, often with a new subnet.
	compose := strings.ReplaceAll(strings.ReplaceAll(nft, "docker0", "br-0123456789ab"), "172.18.", "172.19.")
	recompose := strings.ReplaceAll(strings.ReplaceAll(nft, "docker0", "br-fedcba987654"), "172.18.", "172.20.")
	same(t, "nft, Compose network recreated", compose, recompose)
	norm := NormalizeFirewall(nft)
	if strings.Contains(norm, "chain DOCKER-FORWARD") || !strings.Contains(norm, "chain DOCKER-USER") || strings.Contains(norm, "172.18.0.2") || strings.Contains(norm, "counter") {
		t.Errorf("normalized:\n%s", norm)
	}
	if !strings.Contains(norm, "jump DOCKER-FORWARD") || !strings.Contains(norm, "table ip raw {") {
		t.Errorf("built-in chains and tables must stay:\n%s", norm)
	}
	ipt := load(t, "docker-iptables-save.txt", "iptables-save")
	later := strings.ReplaceAll(strings.ReplaceAll(ipt, "Sun Nov 15 01:06:43 2026", "Mon Nov 16 07:00:00 2026"), "172.18.0.2", "172.18.0.9")
	later = strings.Replace(later, ":PREROUTING ACCEPT [230:3821308]", ":PREROUTING ACCEPT [999:1]", 1)
	same(t, "iptables-save, later run and recreated container", ipt, later)
	same(t, "iptables-save, Compose network recreated", strings.ReplaceAll(strings.ReplaceAll(ipt, "docker0", "br-0123456789ab"), "172.18.", "172.19."),
		strings.ReplaceAll(strings.ReplaceAll(ipt, "docker0", "br-fedcba987654"), "172.18.", "172.21."))
	differ(t, "iptables-save, a new INPUT rule", ipt, strings.Replace(ipt, ":OUTPUT ACCEPT [0:0]\n", ":OUTPUT ACCEPT [0:0]\n-A INPUT -p tcp -m tcp --dport 3306 -j ACCEPT\n", 1))
}

func TestNormalizeFail2ban(t *testing.T) {
	nft := load(t, "fail2ban-nft.txt", "nft -s list ruleset")
	same(t, "nft, other bans", nft, strings.ReplaceAll(nft, "198.51.100.9, 203.0.113.7", "192.0.2.1"))
	same(t, "nft, no fail2ban table at all", nft, "### nft -s list ruleset\n")
	ipt := load(t, "fail2ban-iptables-save.txt", "iptables-save")
	same(t, "iptables-save, other bans", ipt, strings.Replace(ipt, "-A f2b-sshd -s 198.51.100.9/32 -j REJECT --reject-with icmp-port-unreachable\n", "", 1))
	if !strings.Contains(NormalizeFirewall(ipt), "-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd") {
		t.Error("the jump into fail2ban's chain is part of the exposure")
	}
}

func TestNormalizeTimeoutAndDynamicSets(t *testing.T) {
	nft := load(t, "crowdsec-like-nft.txt", "nft -s list ruleset")
	other := strings.Replace(nft, "elements = { 192.0.2.10 timeout 4h,\n\t\t\t     192.0.2.11 timeout 2h }", "elements = { 192.0.2.99 timeout 1h }", 1)
	other = strings.Replace(other, "elements = { 192.0.2.20 }", "elements = { 192.0.2.21, 192.0.2.22 }", 1)
	if other == nft {
		t.Fatal("the fixture did not change")
	}
	same(t, "timeout and dynamic set elements", nft, other)
	differ(t, "a plain set's elements", nft, strings.Replace(nft, "elements = { 22, 443 }", "elements = { 22, 443, 3306 }", 1))
	norm := NormalizeFirewall(nft)
	if strings.Contains(norm, "crowdsec") || strings.Contains(norm, "192.0.2.20") || !strings.Contains(norm, "flags dynamic,timeout") {
		t.Errorf("normalized:\n%s", norm)
	}
}

func TestNormalizeKeepsOtherText(t *testing.T) {
	if got := NormalizeFirewall("### nft -s list ruleset\n\n# No firewall rules are loaded.\n"); got != "### nft -s list ruleset\n# No firewall rules are loaded.\n" {
		t.Errorf("got %q", got)
	}
}

func base() Input {
	no := false
	fw := "### nft -s list ruleset\ntable inet filter {\n\tchain input {\n\t\ttcp dport 443 accept\n\t}\n}\n"
	sshd := "port 22\npermitrootlogin without-password\npasswordauthentication no\n"
	users := []facts.User{{Name: "root", UID: 0, Shell: "/bin/bash", Password: "none", AuthorizedKeys: 1, KeyFiles: []string{"/root/.ssh/authorized_keys"}},
		{Name: "alice", UID: 1000, Shell: "/bin/bash", Password: "locked", AuthorizedKeys: 2}}
	conts := []facts.Container{{Item: "container:web", CapAdd: []string{"NET_ADMIN", "SYS_TIME"}}}
	kern := &facts.Kernel{Sysctls: map[string]string{"kernel.unprivileged_bpf_disabled": "2", "kernel.yama.ptrace_scope": "1"}, Cmdline: "ro quiet"}
	return Input{
		Inventory: &inventory.Inventory{Items: []inventory.Item{
			{ID: "kernel", Kind: inventory.KindKernel, RebootPending: &no},
			{ID: "proc:nginx", Kind: inventory.KindProcess, RestartNeeded: []string{"/usr/lib/libssl.so.3"}},
			{ID: "container:web", Kind: inventory.KindContainer, Ports: []inventory.Port{{IP: "0.0.0.0", HostPort: 8080, ContainerPort: 80}}},
		}},
		Audit:    &audit.Audit{Findings: []audit.Finding{{ID: "f:1", Risk: "high", Fix: audit.Fix{State: "fixed"}}, {ID: "f:2", Risk: "low", Fix: audit.Fix{State: "not-fixed"}}}},
		Network:  &facts.Network{LocalPortRangeStart: 32768, Sockets: []facts.Socket{{Proto: "tcp", Address: "0.0.0.0", Port: 443, Items: []string{"proc:nginx"}}, {Proto: "udp", Address: "127.0.0.53", Port: 53, Items: []string{"proc:resolved"}}}},
		Firewall: &fw, SSHD: &sshd, Users: &users, Containers: &conts, Kernel: kern, PromptVersion: "1", Agent: "claude",
	}
}

func TestCompute(t *testing.T) {
	ref := Compute(base())
	if len(ref) != 64 || ref != Compute(base()) {
		t.Fatalf("fingerprint %q is not stable", ref)
	}
	unchanged := map[string]func(*Input){
		"findings reordered": func(in *Input) { f := in.Audit.Findings; f[0], f[1] = f[1], f[0] },
		"a UDP client socket": func(in *Input) {
			in.Network.Sockets = append(in.Network.Sockets, facts.Socket{Proto: "udp", Address: "0.0.0.0", Port: 41234})
		},
		"a connected UDP socket": func(in *Input) {
			in.Network.Sockets = append(in.Network.Sockets, facts.Socket{Proto: "udp", Address: "127.0.0.1", Port: 900, Connected: true})
		},
		"a fail2ban ban": func(in *Input) {
			s := *in.Firewall + "table inet f2b-table {\n\tset addr-set-sshd {\n\t\ttype ipv4_addr\n\t\telements = { 192.0.2.1 }\n\t}\n}\n"
			in.Firewall = &s
		},
		"a finding's text":        func(in *Input) { in.Audit.Findings[0].Remediation = "other words" },
		"capabilities reordered":  func(in *Input) { (*in.Containers)[0].CapAdd = []string{"SYS_TIME", "NET_ADMIN"} },
		"a key file's path":       func(in *Input) { (*in.Users)[0].KeyFiles = []string{"/etc/ssh/keys/root"} },
		"the kernel command line": func(in *Input) { in.Kernel.Cmdline = "ro" },
	}
	withIDE := func(port int) Input {
		in := base()
		in.Network.Sockets = append(in.Network.Sockets, facts.Socket{Proto: "tcp", Address: "127.0.0.1", Port: port, Items: []string{"proc:ide"}})
		return in
	}
	if Compute(withIDE(41000)) != Compute(withIDE(59000)) {
		t.Error("a listener's random port changed the fingerprint")
	}
	more := withIDE(41000)
	more.Network.Sockets = append(more.Network.Sockets, facts.Socket{Proto: "tcp", Address: "127.0.0.1", Port: 43000, Items: []string{"proc:ide"}})
	if Compute(more) != Compute(withIDE(41000)) {
		t.Error("a second ephemeral listener of the same item and address changed the fingerprint")
	}
	public := withIDE(41000)
	public.Network.Sockets[len(public.Network.Sockets)-1].Address = "0.0.0.0"
	if Compute(public) == Compute(withIDE(41000)) {
		t.Error("an ephemeral listener moving to 0.0.0.0 must change the fingerprint")
	}
	if Compute(withIDE(41000)) == ref {
		t.Error("a new listener, on any port, must change the fingerprint")
	}
	delete(unchanged, "an IDE's loopback listener on a new random port")
	for name, change := range unchanged {
		in := base()
		change(&in)
		if Compute(in) != ref {
			t.Errorf("%s changed the fingerprint", name)
		}
	}
	changed := map[string]func(*Input){
		"a new finding":    func(in *Input) { in.Audit.Findings = append(in.Audit.Findings, audit.Finding{ID: "f:3", Risk: "low"}) },
		"a risk tier":      func(in *Input) { in.Audit.Findings[1].Risk = "critical" },
		"a fix state":      func(in *Input) { in.Audit.Findings[1].Fix.State = "fixed" },
		"a restart needed": func(in *Input) { in.Inventory.Items[1].RestartNeeded = nil },
		"a reboot pending": func(in *Input) { yes := true; in.Inventory.Items[0].RebootPending = &yes },
		"a listening port": func(in *Input) {
			in.Network.Sockets = append(in.Network.Sockets, facts.Socket{Proto: "tcp", Address: "0.0.0.0", Port: 8443})
		},
		"a bind address": func(in *Input) { in.Network.Sockets[0].Address = "127.0.0.1" },
		"a bound UDP server port": func(in *Input) {
			in.Network.Sockets = append(in.Network.Sockets, facts.Socket{Proto: "udp", Address: "0.0.0.0", Port: 161})
		},
		"a firewall rule":         func(in *Input) { s := strings.Replace(*in.Firewall, "443", "443, 22", 1); in.Firewall = &s },
		"a missing firewall fact": func(in *Input) { in.Firewall = nil },
		"a missing network fact":  func(in *Input) { in.Network = nil },
		"a published port":        func(in *Input) { in.Inventory.Items[2].Ports[0].HostPort = 80 },
		"privileged mode":         func(in *Input) { in.Inventory.Items[2].Privileged = true },
		"the prompt version":      func(in *Input) { in.PromptVersion = "2" },
		"the agent":               func(in *Input) { in.Agent = "codex" },
		"the model":               func(in *Input) { in.Model = "opus" },
		"sshd allows passwords": func(in *Input) {
			s := strings.Replace(*in.SSHD, "passwordauthentication no", "passwordauthentication yes", 1)
			in.SSHD = &s
		},
		"a missing sshd fact": func(in *Input) { in.SSHD = nil },
		"a new user": func(in *Input) {
			*in.Users = append(*in.Users, facts.User{Name: "bob", UID: 1001, Shell: "/bin/sh", Password: "set"})
		},
		"an empty password":         func(in *Input) { (*in.Users)[1].Password = "empty" },
		"a new SSH key":             func(in *Input) { (*in.Users)[1].AuthorizedKeys = 3 },
		"a missing users fact":      func(in *Input) { in.Users = nil },
		"an added capability":       func(in *Input) { (*in.Containers)[0].CapAdd = append((*in.Containers)[0].CapAdd, "SYS_ADMIN") },
		"a Docker socket mount":     func(in *Input) { (*in.Containers)[0].DockerSocket = true },
		"host networking":           func(in *Input) { (*in.Containers)[0].HostNetwork = true },
		"the host's PID namespace":  func(in *Input) { (*in.Containers)[0].PIDMode = "host" },
		"a missing containers fact": func(in *Input) { in.Containers = nil },
		"a sysctl":                  func(in *Input) { in.Kernel.Sysctls["kernel.unprivileged_bpf_disabled"] = "0" },
		"a missing kernel fact":     func(in *Input) { in.Kernel = nil },
	}
	for name, change := range changed {
		in := base()
		change(&in)
		if Compute(in) == ref {
			t.Errorf("%s did not change the fingerprint", name)
		}
	}
}
