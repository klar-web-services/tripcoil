package facts

import (
	"context"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/inventory"
)

func prefixes(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// A workstation behind a home router: a LAN address with a global IPv6 one, a tailnet, a commercial
// VPN, Docker's bridges, and a host bridge over the network card.
func homeInterfaces() ([]NetInterface, error) {
	return []NetInterface{
		{Name: "lo", Up: true, Loopback: true, Addrs: prefixes("127.0.0.1/8", "::1/128")},
		{Name: "enp9s0", Up: true, Addrs: prefixes("192.168.178.100/24", "2a02:810c::1/64", "fe80::1/64")},
		{Name: "tailscale0", Up: true, Addrs: prefixes("100.112.221.35/32", "fd7a:115c:a1e0::35/128")},
		{Name: "proton0", Up: true, Addrs: prefixes("10.2.0.2/32", "2a07:b944::2/128")},
		{Name: "docker0", Up: true, Addrs: prefixes("172.17.0.1/16")},
		{Name: "veth1", Up: true, Addrs: prefixes("fe80::2/64")},
		{Name: "br0", Up: true, Addrs: prefixes("192.168.50.1/24")},
		{Name: "wlan0", Up: false, Addrs: prefixes("203.0.113.9/24")},
	}, nil
}

func homeSys(t *testing.T, root string) {
	t.Helper()
	net := "sys/class/net/"
	write(t, root, net+"lo/uevent", "INTERFACE=lo\n")
	write(t, root, net+"enp9s0/uevent", "INTERFACE=enp9s0\n")
	write(t, root, net+"enp9s0/device", "")
	write(t, root, net+"tailscale0/uevent", "INTERFACE=tailscale0\n")
	write(t, root, net+"tailscale0/tun_flags", "0x1001\n")
	write(t, root, net+"proton0/uevent", "DEVTYPE=wireguard\nINTERFACE=proton0\n")
	write(t, root, net+"docker0/uevent", "DEVTYPE=bridge\nINTERFACE=docker0\n")
	write(t, root, net+"docker0/brif/veth1", "")
	write(t, root, net+"veth1/uevent", "INTERFACE=veth1\n")
	write(t, root, net+"veth1/type", "1\n")
	write(t, root, net+"veth1/ifindex", "9\n")
	write(t, root, net+"veth1/iflink", "8\n")
	write(t, root, net+"br0/uevent", "DEVTYPE=bridge\nINTERFACE=br0\n")
	write(t, root, net+"br0/brif/enp9s0", "")
	write(t, root, net+"wlan0/uevent", "DEVTYPE=wlan\nINTERFACE=wlan0\n")
}

func TestAddresses(t *testing.T) {
	root := t.TempDir()
	homeSys(t, root)
	c := collector{ctx: context.Background(), d: Deps{Root: root, Interfaces: homeInterfaces}, inv: &inventory.Inventory{}}
	a, err := c.addresses()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, i := range a.Interfaces {
		var classes []string
		for _, ad := range i.Addresses {
			classes = append(classes, ad.Class)
		}
		flags := ""
		for name, on := range map[string]bool{" up": i.Up, " tailnet": i.Tailnet, " containerBridge": i.ContainerBridge, " behindRouter": i.BehindRouter} {
			if on {
				flags += name
			}
		}
		f := strings.Fields(flags)
		sortStrings(f)
		got[i.Name] = i.Kind + " [" + strings.Join(classes, " ") + "] " + strings.Join(f, " ")
	}
	want := map[string]string{
		"lo":         "loopback [loopback loopback] up",
		"enp9s0":     "ethernet [private global linkLocal] behindRouter up",
		"tailscale0": "tunnel [cgnat private] tailnet up",
		"proton0":    "tunnel [private global] behindRouter up",
		"docker0":    "bridge [private] containerBridge up",
		"veth1":      "veth [linkLocal] up",
		"br0":        "bridge [private] behindRouter up",
		"wlan0":      "wireless [global] ",
	}
	if a.Cloud || !reflect.DeepEqual(got, want) {
		t.Errorf("cloud %v\n got %v\nwant %v", a.Cloud, got, want)
	}

	// A cloud machine is never behind a router: its provider maps the private address to a public one.
	for name, file := range map[string][2]string{
		"cloud-init":   {"run/cloud-init/cloud-id", "hetzner\n"},
		"the vendor":   {"sys/class/dmi/id/sys_vendor", "Hetzner\n"},
		"Azure's tag":  {"sys/class/dmi/id/chassis_asset_tag", azureChassisTag + "\n"},
		"Amazon's DMI": {"sys/class/dmi/id/sys_vendor", "Amazon EC2\n"},
	} {
		root := t.TempDir()
		homeSys(t, root)
		write(t, root, file[0], file[1])
		c := collector{ctx: context.Background(), d: Deps{Root: root, Interfaces: homeInterfaces}, inv: &inventory.Inventory{}}
		a, err := c.addresses()
		if err != nil {
			t.Fatal(err)
		}
		for _, i := range a.Interfaces {
			if !a.Cloud || i.BehindRouter {
				t.Errorf("%s: cloud %v, %s behindRouter %v", name, a.Cloud, i.Name, i.BehindRouter)
			}
		}
	}

	if _, err := (collector{d: Deps{Root: root}}).addresses(); err == nil {
		t.Error("no interface source must be an error, so reach.json is not written")
	}

	// cloud-init without a provider runs on servers at home, and a tunnel whose other end is elsewhere
	// (sit, gre) is no veth pair: its global address must not count as this machine only.
	home := t.TempDir()
	homeSys(t, home)
	write(t, home, "run/cloud-init/cloud-id", "nocloud\n")
	write(t, home, "sys/class/net/sit1/uevent", "INTERFACE=sit1\n")
	write(t, home, "sys/class/net/sit1/type", "776\n")
	write(t, home, "sys/class/net/sit1/ifindex", "12\n")
	write(t, home, "sys/class/net/sit1/iflink", "2\n")
	withSit := func() ([]NetInterface, error) {
		ifs, _ := homeInterfaces()
		return append(ifs, NetInterface{Name: "sit1", Up: true, Addrs: prefixes("2001:db8::9/64")}), nil
	}
	a, err = (collector{ctx: context.Background(), d: Deps{Root: home, Interfaces: withSit}, inv: &inventory.Inventory{}}).addresses()
	if err != nil || a.Cloud {
		t.Fatalf("cloud-init without a provider: cloud %v, %v", a.Cloud, err)
	}
	for _, i := range a.Interfaces {
		if i.Name == "sit1" && (i.Kind != KindOther || a.reachOf("2001:db8::9") != ReachInternet) {
			t.Errorf("sit1: %+v, reach %s", i, a.reachOf("2001:db8::9"))
		}
	}
}

func sortStrings(s []string) {
	for i := range s {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}

func homeAddresses(t *testing.T, cloud bool) Addresses {
	t.Helper()
	root := t.TempDir()
	homeSys(t, root)
	if cloud {
		write(t, root, "run/cloud-init/cloud-id", "hetzner\n")
	}
	a, err := (collector{ctx: context.Background(), d: Deps{Root: root, Interfaces: homeInterfaces}, inv: &inventory.Inventory{}}).addresses()
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestReachOf(t *testing.T) {
	home := homeAddresses(t, false)
	for address, want := range map[string]string{
		"127.0.0.1":              ReachLocalhost,
		"127.0.0.53":             ReachLocalhost, // on no interface, but loopback
		"::1":                    ReachLocalhost,
		"172.17.0.1":             ReachLocalhost, // Docker's bridge
		"100.112.221.35":         ReachTailnet,
		"fd7a:115c:a1e0::35":     ReachTailnet,
		"192.168.178.100":        ReachLAN,
		"2a02:810c::1":           ReachLAN, // global, but behind the router
		"2a07:b944::2":           ReachLAN, // the VPN's far end translates as well
		"192.168.50.1":           ReachLAN, // a bridge over the network card is the machine's own
		"0.0.0.0":                ReachLAN,
		"::":                     ReachLAN,
		"":                       ReachLAN, // a published port without a host address
		"198.51.100.7":           ReachLAN, // on no interface: like the wildcard
		"::ffff:192.168.178.100": ReachLAN,
	} {
		if got := home.reachOf(address); got != want {
			t.Errorf("home %q: %s, want %s", address, got, want)
		}
	}
	// The interface that is down has the only global IPv4 address: it does not count.

	cloud := homeAddresses(t, true)
	for address, want := range map[string]string{
		"127.0.0.1": ReachLocalhost, "172.17.0.1": ReachLocalhost, "100.112.221.35": ReachTailnet,
		"192.168.178.100": ReachInternet, "0.0.0.0": ReachInternet, "::": ReachInternet,
	} {
		if got := cloud.reachOf(address); got != want {
			t.Errorf("cloud %q: %s, want %s", address, got, want)
		}
	}

	// A server with a public address, and one with IPv6 only.
	public := Addresses{Interfaces: []Interface{
		{Name: "lo", Kind: KindLoopback, Up: true, Addresses: []Address{{"127.0.0.1/8", ClassLoopback}}},
		{Name: "eth0", Kind: KindEthernet, Up: true, Addresses: []Address{{"203.0.113.5/24", ClassGlobal}, {"2001:db8::5/64", ClassGlobal}}},
		{Name: "eth1", Kind: KindEthernet, Up: true, BehindRouter: true, Addresses: []Address{{"10.0.0.5/24", ClassPrivate}}},
	}}
	for address, want := range map[string]string{"203.0.113.5": ReachInternet, "2001:db8::5": ReachInternet, "10.0.0.5": ReachLAN, "0.0.0.0": ReachInternet, "::": ReachInternet} {
		if got := public.reachOf(address); got != want {
			t.Errorf("public %q: %s, want %s", address, got, want)
		}
	}
	// Inside a system container the network card is a veth: it counts by its addresses.
	guest := Addresses{Interfaces: []Interface{{Name: "eth0", Kind: KindVeth, Up: true, BehindRouter: true,
		Addresses: []Address{{"10.0.3.5/24", ClassPrivate}, {"fe80::5/64", ClassLinkLocal}}}}}
	for address, want := range map[string]string{"10.0.3.5": ReachLAN, "0.0.0.0": ReachLAN, "fe80::5": ReachLocalhost} {
		if got := guest.reachOf(address); got != want {
			t.Errorf("guest %q: %s, want %s", address, got, want)
		}
	}
	v6only := Addresses{Interfaces: []Interface{{Name: "eth0", Kind: KindEthernet, Up: true, Addresses: []Address{{"2001:db8::5/64", ClassGlobal}}}}}
	if got := v6only.reachOf("::"); got != ReachInternet {
		t.Errorf("an IPv6-only server is not behind a router: %s", got)
	}
	if got := v6only.reachOf("0.0.0.0"); got != ReachLocalhost {
		t.Errorf("0.0.0.0 counts IPv4 addresses only: %s", got)
	}
}

func reachFixture(t *testing.T) (collector, Network, []Container) {
	t.Helper()
	root := t.TempDir()
	write(t, root, "proc/700/comm", "caddy\n")
	write(t, root, "proc/710/comm", "cloudflared\n")
	inv := &inventory.Inventory{Items: []inventory.Item{
		{ID: "kernel", Kind: inventory.KindKernel},
		{ID: "proc:sshd", Kind: inventory.KindProcess, Exe: "/usr/sbin/sshd"},
		{ID: "proc:local", Kind: inventory.KindProcess, Exe: "/usr/bin/local"},
		{ID: "proc:tail", Kind: inventory.KindProcess, Exe: "/usr/bin/tail"},
		{ID: "proc:worker", Kind: inventory.KindProcess, Exe: "/usr/bin/worker"},
		{ID: "container:web", Kind: inventory.KindContainer},
		{ID: "container:db", Kind: inventory.KindContainer},
	}}
	n := Network{LocalPortRangeStart: 32768, Sockets: []Socket{
		{Proto: "tcp", Address: "0.0.0.0", Port: 22, Items: []string{"proc:sshd"}},
		{Proto: "tcp", Address: "::", Port: 22, Items: []string{"proc:sshd"}},
		{Proto: "tcp", Address: "127.0.0.1", Port: 5000, Items: []string{"proc:local"}},
		{Proto: "tcp", Address: "100.112.221.35", Port: 8787, Items: []string{"proc:tail"}},
		{Proto: "udp", Address: "0.0.0.0", Port: 40000, Items: []string{"proc:local"}}, // a port the kernel handed out
		{Proto: "tcp", Address: "0.0.0.0", Port: 9, Items: []string{}},                 // nobody's
	}}
	conts := []Container{
		{Item: "container:web", Ports: []inventory.Port{{IP: "0.0.0.0", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}, {IP: "::", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}}},
		{Item: "container:db", Ports: []inventory.Port{{IP: "127.0.0.1", HostPort: 5432, ContainerPort: 5432, Protocol: "tcp"}, {ContainerPort: 9000, Protocol: "tcp"}}},
	}
	return collector{ctx: context.Background(), d: Deps{Root: root}, inv: inv}, n, conts
}

func summary(r Reach) map[string]string {
	out := map[string]string{}
	for _, i := range r.Items {
		f := []string{i.Default}
		if i.Via != "" {
			f = append(f, i.Via)
		}
		if i.Stated {
			f = append(f, "stated")
		}
		if i.Unsure != "" {
			f = append(f, "unsure")
		}
		out[i.Item] = strings.Join(f, " ")
	}
	return out
}

func TestDefaultReach(t *testing.T) {
	c, n, conts := reachFixture(t)
	home := homeAddresses(t, false)
	r := c.reach(n, conts, home, Routes{})
	want := map[string]string{"proc:sshd": "lan direct", "proc:local": "localhost direct", "proc:tail": "tailnet direct",
		"container:web": "lan direct", "container:db": "localhost direct"}
	if got := summary(r); !reflect.DeepEqual(got, want) {
		t.Errorf("\n got %v\nwant %v", got, want)
	}
	for _, i := range r.Items {
		if i.Item == "container:db" && (len(i.Sockets) != 1 || !i.Sockets[0].Published || i.Sockets[0].Port != 5432) {
			t.Errorf("a port that is only exposed is not published: %+v", i.Sockets)
		}
	}

	// The owner states the ports: it decides between lan and internet, and nothing else.
	c.d.InternetPorts = &[]int{8080}
	want = map[string]string{"proc:sshd": "lan direct stated", "proc:local": "localhost direct", "proc:tail": "tailnet direct",
		"container:web": "internet direct stated", "container:db": "localhost direct"}
	if got := summary(c.reach(n, conts, home, Routes{})); !reflect.DeepEqual(got, want) {
		t.Errorf("stated ports:\n got %v\nwant %v", got, want)
	}
	c.d.InternetPorts = &[]int{}
	if got := summary(c.reach(n, conts, homeAddresses(t, true), Routes{}))["proc:sshd"]; got != "lan direct stated" {
		t.Errorf("an empty list closes a cloud machine's ports too: %s", got)
	}
	c.d.InternetPorts = nil
}

// What a proxy or tunnel routes to is reachable from wherever that program is; a program whose
// routing is not fully known puts in doubt whatever it could publish further.
func TestReachThroughRoutes(t *testing.T) {
	c, n, conts := workstation(t)
	home := homeAddresses(t, false)
	routes := c.routes(n, conts, home)
	r := c.reach(n, conts, home, routes)
	want := map[string]string{
		// The tunnel publishes the user's Caddy and the api, and through that Caddy the MCP server: a chain.
		"proc:cloudflared": "internet tunnel", "proc:caddy": "internet tunnel", "proc:api": "internet tunnel", "proc:mcp": "internet proxy",
		// The stack's Caddy is on the LAN, and so is what it routes to; what it does not route to keeps its own reach.
		"container:caddy": "lan direct", "container:sonarr": "lan direct", "container:arr-dashboard": "lan proxy", "container:gluetun": "lan proxy",
		"container:jellyfin": "lan proxy", "container:flaresolverr": "localhost direct", "proc:editor": "localhost direct",
	}
	if got := summary(r); !reflect.DeepEqual(got, want) {
		t.Errorf("\n got %v\nwant %v", got, want)
	}
	wantRouters := []Router{
		{Item: "container:caddy", Program: "caddy", Kind: ViaProxy, Reach: ReachLAN, Complete: true},
		{Item: "proc:caddy", Program: "caddy", Kind: ViaProxy, Reach: ReachInternet, Complete: true},
		{Item: "proc:cloudflared", Program: "cloudflared", Kind: ViaTunnel, Reach: ReachInternet, Complete: true},
	}
	if !reflect.DeepEqual(r.Routers, wantRouters) {
		t.Errorf("routers %+v", r.Routers)
	}
	for _, i := range r.Items {
		if i.Item == "proc:mcp" && !reflect.DeepEqual(i.Through, []string{"proc:caddy"}) {
			t.Errorf("through: %+v", i.Through)
		}
	}
	// A program that starts or stops and has no socket changes nothing here.
	c.inv.Items = append(c.inv.Items, inventory.Item{ID: "proc:idle", Kind: inventory.KindProcess})
	if again := c.reach(n, conts, home, c.routes(n, conts, home)); !reflect.DeepEqual(again, r) {
		t.Errorf("an unrelated program changed the fact")
	}

	// The tunnel's routing is not known: everything that is not public already is in doubt. The
	// tunnel's own program is what the internet reaches first.
	for i := range routes.Programs {
		if routes.Programs[i].Kind == ViaTunnel {
			routes.Programs[i].Complete, routes.Programs[i].Gaps, routes.Programs[i].Targets = false, []string{"the tunnel is started with a token"}, nil
		}
	}
	r = c.reach(n, conts, home, routes)
	want = map[string]string{
		"proc:cloudflared": "internet tunnel", "proc:caddy": "localhost direct unsure", "proc:api": "localhost direct unsure", "proc:mcp": "localhost direct unsure",
		"container:caddy": "lan direct unsure", "container:sonarr": "lan direct unsure", "container:arr-dashboard": "lan proxy unsure", "container:gluetun": "lan proxy unsure",
		"container:jellyfin": "lan proxy unsure", "container:flaresolverr": "localhost direct unsure", "proc:editor": "localhost direct unsure",
	}
	if got := summary(r); !reflect.DeepEqual(got, want) {
		t.Errorf("an unread tunnel:\n got %v\nwant %v", got, want)
	}
	for _, i := range r.Items {
		if i.Item == "proc:editor" && i.Unsure != "cloudflared runs here and could pass requests from the internet on to this item; Tripcoil could not read all of its routing (the tunnel is started with a token)" {
			t.Errorf("unsure must say why: %q", i.Unsure)
		}
	}

	// An unread proxy on the LAN puts only what is narrower than the LAN in doubt; one without a
	// socket of its own may listen where Tripcoil cannot see it, and counts as public.
	lan := Routes{Programs: []RouteProgram{{Item: "container:caddy", Program: "caddy", Kind: ViaProxy, Gaps: []string{"its configuration was not found"}}}}
	got := summary(c.reach(n, conts, home, lan))
	if got["container:sonarr"] != "lan direct" || got["container:flaresolverr"] != "localhost direct unsure" || got["proc:editor"] != "localhost direct unsure" || got["container:caddy"] != "lan direct" {
		t.Errorf("an unread proxy on the LAN: %v", got)
	}
	hidden := Routes{Programs: []RouteProgram{{Item: "container:gluetun", Program: "traefik", Kind: ViaProxy, Gaps: []string{"its configuration was not found"}}}}
	r = c.reach(n, conts, home, hidden)
	if got := summary(r); got["container:sonarr"] != "lan direct unsure" || r.Routers[0].Reach != ReachInternet {
		t.Errorf("a proxy without a socket: %v, %+v", got, r.Routers)
	}

	// Tailscale Serve offers a port to the tailnet, whatever tailscaled's own sockets say.
	serve := Routes{Programs: []RouteProgram{{Item: "proc:cloudflared", Program: "tailscaled", Kind: ViaProxy, Tailnet: true, Complete: true, Targets: []RouteTarget{{Target: "127.0.0.1:6000", Item: "proc:editor"}}}}}
	if got := summary(c.reach(n, conts, home, serve)); got["proc:editor"] != "tailnet proxy" {
		t.Errorf("Tailscale Serve: %v", got)
	}
}

// A Swarm service's mesh ports are on every node; where they cannot be listed, and for a container
// with an address of its own on the LAN, the default is in doubt.
func TestReachOfSwarmAndMacvlan(t *testing.T) {
	c := collector{ctx: context.Background(), inv: &inventory.Inventory{}, d: Deps{}}
	conts := []Container{
		{Item: "container:web", Service: "shop_web", MeshPorts: []inventory.Port{{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}}},
		{Item: "container:worker", Service: "shop_worker", MeshUnknown: true},
		{Item: "container:cam", OwnAddress: true, Ports: []inventory.Port{{IP: "127.0.0.1", HostPort: 9000, ContainerPort: 80, Protocol: "tcp"}}},
		{Item: "container:plain"},
	}
	r := c.reach(Network{}, conts, homeAddresses(t, true), Routes{})
	want := map[string]string{"container:web": "internet direct", "container:worker": "none unsure", "container:cam": "localhost direct unsure"}
	if got := summary(r); !reflect.DeepEqual(got, want) {
		t.Errorf("\n got %v\nwant %v", got, want)
	}
}

func TestCollectWritesReach(t *testing.T) {
	root, inv := fixture(t)
	homeSys(t, root)
	d := Deps{Root: root, Run: fakeRun(t, map[string]string{}, new([]string)), LookPath: func(string) (string, error) { return "", errNotFound },
		Docker: fakeDocker{"c1": {}}, Interfaces: homeInterfaces, InternetPorts: &[]int{443}}
	runDir := t.TempDir()
	if _, err := Collect(context.Background(), d, inv, runDir); err != nil {
		t.Fatal(err)
	}
	var r Reach
	readJSON(t, filepath.Join(runDir, "facts/reach.json"), &r)
	got := summary(r)
	// No process of the fixture is a proxy or a tunnel, and an item without a socket has no entry.
	_, shop := got["proc:shop"]
	var routes Routes
	readJSON(t, filepath.Join(runDir, "facts/routes.json"), &routes)
	if got["proc:nginx"] != "internet direct stated" || got["proc:sshd"] != "lan direct stated" || got["container:web"] != "lan direct stated" ||
		shop || len(r.Routers) != 0 || routes.Programs == nil || len(routes.Programs) != 0 {
		t.Errorf("reach.json: %v", got)
	}
	var a Addresses
	readJSON(t, filepath.Join(runDir, "facts/addresses.json"), &a)
	if len(a.Interfaces) != 8 {
		t.Errorf("addresses.json: %+v", a)
	}
}
