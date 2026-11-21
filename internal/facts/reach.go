package facts

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/klar-web-services/tripcoil/internal/inventory"
)

// Where an attacker can connect to an item from, narrowest first.
const (
	ReachNone      = "none"
	ReachLocalhost = "localhost"
	ReachTailnet   = "tailnet"
	ReachLAN       = "lan"
	ReachInternet  = "internet"
	ReachUnknown   = "unknown"

	ViaDirect  = "direct"
	ViaProxy   = "proxy"
	ViaTunnel  = "tunnel"
	ViaForward = "forward"
)

var reaches = []string{ReachNone, ReachLocalhost, ReachTailnet, ReachLAN, ReachInternet}

// ReachRank orders the reaches, narrowest first; -1 for unknown or anything else.
func ReachRank(reach string) int { return slices.Index(reaches, reach) }

func wider(a, b string) string {
	if ReachRank(b) > ReachRank(a) {
		return b
	}
	return a
}

// Reach is facts/reach.json: the default reach of each item that has a socket or a published port,
// judged by its bind addresses alone, and of each tunnel's own program. It ignores the firewall and
// is never enough to lower a finding.
type Reach struct {
	Items []ItemReach `json:"items"`
	// Routers are the proxies and tunnels that run here. Each may publish an item, with or without
	// sockets of its own, further than this fact says.
	Routers []Router `json:"routers"`
}

type Router struct {
	Item    string `json:"item"`
	Program string `json:"program"`
	// Kind is ViaProxy or ViaTunnel.
	Kind  string `json:"kind"`
	Reach string `json:"reach"`
}

type ItemReach struct {
	Item    string `json:"item"`
	Default string `json:"default"`
	Via     string `json:"via,omitempty"`
	// Unsure says why the item may be reachable from further away than Default.
	Unsure string `json:"unsure,omitempty"`
	// Stated: the owner's exposure.internetPorts decided between lan and internet.
	Stated  bool          `json:"stated,omitempty"`
	Sockets []ReachSocket `json:"sockets"`
}

type ReachSocket struct {
	Proto     string `json:"proto"`
	Address   string `json:"address"`
	Port      int    `json:"port"`
	Published bool   `json:"published,omitempty"`
	Reach     string `json:"reach"`
}

// reachOf is the reach a socket bound to address has: by the interface that carries the address, or,
// for the wildcard and an address on no interface, the widest over the interfaces that are up.
func (a Addresses) reachOf(address string) string {
	ip, err := netip.ParseAddr(address)
	if err == nil {
		ip = ip.Unmap()
		if ip.IsLoopback() {
			return ReachLocalhost
		}
		for _, i := range a.Interfaces {
			for _, ad := range i.Addresses {
				if p, err := netip.ParsePrefix(ad.Address); err == nil && p.Addr() == ip {
					return a.reachThrough(i, ad.Class)
				}
			}
		}
	}
	v4Only := err == nil && ip.IsUnspecified() && ip.Is4()
	out := ReachLocalhost
	for _, i := range a.Interfaces {
		if !i.Up {
			continue
		}
		for _, ad := range i.Addresses {
			p, err := netip.ParsePrefix(ad.Address)
			if err != nil || (v4Only && !p.Addr().Is4()) {
				continue
			}
			out = wider(out, a.reachThrough(i, ad.Class))
		}
	}
	return out
}

func (a Addresses) reachThrough(i Interface, class string) string {
	switch {
	// The host's end of a container's veth pair has a link-local address only. Inside a system
	// container the veth is the machine's network card, and counts by its addresses.
	case i.Kind == KindLoopback || class == ClassLoopback, i.ContainerBridge, i.Kind == KindVeth && class == ClassLinkLocal:
		return ReachLocalhost
	case i.Tailnet:
		return ReachTailnet
	case a.Cloud, class == ClassGlobal && !i.BehindRouter:
		return ReachInternet
	}
	return ReachLAN
}

// routers are the programs that pass outside requests on to other items: their kind by executable name.
var routers = map[string]string{
	"traefik": ViaProxy, "caddy": ViaProxy, "nginx": ViaProxy, "haproxy": ViaProxy, "envoy": ViaProxy,
	"cloudflared": ViaTunnel, "ngrok": ViaTunnel, "frpc": ViaTunnel,
}

// programs names what an item runs: its executable, and the command of each of its processes.
func (c collector) programs(it inventory.Item) []string {
	var out []string
	if it.Exe != "" {
		out = append(out, filepath.Base(it.Exe))
	}
	pids := slices.Clone(it.PIDs)
	for _, p := range it.Processes {
		pids = append(pids, p.PID)
	}
	for _, pid := range pids {
		if data, err := os.ReadFile(filepath.Join(c.d.Root, "proc", strconv.Itoa(pid), "comm")); err == nil {
			out = append(out, strings.TrimSpace(string(data)))
		}
	}
	return out
}

func (c collector) reach(n Network, conts []Container, a Addresses) Reach {
	byItem := map[string]*ItemReach{}
	add := func(item string, s ReachSocket, port int) {
		r := byItem[item]
		if r == nil {
			r = &ItemReach{Item: item, Default: ReachNone, Via: ViaDirect, Sockets: []ReachSocket{}}
			byItem[item] = r
		}
		if c.d.InternetPorts != nil && ReachRank(s.Reach) >= ReachRank(ReachLAN) {
			s.Reach, r.Stated = ReachLAN, true
			if slices.Contains(*c.d.InternetPorts, port) {
				s.Reach = ReachInternet
			}
		}
		if !slices.Contains(r.Sockets, s) {
			r.Sockets = append(r.Sockets, s)
		}
		r.Default = wider(r.Default, s.Reach)
	}
	for _, s := range n.Exposed() {
		for _, item := range s.Items {
			add(item, ReachSocket{Proto: s.Proto, Address: s.Address, Port: s.Port, Reach: a.reachOf(s.Address)}, s.Port)
		}
	}
	for _, ct := range conts {
		for _, p := range ct.Ports {
			if p.HostPort > 0 {
				add(ct.Item, ReachSocket{Proto: p.Protocol, Address: p.IP, Port: p.HostPort, Published: true, Reach: a.reachOf(p.IP)}, p.HostPort)
			}
		}
	}

	// Until Tripcoil reads what proxies and tunnels route to, each of them puts in doubt every item it
	// could publish further. A proxy without a socket of its own may listen where Tripcoil cannot
	// see it (Swarm's routing mesh), so it counts as public.
	out := Reach{Items: []ItemReach{}, Routers: []Router{}}
	for _, it := range c.inv.Items {
		for _, name := range c.programs(it) {
			kind, ok := routers[name]
			if !ok {
				continue
			}
			r := Router{Item: it.ID, Program: name, Kind: kind, Reach: ReachInternet}
			own := byItem[it.ID]
			switch {
			case kind == ViaProxy && own != nil:
				r.Reach = own.Default
			case kind == ViaTunnel: // what comes through the tunnel reaches the tunnel's own program first
				if own == nil {
					own = &ItemReach{Item: it.ID, Sockets: []ReachSocket{}}
					byItem[it.ID] = own
				}
				own.Default, own.Via = ReachInternet, ViaTunnel
			}
			out.Routers = append(out.Routers, r)
			break
		}
	}
	for _, r := range byItem {
		for _, rt := range out.Routers {
			if rt.Item != r.Item && ReachRank(rt.Reach) > ReachRank(r.Default) {
				r.Unsure = fmt.Sprintf("%s runs here and could pass requests from the %s on to this item; Tripcoil does not read what it routes to", rt.Program, describeReach(rt.Reach))
				break
			}
		}
	}

	for _, r := range byItem {
		slices.SortFunc(r.Sockets, func(x, y ReachSocket) int {
			return cmpAll(strings.Compare(x.Proto, y.Proto), x.Port-y.Port, strings.Compare(x.Address, y.Address), boolCmp(x.Published, y.Published))
		})
		out.Items = append(out.Items, *r)
	}
	slices.SortFunc(out.Items, func(x, y ItemReach) int { return strings.Compare(x.Item, y.Item) })
	return out
}

func describeReach(reach string) string {
	switch reach {
	case ReachLAN:
		return "LAN"
	case ReachLocalhost:
		return "machine itself"
	}
	return reach
}
