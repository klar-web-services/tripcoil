package facts

import (
	"fmt"
	"net/netip"
	"slices"
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

// Reach is facts/reach.json: the default reach of each item that has a socket or a published port
// or that a proxy or tunnel routes to, judged by the bind addresses and by facts/routes.json. It
// ignores the firewall and a proxy's own rules, and is never enough to lower a finding.
type Reach struct {
	Items []ItemReach `json:"items"`
	// Routers are the proxies and tunnels that run here, with the place each takes requests from. One
	// that is not complete may publish an item, with or without sockets of its own, further than
	// this fact says.
	Routers []Router `json:"routers"`
}

type Router struct {
	Item    string `json:"item"`
	Program string `json:"program"`
	// Kind is ViaProxy or ViaTunnel.
	Kind  string `json:"kind"`
	Reach string `json:"reach"`
	// Complete: Tripcoil read all of its routing, and facts/routes.json names everything it routes to.
	Complete bool `json:"complete"`
	// NamesPointTo sums up where the hostnames it serves resolve to: "global", "private", or nothing
	// when none resolved.
	NamesPointTo string `json:"namesPointTo,omitempty"`
}

type ItemReach struct {
	Item    string `json:"item"`
	Default string `json:"default"`
	Via     string `json:"via,omitempty"`
	// Unsure says why the item may be reachable from further away than Default.
	Unsure string `json:"unsure,omitempty"`
	// Stated: the owner's exposure.internetPorts decided between lan and internet.
	Stated bool `json:"stated,omitempty"`
	// Through are the items of the proxies and tunnels that route to it.
	Through []string      `json:"through,omitempty"`
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

func (c collector) reach(n Network, conts []Container, a Addresses, routes Routes) Reach {
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

	for _, ct := range conts {
		for _, p := range ct.MeshPorts { // Swarm's routing mesh publishes these on every address of every node
			add(ct.Item, ReachSocket{Proto: p.Protocol, Port: p.HostPort, Published: true, Reach: a.reachOf("")}, p.HostPort)
		}
	}

	entry := func(item string) *ItemReach {
		r := byItem[item]
		if r == nil {
			r = &ItemReach{Item: item, Default: ReachNone, Sockets: []ReachSocket{}}
			byItem[item] = r
		}
		return r
	}
	// From where a routing program takes requests. A tunnel takes them from the internet, whatever
	// its sockets say, and what comes through reaches the tunnel's own program first. A proxy without
	// a socket of its own may listen where Tripcoil cannot see it, so it counts as public.
	reachOf := func(p RouteProgram) string {
		switch own := byItem[p.Item]; {
		case p.Kind == ViaTunnel:
			return ReachInternet
		case p.Tailnet:
			return ReachTailnet
		case own != nil:
			return own.Default
		}
		return ReachInternet
	}
	for _, p := range routes.Programs {
		if p.Kind == ViaTunnel {
			e := entry(p.Item)
			e.Default, e.Via = ReachInternet, ViaTunnel
		}
	}
	// An item a program routes to is reachable from wherever the program is. Programs route to each
	// other (a tunnel to a proxy to an application), so this repeats until nothing widens.
	for widened, pass := true, 0; widened && pass < 16; pass++ {
		widened = false
		for _, p := range routes.Programs {
			from := reachOf(p)
			for _, t := range p.Targets {
				if t.Item == "" || t.Item == p.Item {
					continue
				}
				e := entry(t.Item)
				if !slices.Contains(e.Through, p.Item) {
					e.Through = append(e.Through, p.Item)
				}
				if ReachRank(from) > ReachRank(e.Default) {
					e.Default, e.Via, widened = from, p.Kind, true
				}
			}
		}
	}
	out := Reach{Items: []ItemReach{}, Routers: []Router{}}
	for _, p := range routes.Programs {
		out.Routers = append(out.Routers, Router{Item: p.Item, Program: p.Program, Kind: p.Kind, Reach: reachOf(p), Complete: p.Complete, NamesPointTo: p.pointTo()})
	}
	// A program whose routing is not fully known may publish any item further than this fact says.
	for _, r := range byItem {
		for _, p := range routes.Programs {
			if from := reachOf(p); !p.Complete && p.Item != r.Item && ReachRank(from) > ReachRank(r.Default) {
				r.Unsure = fmt.Sprintf("%s runs here and could pass requests from the %s on to this item; Tripcoil could not read all of its routing (%s)", p.Program, describeReach(from), p.Gaps[0])
				break
			}
		}
	}
	for _, ct := range conts {
		switch {
		case ct.MeshUnknown:
			entry(ct.Item).Unsure = "its Swarm service may publish ports through the routing mesh, which this node cannot list"
		case ct.OwnAddress:
			entry(ct.Item).Unsure = "it is on a macvlan or ipvlan network, with an address of its own on the LAN"
		}
	}

	// A container that uses another container's network answers on that one's ports and is reached
	// wherever that one is; when that one is not known, its reach is in doubt.
	for _, it := range c.inv.Items {
		id, shared := strings.CutPrefix(it.NetworkMode, "container:")
		if it.Kind != inventory.KindContainer || !shared {
			continue
		}
		owner := slices.IndexFunc(c.inv.Items, func(o inventory.Item) bool {
			return o.Kind == inventory.KindContainer && o.ID != it.ID && (o.ContainerID == id || o.Name == id)
		})
		if owner < 0 {
			entry(it.ID).Unsure = "it uses the network of a container that Tripcoil does not know"
			continue
		}
		if from := byItem[c.inv.Items[owner].ID]; from != nil {
			own := *from
			own.Item = it.ID
			own.Sockets, own.Through = slices.Clone(from.Sockets), slices.Clone(from.Through)
			byItem[it.ID] = &own
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
