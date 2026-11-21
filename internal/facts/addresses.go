package facts

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Addresses is facts/addresses.json: the machine's interfaces, so a public address can be told from
// a private one. It stays on the machine.
type Addresses struct {
	Cloud      bool        `json:"cloud"`
	Interfaces []Interface `json:"interfaces"`
}

type Interface struct {
	Name            string    `json:"name"`
	Kind            string    `json:"kind"`
	Up              bool      `json:"up"`
	Tailnet         bool      `json:"tailnet,omitempty"`
	ContainerBridge bool      `json:"containerBridge,omitempty"`
	BehindRouter    bool      `json:"behindRouter,omitempty"`
	Addresses       []Address `json:"addresses"`
}

type Address struct {
	Address string `json:"address"`
	Class   string `json:"class"`
}

const (
	KindLoopback = "loopback"
	KindEthernet = "ethernet"
	KindWireless = "wireless"
	KindBridge   = "bridge"
	KindVeth     = "veth"
	KindTunnel   = "tunnel"
	KindOther    = "other"

	ClassLoopback  = "loopback"
	ClassLinkLocal = "linkLocal"
	ClassPrivate   = "private"
	ClassCGNAT     = "cgnat"
	ClassGlobal    = "global"
)

// NetInterface is what the kernel says about one interface.
type NetInterface struct {
	Name     string
	Up       bool
	Loopback bool
	Addrs    []netip.Prefix
}

// SystemInterfaces reads the interfaces and their addresses over netlink: /proc and /sys hold no
// IPv4 addresses.
func SystemInterfaces() ([]NetInterface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []NetInterface
	for _, i := range ifs {
		n := NetInterface{Name: i.Name, Up: i.Flags&net.FlagUp != 0, Loopback: i.Flags&net.FlagLoopback != 0}
		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			ones, _ := ipn.Mask.Size()
			if ok {
				ip = ip.Unmap()
				n.Addrs = append(n.Addrs, netip.PrefixFrom(ip, min(ones, ip.BitLen())))
			}
		}
		out = append(out, n)
	}
	return out, nil
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func classOf(a netip.Addr) string {
	switch {
	case a.IsLoopback():
		return ClassLoopback
	case a.IsLinkLocalUnicast():
		return ClassLinkLocal
	case cgnat.Contains(a):
		return ClassCGNAT
	case a.IsPrivate():
		return ClassPrivate
	}
	return ClassGlobal
}

func (c collector) addresses() (Addresses, error) {
	if c.d.Interfaces == nil {
		return Addresses{}, errors.New("the interfaces were not read")
	}
	ifs, err := c.d.Interfaces()
	if err != nil {
		return Addresses{}, err
	}
	out := Addresses{Cloud: c.cloud(), Interfaces: []Interface{}}
	for _, n := range ifs {
		i := Interface{Name: n.Name, Kind: c.interfaceKind(n), Up: n.Up, Addresses: []Address{}}
		i.Tailnet = strings.HasPrefix(n.Name, "tailscale")
		v4, global4 := false, false
		for _, p := range n.Addrs {
			class := classOf(p.Addr())
			i.Addresses = append(i.Addresses, Address{Address: p.String(), Class: class})
			if p.Addr().Is4() {
				v4 = true
				global4 = global4 || class == ClassGlobal
			}
		}
		i.BehindRouter = v4 && !global4 && !out.Cloud && i.Kind != KindLoopback && !i.Tailnet
		out.Interfaces = append(out.Interfaces, i)
	}
	kinds := map[string]string{}
	for _, i := range out.Interfaces {
		kinds[i.Name] = i.Kind
	}
	for k := range out.Interfaces {
		i := &out.Interfaces[k]
		if i.Kind != KindBridge || slices.ContainsFunc(i.Addresses, func(a Address) bool { return a.Class == ClassGlobal }) {
			continue
		}
		members, _ := os.ReadDir(filepath.Join(c.d.Root, "sys/class/net", i.Name, "brif"))
		i.ContainerBridge = !slices.ContainsFunc(members, func(m os.DirEntry) bool { return kinds[m.Name()] != KindVeth })
		if i.ContainerBridge {
			i.BehindRouter = false
		}
	}
	slices.SortFunc(out.Interfaces, func(a, b Interface) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

func (c collector) interfaceKind(n NetInterface) string {
	dir := filepath.Join(c.d.Root, "sys/class/net", n.Name)
	has := func(name string) bool {
		_, err := os.Lstat(filepath.Join(dir, name))
		return err == nil
	}
	read := func(name string) string {
		data, _ := os.ReadFile(filepath.Join(dir, name))
		return strings.TrimSpace(string(data))
	}
	devtype := ""
	for _, l := range strings.Split(read("uevent"), "\n") {
		if v, ok := strings.CutPrefix(l, "DEVTYPE="); ok {
			devtype = v
		}
	}
	switch {
	case n.Loopback:
		return KindLoopback
	case devtype == "bridge" || has("bridge"):
		return KindBridge
	case devtype == "wlan" || has("wireless") || has("phy80211"):
		return KindWireless
	case devtype == "wireguard" || has("tun_flags"):
		return KindTunnel
	case devtype == "" && has("device"):
		return KindEthernet
	case devtype == "" && read("type") == "1" && read("iflink") != "" && read("iflink") != read("ifindex"): // an Ethernet device whose other end is elsewhere
		return KindVeth
	}
	return KindOther
}

// cloudVendors are DMI system vendors of providers that map a private address to a public one.
var cloudVendors = []string{"Amazon EC2", "Google", "Hetzner", "DigitalOcean", "OracleCloud", "Scaleway", "Vultr", "Linode", "Akamai", "OVH", "UpCloud", "Alibaba Cloud", "Tencent Cloud"}

const azureChassisTag = "7783-7084-3265-9085-8269-3286-77"

func (c collector) cloud() bool {
	// cloud-init names the provider it found; it also runs, without one, on servers at home.
	if id, err := os.ReadFile(filepath.Join(c.d.Root, "run/cloud-init/cloud-id")); err == nil {
		if id := strings.TrimSpace(string(id)); id != "" && id != "none" && id != "nocloud" {
			return true
		}
	}
	read := func(name string) string {
		data, _ := os.ReadFile(filepath.Join(c.d.Root, "sys/class/dmi/id", name))
		return strings.TrimSpace(string(data))
	}
	vendor := read("sys_vendor")
	return read("chassis_asset_tag") == azureChassisTag ||
		slices.ContainsFunc(cloudVendors, func(v string) bool { return strings.HasPrefix(vendor, v) })
}
