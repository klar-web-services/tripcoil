// Package agentnet manages the agent's nftables table, inet tripcoil (spec section 8.2). Its
// output chain applies only to packets of sockets owned by the agent's user: DNS to the
// nameservers and the allowed addresses are accepted, local, private, link-local and multicast
// ranges and the host's own addresses are blocked, everything else is accepted. The table is
// written through netlink, so no nft binary is needed.
package agentnet

import (
	"bufio"
	"bytes"
	"math/big"
	"net"
	"net/netip"
	"strings"

	"github.com/google/nftables"
)

// Name is the table's name in the inet family.
const Name = "tripcoil"

// rules is how many rules Apply writes; Present compares against it.
const rules = 10

// blocked are the ranges the agent may never reach, besides the host's own addresses: loopback,
// link-local, private, shared and multicast space, "this network" (0.0.0.0/8), the reserved
// 240.0.0.0/4, which holds the limited broadcast 255.255.255.255, and Azure's platform address
// 168.63.129.16, a public address that serves the VM's configuration like a metadata service
// (DNS to it stays allowed where it is the nameserver).
var blocked = []string{"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
	"224.0.0.0/4", "240.0.0.0/4", "168.63.129.16/32", "::1/128", "fe80::/10", "fc00::/7", "ff00::/8"}

// Policy is what the table enforces for one review.
type Policy struct {
	UID         uint32         // the agent's user
	Nameservers []netip.Addr   // DNS to these is accepted
	Allow       []netip.Prefix // review.allowAddresses
	Own         []netip.Addr   // the addresses on the host's interfaces
}

// Blocked is every range the policy blocks: the fixed ranges and the host's own addresses.
func (p Policy) Blocked() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range blocked {
		out = append(out, netip.MustParsePrefix(s))
	}
	return append(out, hosts(p.Own)...)
}

// Apply replaces the table in one netlink batch.
func Apply(p Policy) error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	build(c, p)
	return c.Flush()
}

// Present reports whether the table and its chain hold the rules Apply writes. A host firewall
// reload that flushes the ruleset removes them.
func Present() (bool, error) {
	c, err := nftables.New()
	if err != nil {
		return false, err
	}
	t, err := c.ListTableOfFamily(Name, nftables.TableFamilyINet)
	if err != nil {
		return false, nil
	}
	ch, err := c.ListChain(t, "output")
	if err != nil {
		return false, nil
	}
	rs, err := c.GetRules(t, ch)
	if err != nil {
		return false, err
	}
	return len(rs) == rules, nil
}

// Delete removes the table; a missing table is no error.
func Delete() error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	t := &nftables.Table{Family: nftables.TableFamilyINet, Name: Name}
	c.AddTable(t)
	c.DelTable(t)
	return c.Flush()
}

// OwnAddrs returns the addresses on the host's interfaces.
func OwnAddrs() ([]netip.Addr, error) {
	as, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range as {
		if n, ok := a.(*net.IPNet); ok {
			if ad, ok := netip.AddrFromSlice(n.IP); ok {
				out = append(out, ad.Unmap())
			}
		}
	}
	return out, nil
}

// Nameservers reads the nameserver lines of a resolv.conf.
func Nameservers(resolvConf []byte) []netip.Addr {
	var out []netip.Addr
	sc := bufio.NewScanner(bytes.NewReader(resolvConf))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		if a, err := netip.ParseAddr(f[1]); err == nil {
			out = append(out, a.WithZone("").Unmap())
		}
	}
	return out
}

// ParseAllow turns review.allowAddresses (addresses or CIDR ranges, validated by the config)
// into prefixes.
func ParseAllow(ss []string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
		} else if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, hosts([]netip.Addr{a})...)
		}
	}
	return out
}

func hosts(as []netip.Addr) []netip.Prefix {
	var out []netip.Prefix
	for _, a := range as {
		a = a.WithZone("").Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out
}

// minimal drops every prefix that another contains: an interval set rejects overlapping
// elements, and the host's own 127.0.0.1 and ::1 lie inside blocked ranges.
func minimal(ps []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for i, p := range ps {
		p = p.Masked()
		inside := false
		for j, q := range ps {
			q = q.Masked()
			if i != j && q.Bits() <= p.Bits() && q.Contains(p.Addr()) && (q.Bits() < p.Bits() || j < i) {
				inside = true
				break
			}
		}
		if !inside {
			out = append(out, p)
		}
	}
	return out
}

// split sorts the minimal prefixes into IPv4 and IPv6.
func split(ps []netip.Prefix) (v4, v6 []netip.Prefix) {
	for _, p := range minimal(ps) {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return v4, v6
}

// elems are a prefix's interval elements: its first address, and the first address after it as
// the interval's end (none when the prefix runs to the end of the address space).
func elems(ps []netip.Prefix) []nftables.SetElement {
	var out []nftables.SetElement
	for _, p := range ps {
		p = p.Masked()
		start := p.Addr().AsSlice()
		n := new(big.Int).SetBytes(start)
		size := new(big.Int).Lsh(big.NewInt(1), uint(p.Addr().BitLen()-p.Bits()))
		end := new(big.Int).Add(n, size)
		if end.BitLen() > len(start)*8 {
			out = append(out, nftables.SetElement{Key: start})
			continue
		}
		eb := make([]byte, len(start))
		end.FillBytes(eb)
		out = append(out, nftables.SetElement{Key: start}, nftables.SetElement{Key: eb, IntervalEnd: true})
	}
	return out
}
