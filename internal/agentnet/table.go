package agentnet

import (
	"encoding/binary"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func build(c *nftables.Conn, p Policy) {
	t := &nftables.Table{Family: nftables.TableFamilyINet, Name: Name}
	c.AddTable(t) // so that the delete cannot fail on a missing table
	c.DelTable(t)
	c.AddTable(t)
	policy := nftables.ChainPolicyAccept
	ch := c.AddChain(&nftables.Chain{Name: "output", Table: t, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter, Policy: &policy})

	dns4, dns6 := split(hosts(p.Nameservers))
	allow4, allow6 := split(p.Allow)
	block4, block6 := split(p.Blocked())
	set := func(name string, v6 bool, ps []netip.Prefix) *nftables.Set {
		kt := nftables.TypeIPAddr
		if v6 {
			kt = nftables.TypeIP6Addr
		}
		s := &nftables.Set{Table: t, Name: name, KeyType: kt, Interval: true}
		c.AddSet(s, elems(ps))
		return s
	}
	sets := [2]map[string]*nftables.Set{
		{"dns": set("dns4", false, dns4), "allow": set("allow4", false, allow4), "block": set("block4", false, block4)},
		{"dns": set("dns6", true, dns6), "allow": set("allow6", true, allow6), "block": set("block6", true, block6)},
	}

	uid := []expr.Any{&expr.Meta{Key: expr.MetaKeySKUID, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(p.UID)}}
	daddr := func(v6 int, s *nftables.Set) []expr.Any {
		fam, off, ln := byte(unix.NFPROTO_IPV4), uint32(16), uint32(4)
		if v6 == 1 {
			fam, off, ln = unix.NFPROTO_IPV6, 24, 16
		}
		return []expr.Any{&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{fam}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: ln},
			&expr.Lookup{SourceRegister: 1, SetName: s.Name, SetID: s.ID}}
	}
	l4 := func(proto byte) []expr.Any {
		return []expr.Any{&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}}}
	}
	rule := func(es ...[]expr.Any) {
		var all []expr.Any
		for _, e := range es {
			all = append(all, e...)
		}
		c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: all})
	}
	port := binary.BigEndian.AppendUint16(nil, 53)
	dport := []expr.Any{&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: port}}
	accept := []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}
	drop := []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}
	// A TCP connect that is dropped retries its SYN until it times out; a reset makes it fail at
	// once with ECONNREFUSED. Everything else is dropped, which a local sender sees as EPERM.
	reset := []expr.Any{&expr.Reject{Type: unix.NFT_REJECT_TCP_RST}}
	for v6 := range 2 {
		rule(uid, daddr(v6, sets[v6]["dns"]), l4(unix.IPPROTO_UDP), dport, accept)
		rule(uid, daddr(v6, sets[v6]["dns"]), l4(unix.IPPROTO_TCP), dport, accept)
	}
	for v6 := range 2 {
		rule(uid, daddr(v6, sets[v6]["allow"]), accept)
	}
	for v6 := range 2 {
		rule(uid, daddr(v6, sets[v6]["block"]), l4(unix.IPPROTO_TCP), reset)
	}
	for v6 := range 2 {
		rule(uid, daddr(v6, sets[v6]["block"]), drop)
	}
}
