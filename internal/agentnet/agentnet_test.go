package agentnet

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/google/nftables"
)

func prefixes(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestMinimal(t *testing.T) {
	got := minimal(prefixes("127.0.0.0/8", "127.0.0.1/32", "10.0.0.0/8", "10.0.0.0/8", "203.0.113.7/32", "::1/128", "::1/128", "fe80::/10", "fe80::1/128"))
	want := prefixes("127.0.0.0/8", "10.0.0.0/8", "203.0.113.7/32", "::1/128", "fe80::/10")
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestElems(t *testing.T) {
	got := elems(prefixes("10.0.0.0/8", "203.0.113.7/32", "ff00::/8", "224.0.0.0/4"))
	want := []nftables.SetElement{
		{Key: []byte{10, 0, 0, 0}}, {Key: []byte{11, 0, 0, 0}, IntervalEnd: true},
		{Key: []byte{203, 0, 113, 7}}, {Key: []byte{203, 0, 113, 8}, IntervalEnd: true},
		{Key: netip.MustParseAddr("ff00::").AsSlice()}, // runs to the end of the address space
		{Key: []byte{224, 0, 0, 0}}, {Key: []byte{240, 0, 0, 0}, IntervalEnd: true},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d elements, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if !slices.Equal(got[i].Key, want[i].Key) || got[i].IntervalEnd != want[i].IntervalEnd {
			t.Errorf("element %d: got %v %v, want %v %v", i, got[i].Key, got[i].IntervalEnd, want[i].Key, want[i].IntervalEnd)
		}
	}
}

func TestNameservers(t *testing.T) {
	conf := "# generated\nsearch example.org\nnameserver 127.0.0.53\nnameserver  fe80::1%eth0\nnameserver ::ffff:192.0.2.1\nnameserver not-an-address\noptions edns0\n"
	got := Nameservers([]byte(conf))
	want := []netip.Addr{netip.MustParseAddr("127.0.0.53"), netip.MustParseAddr("fe80::1"), netip.MustParseAddr("192.0.2.1")}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseAllow(t *testing.T) {
	got := ParseAllow([]string{"10.9.9.9", "192.168.10.7/24", "fd00::1"})
	want := prefixes("10.9.9.9/32", "192.168.10.0/24", "fd00::1/128")
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestBlocked(t *testing.T) {
	p := Policy{Own: []netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("::ffff:198.51.100.2"), netip.MustParseAddr("127.0.0.1")}}
	v4, v6 := split(p.Blocked())
	want4 := prefixes("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
		"224.0.0.0/4", "240.0.0.0/4", "203.0.113.7/32", "198.51.100.2/32")
	want6 := prefixes("::1/128", "fe80::/10", "fc00::/7", "ff00::/8")
	if !slices.Equal(v4, want4) || !slices.Equal(v6, want6) {
		t.Fatalf("got %v %v", v4, v6)
	}
}
