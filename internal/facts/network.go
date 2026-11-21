package facts

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/klar-web-services/tripcoil/internal/inventory"
)

type Network struct {
	Sockets             []Socket `json:"sockets"`
	LocalPortRangeStart int      `json:"localPortRangeStart"`
}

type Socket struct {
	Proto     string   `json:"proto"`
	Address   string   `json:"address"`
	Port      int      `json:"port"`
	Connected bool     `json:"connected,omitempty"`
	Items     []string `json:"items"`
	PIDs      []int    `json:"pids"`
	inode     string
}

// Exposed are the sockets that say what the machine offers: every listening TCP socket, and the
// bound UDP sockets that are neither connected nor on a port the kernel handed out.
func (n Network) Exposed() []Socket {
	var out []Socket
	for _, s := range n.Sockets {
		if s.Proto == "udp" && (s.Connected || n.Ephemeral(s.Port)) {
			continue
		}
		out = append(out, s)
	}
	return out
}

// Ephemeral reports whether a port is one the kernel hands out when a program binds port 0: at or
// above the start of net.ipv4.ip_local_port_range. Development servers, IDEs and agents listen on
// such ports, a new one at each start, so a listener on one counts by its address and items only.
func (n Network) Ephemeral(port int) bool {
	return n.LocalPortRangeStart > 0 && port >= n.LocalPortRangeStart
}

const (
	stateEstablished = "01"
	stateClose       = "07"
	stateListen      = "0A"
)

func (c collector) network() (Network, error) {
	n := Network{Sockets: []Socket{}}
	for _, f := range []struct{ file, proto string }{{"tcp", "tcp"}, {"tcp6", "tcp"}, {"udp", "udp"}, {"udp6", "udp"}} {
		data, err := os.ReadFile(filepath.Join(c.d.Root, "proc/net", f.file))
		if os.IsNotExist(err) && strings.HasSuffix(f.file, "6") {
			continue
		}
		if err != nil {
			return Network{}, err
		}
		socks, err := parseSockets(data, f.proto)
		if err != nil {
			return Network{}, fmt.Errorf("/proc/net/%s: %w", f.file, err)
		}
		n.Sockets = append(n.Sockets, socks...)
	}
	owners := c.socketOwners()
	for i := range n.Sockets {
		s := &n.Sockets[i]
		s.PIDs = owners[s.inode]
		if s.PIDs == nil {
			s.PIDs = []int{}
		}
		s.Items = []string{}
		for _, pid := range s.PIDs {
			if id, ok := c.itemOfPID(pid); ok && !slices.Contains(s.Items, id) {
				s.Items = append(s.Items, id)
			}
		}
		slices.Sort(s.Items)
	}
	slices.SortFunc(n.Sockets, func(a, b Socket) int {
		return cmpAll(strings.Compare(a.Proto, b.Proto), a.Port-b.Port, strings.Compare(a.Address, b.Address), boolCmp(a.Connected, b.Connected), strings.Compare(a.inode, b.inode))
	})
	if data, err := os.ReadFile(filepath.Join(c.d.Root, "proc/sys/net/ipv4/ip_local_port_range")); err == nil {
		if f := strings.Fields(string(data)); len(f) == 2 {
			n.LocalPortRangeStart, _ = strconv.Atoi(f[0])
		}
	}
	return n, nil
}

func parseSockets(data []byte, proto string) ([]Socket, error) {
	var out []Socket
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		st := f[3]
		switch {
		case proto == "tcp" && st == stateListen:
		case proto == "udp" && (st == stateClose || st == stateEstablished):
		default:
			continue
		}
		addr, port, err := parseAddr(f[1])
		if err != nil {
			return nil, err
		}
		out = append(out, Socket{Proto: proto, Address: addr.String(), Port: port, Connected: proto == "udp" && st == stateEstablished, inode: f[9]})
	}
	return out, sc.Err()
}

func parseAddr(s string) (netip.Addr, int, error) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return netip.Addr{}, 0, fmt.Errorf("bad address %q", s)
	}
	raw, err := hex.DecodeString(h)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.Addr{}, 0, fmt.Errorf("bad address %q", s)
	}
	for i := 0; i < len(raw); i += 4 {
		binary.BigEndian.PutUint32(raw[i:], binary.NativeEndian.Uint32(raw[i:]))
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("bad port in %q", s)
	}
	a, _ := netip.AddrFromSlice(raw)
	return a.Unmap(), int(port), nil
}

// socketOwners maps socket inodes to the processes that hold them: every process, because a service
// restarted since the Inventory holds its sockets under a new PID. Such a process counts for the item
// that runs its executable (see itemOfPID).
func (c collector) socketOwners() map[string][]int {
	out := map[string][]int{}
	entries, err := os.ReadDir(filepath.Join(c.d.Root, "proc"))
	if err != nil {
		return out
	}
	var pids []int
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	slices.Sort(pids)
	for _, pid := range pids {
		dir := filepath.Join(c.d.Root, "proc", strconv.Itoa(pid), "fd")
		fds, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range fds {
			target, err := os.Readlink(filepath.Join(dir, e.Name()))
			if inode, ok := strings.CutPrefix(target, "socket:["); err == nil && ok {
				inode = strings.TrimSuffix(inode, "]")
				if !slices.Contains(out[inode], pid) {
					out[inode] = append(out[inode], pid)
				}
			}
		}
	}
	return out
}

func (c collector) itemOfPID(pid int) (string, bool) {
	if id, ok := c.itemOf[pid]; ok {
		return id, true
	}
	dir := filepath.Join(c.d.Root, "proc", strconv.Itoa(pid))
	ns, err1 := os.Readlink(filepath.Join(dir, "ns/mnt"))
	hostNS, err2 := os.Readlink(filepath.Join(c.d.Root, "proc/1/ns/mnt"))
	exe, err3 := os.Readlink(filepath.Join(dir, "exe"))
	if err1 != nil || err2 != nil || err3 != nil || ns != hostNS {
		return "", false
	}
	found := ""
	for _, it := range c.inv.Items {
		if it.Kind == inventory.KindProcess && it.AppDir == "" && it.Exe == exe {
			if found != "" {
				return "", false
			}
			found = it.ID
		}
	}
	return found, found != ""
}

func itemsByPID(inv *inventory.Inventory) map[int]string {
	out := map[int]string{}
	for _, it := range inv.Items {
		for _, p := range it.Processes {
			out[p.PID] = it.ID
		}
		for _, pid := range it.PIDs {
			out[pid] = it.ID
		}
	}
	return out
}

func cmpAll(cs ...int) int {
	for _, c := range cs {
		if c != 0 {
			return c
		}
	}
	return 0
}

func boolCmp(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	}
	return -1
}
