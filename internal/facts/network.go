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

// Network is facts/network.json: the host's listening TCP sockets and bound UDP sockets, mapped to
// the items whose processes hold them (spec section 7.1). Sockets in a container's own network
// namespace are not here; the container's published ports are (containers.json).
type Network struct {
	Sockets []Socket `json:"sockets"`
	// LocalPortRangeStart is the start of net.ipv4.ip_local_port_range: the kernel picks a UDP
	// client's port at or above it, which the change check leaves out (spec section 8.6).
	LocalPortRangeStart int `json:"localPortRangeStart"`
}

// Socket is one listening TCP socket or bound UDP socket.
type Socket struct {
	Proto     string   `json:"proto"`   // tcp or udp
	Address   string   `json:"address"` // the bind address: 0.0.0.0, ::, 127.0.0.1, ...
	Port      int      `json:"port"`
	Connected bool     `json:"connected,omitempty"` // a UDP socket connected to one peer
	Items     []string `json:"items"`               // the items whose processes hold it
	PIDs      []int    `json:"pids"`
	inode     string
}

// Socket states in /proc/net/*: TCP_ESTABLISHED (a connected UDP socket), TCP_CLOSE (a bound,
// unconnected UDP socket) and TCP_LISTEN.
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
			continue // IPv6 is off
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

// parseSockets reads the listening TCP and bound UDP sockets from a /proc/net table.
func parseSockets(data []byte, proto string) ([]Socket, error) {
	var out []Socket
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	first := true
	for sc.Scan() {
		if first { // the header
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

// parseAddr reads "0100007F:1F90": the address as the kernel stores it, in 32-bit words of host
// byte order, then the port in hex.
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
			continue // a kernel thread, or the process ended
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

// itemOfPID is the item of a process: the Inventory's, or for a process the Inventory did not see,
// the one process item without an app directory that runs the same executable, when the process is
// in the host's mount namespace. An interpreter's item stands for one app only (another script of the
// same python is another app), and a process in a container's mount namespace names its own files.
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
				return "", false // several items run it (other app directories)
			}
			found = it.ID
		}
	}
	return found, found != ""
}

// itemsByPID maps the inventory's process and container PIDs to their items.
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
