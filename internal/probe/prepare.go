package probe

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// Setup is what root prepared for one probe. Close removes it.
type Setup struct {
	Args      Args
	agentUID  int
	listeners []net.Listener
	files     []string
}

// Prepare writes files the agent could read without the sandbox (in the config folder, the cache
// and a decoy run folder shared with the agent's group), makes a decoy folder the agent's group
// could write to, listens on every address on a free port, and returns the probe's arguments.
// The cache folder is root's alone (0700), so its check holds even without the sandbox; the
// others do not.
func Prepare(stateDir, configDir, runDir string, agentUID, agentGID int, own, nameservers []netip.Addr) (*Setup, error) {
	b := make([]byte, 6)
	rand.Read(b)
	tok := ".probe-" + hex.EncodeToString(b)
	s := &Setup{Args: Args{Runs: filepath.Join(stateDir, "runs"), RunID: filepath.Base(runDir), RootPID: os.Getpid(), ClearKeyrings: true}, agentUID: agentUID}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	plant := func(path string, mode os.FileMode) error {
		if err := os.WriteFile(path, []byte("tripcoil sandbox probe\n"), mode); err != nil {
			return err
		}
		s.files = append(s.files, path)
		s.Args.Reads = append(s.Args.Reads, path)
		return os.Chmod(path, mode)
	}
	for _, dir := range []string{configDir, filepath.Join(stateDir, "cache")} {
		if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
			continue // nothing there to hide
		}
		if err := plant(filepath.Join(dir, tok), 0o644); err != nil {
			return nil, err
		}
	}
	decoy := filepath.Join(stateDir, "runs", tok)
	if err := os.Mkdir(decoy, 0o750); err != nil {
		return nil, err
	}
	s.files = append(s.files, decoy)
	if err := os.Chown(decoy, -1, agentGID); err != nil {
		return nil, err
	}
	if err := plant(filepath.Join(decoy, "run.json"), 0o640); err != nil {
		return nil, err
	}
	if err := os.Chown(filepath.Join(decoy, "run.json"), -1, agentGID); err != nil {
		return nil, err
	}
	writable := filepath.Join(stateDir, tok+"-w")
	if err := os.Mkdir(writable, 0o770); err != nil {
		return nil, err
	}
	s.files = append(s.files, writable)
	if err := os.Chown(writable, -1, agentGID); err != nil {
		return nil, err
	}
	if err := os.Chmod(writable, 0o770); err != nil {
		return nil, err
	}
	s.Args.Writes = []string{filepath.Join(writable, "file")}
	s.files = append(s.files, s.Args.Writes...)
	// Folders any user may write to: inside the sandbox they are private or read-only, so
	// nothing written there may show on the host afterwards (Leaked).
	for _, dir := range []string{"/tmp", "/var/tmp", "/dev/shm", "/run/lock"} {
		if _, err := os.Stat(dir); err == nil {
			s.Args.Private = append(s.Args.Private, filepath.Join(dir, tok))
		}
	}
	s.files = append(s.files, s.Args.Private...)

	l4, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	s.listen(l4)
	port := l4.Addr().(*net.TCPAddr).Port
	v6 := false
	if l6, err := net.Listen("tcp6", "[::]:"+strconv.Itoa(port)); err == nil { // no IPv6 on the host: no IPv6 targets
		s.listen(l6)
		v6 = true
	}
	// Root's listener answers on loopback and the host's own addresses, so a refused TCP connect
	// there can only be the table's. Another host, such as a resolver on the LAN, refuses by
	// itself: only UDP proves the table there.
	targets := []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	if v6 {
		targets = append(targets, netip.IPv6Loopback())
	}
	mine := map[netip.Addr]bool{}
	for _, a := range own {
		mine[a] = true
		if !a.IsLoopback() && !a.IsLinkLocalUnicast() && (a.Is4() || v6) {
			targets = append(targets, a)
		}
	}
	var udpOnly []netip.Addr
	for _, a := range nameservers { // DNS is allowed; another port on a local resolver must not be
		switch {
		case a.IsLoopback() || mine[a]:
			if a.Is4() || v6 {
				targets = append(targets, a)
			}
		case (a.IsPrivate() || (a.Is4() && a.IsLinkLocalUnicast())) && (a.Is4() || v6):
			udpOnly = append(udpOnly, a)
		}
	}
	seen := map[string]bool{}
	add := func(a netip.Addr, tcp bool) {
		t := netip.AddrPortFrom(a, uint16(port)).String()
		if !seen[t] {
			seen[t] = true
			if tcp {
				s.Args.TCP = append(s.Args.TCP, t)
			}
			s.Args.UDP = append(s.Args.UDP, t)
		}
	}
	for _, a := range targets {
		add(a, true)
	}
	for _, a := range udpOnly {
		add(a, false)
	}
	// The cloud metadata address: nothing of root's listens there.
	s.Args.TCP = append(s.Args.TCP, "169.254.169.254:80")
	s.Args.UDP = append(s.Args.UDP, "169.254.169.254:80")
	ok = true
	return s, nil
}

// listen accepts and closes connections until the listener is closed.
func (s *Setup) listen(l net.Listener) {
	s.listeners = append(s.listeners, l)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
}

// Leaked returns the files the probe wrote into the private folders that show on the host. Only
// files of the agent's user count: the names are on the probe's command line, which any local
// user can read, and a file another user made there proves nothing.
func (s *Setup) Leaked() []string {
	var out []string
	for _, p := range s.Args.Private {
		if fi, err := os.Lstat(p); err == nil && int(fi.Sys().(*syscall.Stat_t).Uid) == s.agentUID {
			out = append(out, fmt.Sprintf("write %s: it outlived the sandbox", p))
		}
	}
	return out
}

// Close stops the listeners and removes the files.
func (s *Setup) Close() {
	for _, l := range s.listeners {
		l.Close()
	}
	for i := len(s.files) - 1; i >= 0; i-- {
		os.Remove(s.files[i])
	}
}
