package facts

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// User is one entry of facts/users.json: an account with a login shell, whether it has a password,
// and how many authorized SSH keys it has. Never the hashes or the keys themselves.
type User struct {
	Name           string   `json:"name"`
	UID            int      `json:"uid"`
	Home           string   `json:"home"`
	Shell          string   `json:"shell"`
	Password       string   `json:"password"` // set, locked, none, empty (no password at all) or unknown
	AuthorizedKeys int      `json:"authorizedKeys"`
	KeyFiles       []string `json:"keyFiles"` // the authorized-keys files that exist
	// KeysUnread names the authorized-keys files that were not read, and why.
	KeysUnread []string `json:"keysUnread,omitempty"`
}

// maxKeysFile is the most read of one authorized-keys file.
const maxKeysFile = 1 << 20

func (c collector) users() ([]User, error) {
	passwd, err := os.ReadFile(filepath.Join(c.d.Root, "etc/passwd"))
	if err != nil {
		return nil, err
	}
	shells := map[string]bool{}
	if data, err := os.ReadFile(filepath.Join(c.d.Root, "etc/shells")); err == nil {
		for _, l := range strings.Split(string(data), "\n") {
			if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
				shells[l] = true
			}
		}
	}
	shadow := map[string]string{}
	if data, err := os.ReadFile(filepath.Join(c.d.Root, "etc/shadow")); err == nil {
		for _, l := range strings.Split(string(data), "\n") {
			if f := strings.SplitN(l, ":", 3); len(f) >= 2 {
				shadow[f[0]] = f[1]
			}
		}
	}
	keyFiles := authorizedKeysFiles(c.sshdT)
	types := c.mountTypes()
	out := []User{}
	sc := bufio.NewScanner(bytes.NewReader(passwd))
	for sc.Scan() {
		f := strings.Split(sc.Text(), ":")
		if len(f) != 7 || !loginShell(f[6], shells) {
			continue
		}
		uid, _ := strconv.Atoi(f[2])
		sh, inShadow := shadow[f[0]]
		u := User{Name: f[0], UID: uid, Home: f[5], Shell: f[6], Password: passwordState(f[1], sh, inShadow), KeyFiles: []string{}}
		for _, kf := range keyFiles {
			p := expandKeysFile(kf, u)
			if p == "" {
				continue
			}
			n, ok, why := c.countKeys(p, types)
			if why != "" {
				u.KeysUnread = append(u.KeysUnread, p+": "+why)
				continue
			}
			if ok {
				u.AuthorizedKeys += n
				u.KeyFiles = append(u.KeyFiles, p)
			}
		}
		out = append(out, u)
	}
	slices.SortFunc(out, func(a, b User) int { return a.UID - b.UID })
	return out, nil
}

// loginShell reports whether an account can log in: its shell is listed in /etc/shells, or, when
// that file is missing, is not one of the shells that refuse a login.
func loginShell(shell string, shells map[string]bool) bool {
	if shell == "" {
		return false
	}
	if len(shells) > 0 {
		return shells[shell]
	}
	switch path.Base(shell) {
	case "nologin", "false", "sync", "halt", "shutdown":
		return false
	}
	return true
}

// passwordState reads the password field of passwd and shadow: "x" in passwd means shadow holds it,
// and without a shadow entry the state is unknown.
func passwordState(passwdField, shadowField string, inShadow bool) string {
	p := passwdField
	if p == "x" {
		if !inShadow {
			return "unknown"
		}
		p = shadowField
	}
	switch {
	case p == "":
		return "empty"
	case p == "*" || p == "!" || p == "!!" || p == "!*":
		return "none"
	case strings.HasPrefix(p, "!") || strings.HasPrefix(p, "*"):
		return "locked"
	}
	return "set"
}

// authorizedKeysFiles reads AuthorizedKeysFile from sshd -T, or sshd's default.
func authorizedKeysFiles(sshdT string) []string {
	for _, l := range strings.Split(sshdT, "\n") {
		if v, ok := strings.CutPrefix(l, "authorizedkeysfile "); ok {
			return strings.Fields(v)
		}
	}
	return []string{".ssh/authorized_keys", ".ssh/authorized_keys2"}
}

// expandKeysFile expands sshd's tokens (%h, %u, %U, %%) and makes a relative path relative to the
// home directory. It is "" for a path it cannot expand, or "none".
func expandKeysFile(spec string, u User) string {
	if spec == "none" {
		return ""
	}
	var b strings.Builder
	for i := 0; i < len(spec); i++ {
		if spec[i] != '%' {
			b.WriteByte(spec[i])
			continue
		}
		if i+1 == len(spec) {
			return ""
		}
		i++
		switch spec[i] {
		case 'h':
			b.WriteString(u.Home)
		case 'u':
			b.WriteString(u.Name)
		case 'U':
			b.WriteString(strconv.Itoa(u.UID))
		case '%':
			b.WriteByte('%')
		default:
			return ""
		}
	}
	p := b.String()
	if !strings.HasPrefix(p, "/") {
		p = path.Join(u.Home, p)
	}
	return path.Clean(p)
}

// countKeys counts the key lines of an authorized-keys file, at most maxKeysFile bytes of it. Users
// control the path, so it is walked one component at a time from a descriptor, never through a
// link, and a component's lookup only happens on a directory whose mount Tripcoil knows to be a
// local file system: on a user's FUSE daemon or a dead NFS server a lookup can block forever. Each
// descriptor's mount comes from /proc/self/fdinfo, which never touches the file system, and its
// type from mountinfo. ok is false when there is no such file; why says why a file was not read.
func (c collector) countKeys(p string, types map[int]string) (n int, ok bool, why string) {
	f, why := c.openKeys(p, types)
	if f == nil {
		return 0, false, why
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxKeysFile))
	if err != nil {
		return 0, false, ""
	}
	for _, l := range strings.Split(string(data), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			n++
		}
	}
	return n, true, ""
}

func (c collector) openKeys(p string, types map[int]string) (*os.File, string) {
	fd, err := syscall.Open(c.d.Root, oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ""
	}
	parts := strings.Split(strings.Trim(path.Clean(p), "/"), "/")
	for i, part := range parts {
		if why := mountCheck(fd, types); why != "" {
			syscall.Close(fd)
			return nil, why
		}
		parent, _ := mountID(fd)
		next, err := syscall.Openat(fd, part, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if err != nil {
			return nil, "" // no such file
		}
		fd = next
		// A new mount: read the table again, because the kernel reuses a freed mount's ID, which a
		// user's new FUSE mount could take over from a mount the table still lists.
		if id, _ := mountID(fd); id != parent {
			types = c.mountTypes()
		}
		if why := mountCheck(fd, types); why != "" {
			syscall.Close(fd)
			return nil, why
		}
		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil {
			syscall.Close(fd)
			return nil, ""
		}
		switch mode := st.Mode & syscall.S_IFMT; {
		case mode == syscall.S_IFLNK:
			syscall.Close(fd)
			return nil, "/" + strings.Join(parts[:i+1], "/") + " is a symbolic link, which root does not follow here"
		case i < len(parts)-1 && mode != syscall.S_IFDIR, i == len(parts)-1 && mode != syscall.S_IFREG:
			syscall.Close(fd)
			return nil, ""
		}
	}
	defer syscall.Close(fd)
	f, err := os.OpenFile("/proc/self/fd/"+strconv.Itoa(fd), os.O_RDONLY|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ""
	}
	return f, ""
}

// oPath is O_PATH: a descriptor that only names a file, whose open never reads it.
const oPath = 0x200000

// mountCheck says why a descriptor's file system is not read, or is "".
func mountCheck(fd int, types map[int]string) string {
	id, ok := mountID(fd)
	typ := types[id]
	switch {
	case !ok || typ == "":
		return "it is on a mount that appeared after the mount table was read"
	case typ == "autofs":
		return "it is automounted (autofs), and a lookup could wait for a network server"
	case remoteFS(typ):
		return "it is on " + typ + ", which root does not read"
	case pseudoFS[typ]:
		return "it is on " + typ
	}
	return ""
}

// mountID reads a descriptor's mount ID from /proc/self/fdinfo.
func mountID(fd int) (int, bool) {
	data, err := os.ReadFile("/proc/self/fdinfo/" + strconv.Itoa(fd))
	if err != nil {
		return 0, false
	}
	for _, l := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(l, "mnt_id:"); ok {
			id, err := strconv.Atoi(strings.TrimSpace(v))
			return id, err == nil
		}
	}
	return 0, false
}

// mountTypes maps mount IDs to file system types, from mountinfo (Deps.MountInfo, by default
// /proc/self/mountinfo). It is empty when mountinfo cannot be read, so nothing is read then.
func (c collector) mountTypes() map[int]string {
	path := c.d.MountInfo
	if path == "" {
		path = "/proc/self/mountinfo"
	}
	out := map[int]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, l := range strings.Split(string(data), "\n") {
		pre, post, ok := strings.Cut(l, " - ")
		f, g := strings.Fields(pre), strings.Fields(post)
		if !ok || len(f) < 5 || len(g) < 1 {
			continue
		}
		if id, err := strconv.Atoi(f[0]); err == nil {
			out[id] = g[0]
		}
	}
	return out
}

// remoteFS reports whether a file system is served by a user's daemon or over the network: a lookup
// on it can block root's run for as long as the daemon or the server wants.
func remoteFS(fs string) bool {
	switch {
	case fs == "fuse", fs == "fuseblk", strings.HasPrefix(fs, "fuse."):
		return true
	}
	switch fs {
	case "nfs", "nfs4", "cifs", "smb3", "smbfs", "9p", "ceph", "glusterfs", "afs", "lustre", "gfs2", "ocfs2", "davfs":
		return true
	}
	return false
}

// pseudoFS are the kernel's file systems, whose files are not users' keys.
var pseudoFS = map[string]bool{"proc": true, "sysfs": true, "debugfs": true, "tracefs": true, "securityfs": true, "cgroup": true,
	"cgroup2": true, "configfs": true, "bpf": true, "efivarfs": true, "pstore": true, "devtmpfs": true}
