package inventory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/klar-web-services/tripcoil/internal/pkgtool"
	"github.com/klar-web-services/tripcoil/internal/problem"
	"github.com/klar-web-services/tripcoil/internal/procfs"
	"github.com/klar-web-services/tripcoil/internal/redact"
)

// Source is what the process collector reads from /proc. procfs.FS implements it.
type Source interface {
	PIDs() ([]int, error)
	Exe(pid int) (string, bool, error)
	ExeFileID(pid int) (procfs.FileID, error)
	MapFileID(pid int, m procfs.Mapping) (procfs.FileID, error)
	Cmdline(pid int) ([]string, error)
	Cwd(pid int) (string, error)
	UID(pid int) (int, error)
	StartTime(pid int) (time.Time, error)
	Cgroup(pid int) (string, error)
	Maps(pid int) ([]procfs.Mapping, error)
	SameRootAsInit(pid int) (bool, error)
	RootDir(pid int) (string, error)
	RootFileID(pid int) (procfs.FileID, error)
	OpenExe(pid int) (io.ReadCloser, error)
	OpenMapFile(pid int, m procfs.Mapping) (io.ReadCloser, error)
}

// Caps on the distinct shared libraries taken per process and per run. A user can map up to
// vm.max_map_count files named lib<N>.so, and each library costs a package tool query, inventory
// space and later a scan.
const (
	maxProcessLibraries = 1024
	maxRunLibraries     = 20000
)

var processLibraryCap, runLibraryCap = maxProcessLibraries, maxRunLibraries // lowered by tests

type processCollector struct {
	src      Source
	root     string            // host root, for /etc/passwd and for checking what is on disk now
	resolver *pkgtool.Resolver // nil when the package tool is unavailable
	distro   Distro
	cacheDir string

	users    map[int]string
	owned    map[string]bool    // package ownership of single paths (app directory markers), by path
	files    map[fileKey]Origin // origins of unpackaged running files
	libPaths map[string]bool    // the distinct library paths taken in this run
	readLeft int64              // what is left of the run's read budget
}

// fileKey identifies a running file by path and by device and inode: another mount namespace
// can put another file at the same path. A file unlinked after one process was read needs a copy.
type fileKey struct {
	path    string
	id      procfs.FileID
	deleted bool
}

type rawProcess struct {
	pid        int
	cmdline    []string // unredacted; only used to find the app directory, never written
	exe        string
	exeDeleted bool
	cwd        string
	user       string
	started    time.Time
	unit       string
	libs       []procfs.Mapping
	otherRoot  bool     // its root directory is not the host's
	notHost    []string // libraries of a process in another root that are not the host's files
	libLimit   string   // why some libraries were not taken, if some were not
	unresolved string   // why the origin cannot be resolved, if it cannot
}

type processResult struct {
	items         []Item
	origins       []Origin
	containerPIDs map[string][]int // Docker container ID -> its host PIDs
	problems      []problem.Problem
}

func (c *processCollector) collect(ctx context.Context) (processResult, error) {
	c.owned, c.files, c.libPaths, c.readLeft = map[string]bool{}, map[fileKey]Origin{}, map[string]bool{}, runReadCap
	pruneCache(c.cacheDir)
	pids, err := c.src.PIDs()
	if err != nil {
		return processResult{}, fmt.Errorf("cannot list processes: %w", err)
	}
	res := processResult{containerPIDs: map[string][]int{}}
	var procs []*rawProcess
	for _, pid := range pids {
		p, containerID, ok := c.read(pid)
		switch {
		case !ok:
		case containerID != "":
			res.containerPIDs[containerID] = append(res.containerPIDs[containerID], pid)
		default:
			procs = append(procs, p)
		}
	}
	owners, err := c.owners(ctx, procs)
	if err != nil {
		res.problems = append(res.problems, problem.New(problem.Error, problem.PackageToolFailed, "inventory",
			"the package tool failed, so the packages of running processes are unknown: %v", err))
		c.resolver, owners = nil, nil
	}
	finder := appDirFinder{root: c.root, owned: c.ownedPath}
	b := newBuilder()
	for _, p := range procs {
		c.build(ctx, p, owners, finder, b)
	}
	res.items, res.origins = b.result()
	return res, nil
}

// read reads one process. ok is false for a process that ended or is a kernel thread; a
// containerID means the process belongs to that Docker container.
func (c *processCollector) read(pid int) (p *rawProcess, containerID string, ok bool) {
	cmdline, err := c.src.Cmdline(pid)
	if err != nil {
		return nil, "", false
	}
	exe, deleted, exeErr := c.src.Exe(pid)
	if errors.Is(exeErr, fs.ErrNotExist) { // a kernel thread or zombie, or it exited meanwhile
		return nil, "", false
	}
	cgroup, _ := c.src.Cgroup(pid)
	if id := procfs.DockerContainerID(cgroup); id != "" {
		return nil, id, true
	}
	p = &rawProcess{pid: pid, cmdline: cmdline, exe: exe, exeDeleted: deleted, unit: procfs.SystemdUnit(procfs.ParseCgroup([]byte(cgroup)))}
	if uid, err := c.src.UID(pid); err == nil {
		p.user = c.userName(uid)
	}
	p.started, _ = c.src.StartTime(pid)
	switch {
	case exeErr != nil:
		p.unresolved = fmt.Sprintf("its executable cannot be read (%s)", errReason(exeErr))
	case strings.HasPrefix(exe, "/snap/"):
		p.unresolved = "it runs from a snap, and snaps are not audited in v1"
	default:
		if same, err := c.src.SameRootAsInit(pid); err == nil && !same {
			p.otherRoot = true
			if !c.runsHostFile(pid, exe, deleted) {
				p.unresolved = "it runs in another root file system (a container runtime other than Docker, systemd-nspawn or a chroot)"
			}
		}
	}
	if p.unresolved != "" {
		return p, "", true
	}
	p.cwd, _ = c.src.Cwd(pid)
	maps, _ := c.src.Maps(pid)
	for _, m := range maps {
		if m.Path == exe || !isSharedLibrary(m.Path) {
			continue
		}
		if len(p.libs)+len(p.notHost) == processLibraryCap {
			p.libLimit = fmt.Sprintf("it maps more than %d shared libraries, and the others were not inventoried", processLibraryCap)
			break
		}
		if !c.libPaths[m.Path] {
			if len(c.libPaths) == runLibraryCap {
				p.libLimit = fmt.Sprintf("the run reached its cap of %d shared libraries, and the others were not inventoried", runLibraryCap)
				continue
			}
			c.libPaths[m.Path] = true
		}
		if p.otherRoot && !m.Deleted { // a replaced file never matches the newer one at its path
			if id, err := c.src.MapFileID(pid, m); err != nil || !c.isHostFile(m.Path, id) {
				p.notHost = append(p.notHost, m.Path)
				continue
			}
		}
		p.libs = append(p.libs, m)
	}
	return p, "", true
}

// runsHostFile reports whether a process in another root runs the host's own file at exe, as a
// chrooted daemon does (sshd's pre-authentication child, Postfix's daemons, haproxy): it executed
// that file before it chrooted, so the file lies outside its root. Such a process is resolved
// like a host process: its executable is the host's, and so are the libraries it maps that are
// the host's files. So is a sandboxed Chromium or Electron process, whose root is an emptied
// /proc/<pid>/fdinfo. A process in a plain chroot runs a file inside its root, whose packages the
// host does not know, and a container that runs a bind-mounted host executable maps its own
// libraries.
func (c *processCollector) runsHostFile(pid int, exe string, deleted bool) bool {
	root, err := c.src.RootDir(pid)
	if err != nil || root == "/" || within(exe, root) {
		return false
	}
	if deleted {
		// The host's file at exe was replaced, as by an upgrade of the daemon, so only its root
		// can tell a host chroot from a chroot inside a container (LXC), whose root only names a
		// host path.
		id, err := c.src.RootFileID(pid)
		return err == nil && c.isHostFile(root, id)
	}
	id, err := c.src.ExeFileID(pid)
	return err == nil && c.isHostFile(exe, id)
}

// isHostFile reports whether the host's file at path is the file id.
func (c *processCollector) isHostFile(path string, id procfs.FileID) bool {
	fi, err := os.Stat(filepath.Join(c.root, path))
	if err != nil {
		return false
	}
	host, ok := procfs.IDOf(fi)
	return ok && host == id
}

func (c *processCollector) userName(uid int) string {
	if c.users == nil {
		c.users = readPasswd(filepath.Join(c.root, "etc", "passwd"))
	}
	if n, ok := c.users[uid]; ok {
		return n
	}
	return strconv.Itoa(uid)
}

func readPasswd(path string) map[int]string {
	m := map[int]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return m
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 3 {
			continue
		}
		if uid, err := strconv.Atoi(f[2]); err == nil {
			if _, dup := m[uid]; !dup {
				m[uid] = f[0]
			}
		}
	}
	return m
}

// owners asks the package tool about every executable and library in one batch.
func (c *processCollector) owners(ctx context.Context, procs []*rawProcess) (map[string]pkgtool.Package, error) {
	if c.resolver == nil {
		return nil, nil
	}
	seen := map[string]bool{}
	var paths []string
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	for _, p := range procs {
		if p.unresolved != "" {
			continue
		}
		add(p.exe)
		for _, m := range p.libs {
			add(m.Path)
		}
	}
	if len(paths) == 0 {
		return map[string]pkgtool.Package{}, nil
	}
	return c.resolver.Owners(ctx, paths)
}

// ownedPath reports, once per path, whether an installed OS package owns path.
func (c *processCollector) ownedPath(ctx context.Context, path string) bool {
	if c.resolver == nil {
		return false
	}
	if v, ok := c.owned[path]; ok {
		return v
	}
	v := c.resolver.Owned(ctx, path)
	c.owned[path] = v
	return v
}

func (c *processCollector) build(ctx context.Context, p *rawProcess, owners map[string]pkgtool.Package, finder appDirFinder, b *itemBuilder) {
	proc := Process{PID: p.pid, User: p.user, Cmdline: redact.Cmdline(p.cmdline), Started: p.started}
	if p.unresolved != "" {
		name, subject := filepath.Base(p.exe), p.exe
		if subject == "" {
			name = commandName(p.cmdline)
			subject = "command:" + name
		}
		// Its own item: another root's /usr/sbin/nginx is not the host's /usr/sbin/nginx.
		d := b.process("unresolved:"+subject, p.exe, "", name)
		d.addProcess(proc, p.unit)
		o := Origin{ID: UnresolvedOriginID("process:" + subject), Kind: OriginUnresolved, Reason: p.unresolved}
		if p.exe != "" {
			o.Paths = []string{p.exe}
		}
		b.link(d, o)
		return
	}
	interpreter := isInterpreter(p.exe)
	var dir appDir
	found := false
	if interpreter {
		dir, found = finder.find(ctx, p.cmdline, p.cwd)
	}
	d := b.process(p.exe, p.exe, dir.Path, filepath.Base(p.exe))
	d.addProcess(proc, p.unit)
	if interpreter {
		if found {
			b.link(d, Origin{ID: AppDirOriginID(dir.Path), Kind: OriginAppDir, Path: dir.Path, Jar: dir.Jar})
		} else {
			d.note(problem.AppDirNotFound)
		}
	}
	c.linkFile(ctx, b, d, p.exe, p.exeDeleted, owners, c.opener(p, errProcessEnded, func() (io.ReadCloser, error) { return c.src.OpenExe(p.pid) }))
	for _, m := range p.libs {
		if found && !dir.Jar && within(m.Path, dir.Path) {
			if m.Deleted && c.existsOnHost(m.Path) {
				d.restartNeeded(m.Path) // the Audit scans the newer file on disk
			}
			continue // covered by the app directory
		}
		c.linkFile(ctx, b, d, m.Path, m.Deleted, owners, c.opener(p, errUnmapped, func() (io.ReadCloser, error) { return c.src.OpenMapFile(p.pid, m) }))
	}
	for _, path := range p.notHost {
		b.link(d, Origin{ID: UnresolvedOriginID("another root:" + path), Kind: OriginUnresolved,
			Reason: "it runs in another root file system, and the library is not the host's file at that path", Paths: []string{path}})
	}
	if p.libLimit != "" {
		b.link(d, Origin{ID: UnresolvedOriginID("libraries:" + p.libLimit), Kind: OriginUnresolved, Reason: p.libLimit})
	}
}

var (
	errProcessEnded = errors.New("the process ended during the inventory")
	errUnmapped     = errors.New("the process ended or unmapped the file during the inventory")
)

// opener wraps open, which opens a running file of p, with a check that the PID is still p's: a
// PID reused since p was read would supply another process's file. gone is the error for a file
// that no longer exists in /proc.
func (c *processCollector) opener(p *rawProcess, gone error, open func() (io.ReadCloser, error)) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) {
		r, err := open()
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			return nil, gone
		}
		if err != nil {
			return nil, err
		}
		if t, err := c.src.StartTime(p.pid); err != nil || !t.Equal(p.started) {
			r.Close()
			return nil, errProcessEnded
		}
		return r, nil
	}
}

// linkFile attaches the origin of a running executable or library: its package, or the file
// itself. open reads the running file through /proc.
func (c *processCollector) linkFile(ctx context.Context, b *itemBuilder, d *draft, path string, deleted bool, owners map[string]pkgtool.Package, open func() (io.ReadCloser, error)) {
	pkg, owned := owners[path]
	if deleted && (owned || c.existsOnHost(path)) {
		d.restartNeeded(path) // a newer file is in place, and a restart loads it
	}
	if c.resolver == nil {
		b.link(d, Origin{ID: UnresolvedOriginID(path), Kind: OriginUnresolved, Reason: "package ownership is unknown because the package tool failed", Paths: []string{path}})
		return
	}
	if owned {
		o := packageOrigin(c.distro, pkg)
		o.RunningOlderCopy = deleted
		b.link(d, o)
		return
	}
	o, err := c.fileOrigin(ctx, path, deleted, open)
	if err != nil {
		reason := fmt.Sprintf("the running file was not read (%s)", errReason(err))
		b.link(d, Origin{ID: UnresolvedOriginID(path + "\x00" + reason), Kind: OriginUnresolved, Reason: reason, Paths: []string{path}})
		return
	}
	b.link(d, o)
}

// fileOrigin identifies an unpackaged running file by its content, read through /proc: that is
// the file that runs, not whatever is at the path now (another mount namespace may differ), and
// it can never be a FIFO or device someone put at that path. A replaced file is also copied into
// the cache, because the Audit cannot read it from the path.
func (c *processCollector) fileOrigin(ctx context.Context, path string, deleted bool, open func() (io.ReadCloser, error)) (Origin, error) {
	f, err := openRunning(open, &c.readLeft)
	if err != nil {
		return Origin{}, err
	}
	defer f.Close()
	key := fileKey{path, f.id, deleted}
	if o, ok := c.files[key]; ok && f.idKnown {
		return o, nil
	}
	var sha, copyPath string
	if deleted {
		sha, copyPath, err = copyToCache(ctx, f, c.cacheDir)
	} else {
		sha, err = hashRunning(ctx, f)
	}
	if err != nil {
		return Origin{}, err
	}
	o := Origin{ID: BinaryOriginID(sha), Kind: OriginBinary, SHA256: sha, Paths: []string{path}, Copy: copyPath}
	if f.idKnown {
		c.files[key] = o
	}
	return o, nil
}

// errReason describes err without the paths it names, such as /proc/<pid>/map_files/<range>,
// which change from run to run.
func errReason(err error) string {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err.Error()
	}
	var linkErr *os.LinkError
	if errors.As(err, &linkErr) {
		return linkErr.Err.Error()
	}
	return err.Error()
}

func (c *processCollector) existsOnHost(path string) bool {
	_, err := os.Lstat(filepath.Join(c.root, path))
	return err == nil
}

func commandName(cmdline []string) string {
	if len(cmdline) == 0 {
		return "unknown"
	}
	fields := strings.Fields(cmdline[0])
	if len(fields) == 0 {
		return "unknown"
	}
	return filepath.Base(fields[0])
}
