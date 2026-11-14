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
	Cmdline(pid int) ([]string, error)
	Cwd(pid int) (string, error)
	UID(pid int) (int, error)
	StartTime(pid int) (time.Time, error)
	Cgroup(pid int) (string, error)
	Maps(pid int) ([]procfs.Mapping, error)
	SameRootAsInit(pid int) (bool, error)
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
	owned    map[string]bool   // package ownership of single paths (app directory markers), by path
	hashed   map[string]Origin // origins of unpackaged files that were not replaced, by path
	libPaths map[string]bool   // the distinct library paths taken in this run
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
	libLimit   string // why some libraries were not taken, if some were not
	unresolved string // why the origin cannot be resolved, if it cannot
}

type processResult struct {
	items         []Item
	origins       []Origin
	containerPIDs map[string][]int // Docker container ID -> its host PIDs
	problems      []problem.Problem
}

func (c *processCollector) collect(ctx context.Context) (processResult, error) {
	c.owned, c.hashed, c.libPaths = map[string]bool{}, map[string]Origin{}, map[string]bool{}
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
	if ctx.Err() == nil { // an interrupted run did not get to every copy the last run refers to
		keep := map[string]bool{}
		for _, o := range res.origins {
			if o.Copy != "" {
				keep[o.Copy] = true
			}
		}
		pruneCache(c.cacheDir, keep)
	}
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
	if exeErr != nil && errors.Is(exeErr, fs.ErrNotExist) && len(cmdline) == 0 {
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
		p.unresolved = fmt.Sprintf("its executable cannot be read (%v)", exeErr)
	case strings.HasPrefix(exe, "/snap/"):
		p.unresolved = "it runs from a snap, and snaps are not audited in v1"
	default:
		if same, err := c.src.SameRootAsInit(pid); err == nil && !same && !c.runsHostFile(pid, exe) {
			p.unresolved = "it runs in another root file system (a container runtime other than Docker, systemd-nspawn or a chroot)"
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
		if len(p.libs) == processLibraryCap {
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
		p.libs = append(p.libs, m)
	}
	return p, "", true
}

// runsHostFile reports whether a process in another root runs the host's own file at exe, as a
// chrooted daemon does (sshd's pre-authentication child, Postfix's daemons). Such a process is
// resolved like a host process: its executable and libraries are the host's.
func (c *processCollector) runsHostFile(pid int, exe string) bool {
	running, err := c.src.ExeFileID(pid)
	if err != nil {
		return false
	}
	fi, err := os.Stat(filepath.Join(c.root, exe))
	if err != nil {
		return false
	}
	host, ok := procfs.IDOf(fi)
	return ok && host == running
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
		o := Origin{ID: UnresolvedOriginID(subject), Kind: OriginUnresolved, Reason: p.unresolved}
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
	c.linkFile(ctx, b, d, p.exe, p.exeDeleted, owners, func() (io.ReadCloser, error) { return c.src.OpenExe(p.pid) })
	for _, m := range p.libs {
		if found && !dir.Jar && within(m.Path, dir.Path) {
			continue // covered by the app directory
		}
		c.linkFile(ctx, b, d, m.Path, m.Deleted, owners, func() (io.ReadCloser, error) { return c.src.OpenMapFile(p.pid, m) })
	}
	if p.libLimit != "" {
		b.link(d, Origin{ID: UnresolvedOriginID("libraries:" + p.libLimit), Kind: OriginUnresolved, Reason: p.libLimit})
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
		b.link(d, Origin{ID: UnresolvedOriginID(path), Kind: OriginUnresolved, Reason: fmt.Sprintf("the running file was not read (%v)", err), Paths: []string{path}})
		return
	}
	b.link(d, o)
}

// fileOrigin identifies an unpackaged running file by its content, read through /proc: that is
// the file that runs, not whatever is at the path now (another mount namespace may differ), and
// it can never be a FIFO or device someone put at that path. A replaced file is also copied into
// the cache, because the Audit cannot read it from the path.
func (c *processCollector) fileOrigin(ctx context.Context, path string, deleted bool, open func() (io.ReadCloser, error)) (Origin, error) {
	if !deleted {
		if o, ok := c.hashed[path]; ok {
			return o, nil
		}
	}
	f, err := openRunning(open)
	if err != nil {
		return Origin{}, err
	}
	defer f.Close()
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
	if !deleted {
		c.hashed[path] = o
	}
	return o, nil
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
