package procfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func proc(t *testing.T, root string, pid int, files, links map[string]string) {
	t.Helper()
	dir := filepath.Join(root, "proc", strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
}

func fixture(t *testing.T) (FS, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "proc/self"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "proc/stat"), []byte("cpu  1 2 3\nbtime 1700000000\nprocesses 99\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "other-root"), 0o755); err != nil {
		t.Fatal(err)
	}
	proc(t, root, 1, map[string]string{"cmdline": "/sbin/init\x00"}, map[string]string{"root": "../.."})
	proc(t, root, 42, map[string]string{
		"cmdline": "nginx: master process /usr/sbin/nginx\x00\x00",
		"status":  "Name:\tnginx\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n",
		"stat":    "42 (nginx) S 1 42 42 0 -1 4194560 100 0 0 0 0 0 0 0 20 0 1 0 12345 1000 1\n",
		"cgroup":  "0::/system.slice/nginx.service\n",
		"maps": "55d0a0000000-55d0a0100000 r-xp 00000000 08:01 100 /usr/sbin/nginx\n" +
			"7f9474200000-7f9474224000 r--p 00000000 00:20 13120726 /usr/lib/libc.so.6\n" +
			"7f9474224000-7f94743d3000 r-xp 00024000 00:20 13120726 /usr/lib/libc.so.6\n" +
			"7f9475000000-7f9475100000 r-xp 00000000 00:20 999 /usr/lib/libssl.so.3 (deleted)\n" +
			"7f9476000000-7f9476001000 rw-p 00000000 00:00 0 \n" +
			"7ffd1000000-7ffd1021000 rw-p 00000000 00:00 0 [stack]\n" +
			"7f9477000000-7f9477001000 r--p 00000000 08:01 5 /opt/my app/lib.so\n",
	}, map[string]string{"exe": "/usr/sbin/nginx", "cwd": "/", "root": "../.."})
	proc(t, root, 43, map[string]string{
		"cmdline": "/opt/api/api\x00--port\x0080\x00",
		"stat":    "43 (my (weird) proc) S 1 43 43 0 -1 4194560 100 0 0 0 0 0 0 0 20 0 1 0 200 1000 1\n",
	}, map[string]string{"exe": "/opt/api/api (deleted)", "root": "../../other-root"})
	proc(t, root, 2, map[string]string{"cmdline": ""}, nil)
	return FS{Root: root}, root
}

func TestPIDs(t *testing.T) {
	f, _ := fixture(t)
	pids, err := f.PIDs()
	if err != nil || !slices.Equal(pids, []int{1, 2, 42, 43}) {
		t.Fatalf("%v %v", pids, err)
	}
}

func TestExe(t *testing.T) {
	f, _ := fixture(t)
	if p, del, err := f.Exe(42); err != nil || p != "/usr/sbin/nginx" || del {
		t.Fatalf("42: %q %v %v", p, del, err)
	}
	if p, del, err := f.Exe(43); err != nil || p != "/opt/api/api" || !del {
		t.Fatalf("43: %q %v %v", p, del, err)
	}
	if _, _, err := f.Exe(2); !os.IsNotExist(err) {
		t.Fatalf("kernel thread: %v", err)
	}
}

func TestCmdlineCwdUID(t *testing.T) {
	f, _ := fixture(t)
	if c, err := f.Cmdline(43); err != nil || !slices.Equal(c, []string{"/opt/api/api", "--port", "80"}) {
		t.Fatalf("%q %v", c, err)
	}
	if c, err := f.Cmdline(42); err != nil || !slices.Equal(c, []string{"nginx: master process /usr/sbin/nginx"}) {
		t.Fatalf("%q %v", c, err)
	}
	if c, err := f.Cmdline(2); err != nil || c != nil {
		t.Fatalf("kernel thread cmdline %q %v", c, err)
	}
	if cwd, err := f.Cwd(42); err != nil || cwd != "/" {
		t.Fatalf("%q %v", cwd, err)
	}
	if uid, err := f.UID(42); err != nil || uid != 0 {
		t.Fatalf("%d %v", uid, err)
	}
}

func TestStartTime(t *testing.T) {
	f, _ := fixture(t)
	got, err := f.StartTime(42)
	want := time.Unix(1700000000, 0).Add(123450 * time.Millisecond).UTC()
	if err != nil || !got.Equal(want) {
		t.Fatalf("%v %v, want %v", got, err, want)
	}
	if got, err := f.StartTime(43); err != nil || !got.Equal(time.Unix(1700000002, 0).UTC()) {
		t.Fatalf("comm with parentheses: %v %v", got, err)
	}
}

func TestStartTicks(t *testing.T) {
	f, root := fixture(t)
	if got, err := f.StartTicks(42); err != nil || got != 12345 {
		t.Fatalf("%d %v", got, err)
	}
	if got, err := f.StartTicks(43); err != nil || got != 200 {
		t.Fatalf("comm with parentheses: %d %v", got, err)
	}
	if err := os.WriteFile(filepath.Join(root, "proc/stat"), []byte("btime 1700003600\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := f.StartTicks(42); err != nil || got != 12345 {
		t.Fatalf("after a clock step: %d %v", got, err)
	}
	proc(t, root, 44, map[string]string{"stat": "44 (short) S 1\n"}, nil)
	if _, err := f.StartTicks(44); err == nil {
		t.Fatal("a short stat line must be an error")
	}
}

func TestCgroupAndMaps(t *testing.T) {
	f, _ := fixture(t)
	if cg, err := f.Cgroup(42); err != nil || cg != "0::/system.slice/nginx.service\n" {
		t.Fatalf("%q %v", cg, err)
	}
	maps, err := f.Maps(42)
	if err != nil {
		t.Fatal(err)
	}
	want := []Mapping{
		{Start: "55d0a0000000", End: "55d0a0100000", Path: "/usr/sbin/nginx"},
		{Start: "7f9474200000", End: "7f9474224000", Path: "/usr/lib/libc.so.6"},
		{Start: "7f9475000000", End: "7f9475100000", Path: "/usr/lib/libssl.so.3", Deleted: true},
		{Start: "7f9477000000", End: "7f9477001000", Path: "/opt/my app/lib.so"},
	}
	if !slices.Equal(maps, want) {
		t.Fatalf("maps\n got %+v\nwant %+v", maps, want)
	}
}

func TestSameRootAsInit(t *testing.T) {
	f, _ := fixture(t)
	if same, err := f.SameRootAsInit(42); err != nil || !same {
		t.Fatalf("42: %v %v", same, err)
	}
	if same, err := f.SameRootAsInit(43); err != nil || same {
		t.Fatalf("43: %v %v", same, err)
	}
}

func TestExeFileID(t *testing.T) {
	f, root := fixture(t)
	real := filepath.Join(root, "usr/sbin/sshd")
	if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, []byte("sshd"), 0o755); err != nil {
		t.Fatal(err)
	}
	proc(t, root, 77, nil, map[string]string{"exe": "../../usr/sbin/sshd"})
	got, err := f.ExeFileID(77)
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(real)
	want, ok := IDOf(fi)
	if !ok || got != want {
		t.Fatalf("%+v, want %+v", got, want)
	}
}

func TestOpenMapFile(t *testing.T) {
	f, root := fixture(t)
	mf := filepath.Join(root, "proc/42/map_files")
	if err := os.MkdirAll(mf, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mf, "7f9475000000-7f9475100000"), []byte("old libssl"), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := f.OpenMapFile(42, Mapping{Start: "7f9475000000", End: "7f9475100000"})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	b, _ := io.ReadAll(r)
	if string(b) != "old libssl" {
		t.Fatalf("%q", b)
	}
}

func TestStartTimeLongUptime(t *testing.T) {
	f, root := fixture(t)
	proc(t, root, 50, map[string]string{
		"stat": "50 (old) S 1 50 50 0 -1 4194560 100 0 0 0 0 0 0 0 20 0 1 0 10368000000 1000 1\n",
	}, nil)
	got, err := f.StartTime(50)
	want := time.Unix(1700000000+103680000, 0).UTC()
	if err != nil || !got.Equal(want) {
		t.Fatalf("%v %v, want %v", got, err, want)
	}
}

func TestOpenMapFileUnpadded(t *testing.T) {
	f, root := fixture(t)
	mf := filepath.Join(root, "proc/42/map_files")
	if err := os.MkdirAll(mf, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mf, "400000-74d000"), []byte("low mapping"), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := f.OpenMapFile(42, Mapping{Start: "00400000", End: "0074d000", Path: "/usr/sbin/nginx"})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	b, _ := io.ReadAll(r)
	if string(b) != "low mapping" {
		t.Fatalf("%q", b)
	}
}

func TestParseMapsKeepsPathVerbatim(t *testing.T) {
	data := "7f0000000000-7f0000001000 r-xp 00000000 08:01 200                        /opt/my  app/lib.so\n" +
		"7f0000004000-7f0000005000 rw-p 00000000 00:00 0      [anon:x /tmp/evil.so.1]\n" +
		"7f0000006000-7f0000007000 rw-p 00000000 00:00 0      [anon_shmem:y /usr/lib/libssl.so.3]\n" +
		"7f0000002000-7f0000003000 r-xp 00000000 08:01 201                        /opt/my  app/old.so (deleted)\n"
	want := []Mapping{
		{Start: "7f0000000000", End: "7f0000001000", Path: "/opt/my  app/lib.so"},
		{Start: "7f0000002000", End: "7f0000003000", Path: "/opt/my  app/old.so", Deleted: true},
	}
	if got := ParseMaps([]byte(data)); !slices.Equal(got, want) {
		t.Fatalf("\n got %+v\nwant %+v", got, want)
	}
}

func TestOpenRefusesNonRegularFiles(t *testing.T) {
	f, root := fixture(t)
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	mf := filepath.Join(root, "proc/42/map_files")
	if err := os.MkdirAll(mf, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"1000-2000": fifo, "3000-4000": "/dev/null"} {
		if err := os.Symlink(target, filepath.Join(mf, name)); err != nil {
			t.Fatal(err)
		}
	}
	proc(t, root, 78, nil, map[string]string{"exe": fifo})
	for name, open := range map[string]func() (io.ReadCloser, error){
		"exe FIFO":           func() (io.ReadCloser, error) { return f.OpenExe(78) },
		"mapped FIFO":        func() (io.ReadCloser, error) { return f.OpenMapFile(42, Mapping{Start: "1000", End: "2000"}) },
		"mapped char device": func() (io.ReadCloser, error) { return f.OpenMapFile(42, Mapping{Start: "3000", End: "4000"}) },
	} {
		done := make(chan error, 1)
		go func() {
			r, err := open()
			if err == nil {
				r.Close()
			}
			done <- err
		}()
		select {
		case err := <-done:
			if !errors.Is(err, ErrNotRegular) {
				t.Errorf("%s: %v, want ErrNotRegular", name, err)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("%s: open blocked", name)
		}
	}
}

func TestMapFileID(t *testing.T) {
	f, root := fixture(t)
	real := filepath.Join(root, "usr/lib/libc.so.6")
	if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, []byte("libc"), 0o755); err != nil {
		t.Fatal(err)
	}
	mf := filepath.Join(root, "proc/42/map_files")
	if err := os.MkdirAll(mf, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(mf, "7f9474200000-7f9474224000")); err != nil {
		t.Fatal(err)
	}
	got, err := f.MapFileID(42, Mapping{Start: "7f9474200000", End: "7f9474224000", Path: "/usr/lib/libc.so.6"})
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(real)
	if want, ok := IDOf(fi); !ok || got != want {
		t.Fatalf("%+v, want %+v", got, want)
	}
}

func TestRootDir(t *testing.T) {
	f, root := fixture(t)
	proc(t, root, 80, nil, map[string]string{"root": "/run/sshd"})
	proc(t, root, 81, nil, map[string]string{"root": "/srv/jail (deleted)"})
	for pid, want := range map[int]string{80: "/run/sshd", 81: "/srv/jail"} {
		if got, err := f.RootDir(pid); err != nil || got != want {
			t.Errorf("%d: %q %v, want %q", pid, got, err, want)
		}
	}
}

func TestOpenNeverOpensNonRegularFilesForReading(t *testing.T) {
	f, root := fixture(t)
	dir := t.TempDir()
	fifo, lib := filepath.Join(dir, "fifo"), filepath.Join(dir, "lib.so")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lib, []byte("lib"), 0o644); err != nil {
		t.Fatal(err)
	}
	mf := filepath.Join(root, "proc/42/map_files")
	if err := os.MkdirAll(mf, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"1000-2000": fifo, "3000-4000": lib} {
		if err := os.Symlink(target, filepath.Join(mf, name)); err != nil {
			t.Fatal(err)
		}
	}
	in, err := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
	if err != nil {
		t.Skip(err)
	}
	defer syscall.Close(in)
	fifoWatch, err1 := syscall.InotifyAddWatch(in, fifo, syscall.IN_OPEN)
	libWatch, err2 := syscall.InotifyAddWatch(in, lib, syscall.IN_OPEN)
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	if _, err := f.OpenMapFile(42, Mapping{Start: "1000", End: "2000"}); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("FIFO: %v", err)
	}
	r, err := f.OpenMapFile(42, Mapping{Start: "3000", End: "4000"})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(r); string(b) != "lib" {
		t.Fatalf("%q", b)
	}
	r.Close()
	opened := map[int]bool{}
	buf := make([]byte, 4096)
	n, _ := syscall.Read(in, buf)
	for off := 0; off+syscall.SizeofInotifyEvent <= n; {
		opened[int(int32(binary.NativeEndian.Uint32(buf[off:])))] = true
		off += syscall.SizeofInotifyEvent + int(binary.NativeEndian.Uint32(buf[off+12:]))
	}
	if opened[fifoWatch] || !opened[libWatch] {
		t.Fatalf("opened the FIFO: %v, the regular file: %v", opened[fifoWatch], opened[libWatch])
	}
}

func TestRootFileID(t *testing.T) {
	f, root := fixture(t)
	got, err := f.RootFileID(43)
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(filepath.Join(root, "other-root"))
	if want, ok := IDOf(fi); !ok || got != want {
		t.Fatalf("%+v, want %+v", got, want)
	}
}

func TestOpenRegularRefusesKernelFiles(t *testing.T) {
	for _, path := range []string{"/proc/self/status", "/sys/kernel/mm/transparent_hugepage/enabled"} {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		if f, err := OpenRegular(path); !errors.Is(err, ErrPseudoFile) {
			if f != nil {
				f.Close()
			}
			t.Errorf("%s: %v, want ErrPseudoFile", path, err)
		}
	}
	f, err := OpenRegular("/proc/self/exe")
	if err != nil {
		t.Fatalf("/proc/self/exe: %v", err)
	}
	f.Close()
}

const fSetLease = 1024

const leaseChildEnv = "PROCFS_LEASE_CHILD"

func TestOpenRegularLeaseChild(t *testing.T) {
	path := os.Getenv(leaseChildEnv)
	if path == "" {
		t.Skip("runs only as the child of TestOpenRegularLease")
	}
	f, err := OpenRegular(path)
	if err == nil {
		f.Close()
	}
	t.Logf("CHILD DONE: %v", err)
}

func TestOpenRegularLease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leased")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), fSetLease, syscall.F_WRLCK); errno != 0 {
		t.Skipf("no write lease available: %v", errno)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestOpenRegularLeaseChild$", "-test.v")
	cmd.Env = append(os.Environ(), leaseChildEnv+"="+path)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil || !bytes.Contains(out.Bytes(), []byte("CHILD DONE")) {
			t.Fatalf("child: %v\n%s", err, out.String())
		}
	case <-time.After(5 * time.Second):
		cmd.Process.Kill()
		<-done
		t.Fatal("OpenRegular blocked on a file with a write lease")
	}
}
