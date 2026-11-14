package priority

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// The checks run in a child process, because a test cannot undo a lower priority.
const childEnv = "TRIPCOIL_PRIORITY_CHILD"

func niceOf(t *testing.T, statPath string) int {
	t.Helper()
	data, err := os.ReadFile(statPath)
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(data[bytes.LastIndexByte(data, ')')+1:])) // fields[0] is field 3
	n, err := strconv.Atoi(fields[16])                                        // field 19: nice
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func ioClassOf(t *testing.T, tid int) int {
	t.Helper()
	v, _, errno := syscall.Syscall(syscall.SYS_IOPRIO_GET, ioprioWhoProcess, uintptr(tid), 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	return int(v) >> ioprioClassShift
}

func runChild(t *testing.T, mode string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestLower$", "-test.v")
	cmd.Env = append(os.Environ(), childEnv+"="+mode)
	out, err := cmd.CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("CHILD OK")) {
		t.Fatalf("child %s: %v\n%s", mode, err, out)
	}
}

func TestLower(t *testing.T) {
	nicer := 0 // a thread that is already nicer than Nice keeps its own value
	switch os.Getenv(childEnv) {
	case "":
		runChild(t, "plain")
		runChild(t, "nicer")
		return
	case "nicer":
		runtime.LockOSThread()
		nicer = syscall.Gettid()
		if err := syscall.Setpriority(syscall.PRIO_PROCESS, nicer, 15); err != nil {
			t.Fatal(err)
		}
	}
	if err := Lower(); err != nil {
		t.Fatal(err)
	}
	tasks, _ := filepath.Glob("/proc/self/task/*")
	for _, task := range tasks {
		tid, _ := strconv.Atoi(filepath.Base(task))
		want := Nice
		if tid == nicer {
			want = 15
		}
		if n := niceOf(t, filepath.Join(task, "stat")); n != want {
			t.Fatalf("thread %d: nice %d, want %d", tid, n, want)
		}
		if c := ioClassOf(t, tid); c != ioprioClassIdle {
			t.Fatalf("thread %d: IO class %d, want idle", tid, c)
		}
	}
	out, err := exec.Command("cat", "/proc/self/stat").Output()
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "stat")
	if err := os.WriteFile(f, out, 0o600); err != nil {
		t.Fatal(err)
	}
	if n := niceOf(t, f); n < Nice {
		t.Fatalf("child process nice %d, want at least %d", n, Nice)
	}
	t.Log("CHILD OK")
}
