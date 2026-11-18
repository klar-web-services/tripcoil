package probe

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type Args struct {
	Reads         []string `json:"reads"`
	Writes        []string `json:"writes"`
	Private       []string `json:"private"`
	Home          string   `json:"home"`
	Runs          string   `json:"runs"`
	RunID         string   `json:"runId"`
	RootPID       int      `json:"rootPid"`
	TCP           []string `json:"tcp"`
	UDP           []string `json:"udp"`
	ClearKeyrings bool     `json:"clearKeyrings"`
}

type Check struct {
	Check   string `json:"check"`
	Target  string `json:"target"`
	Result  string `json:"result"`
	Blocked bool   `json:"blocked"`
}

const refusedWithin = time.Second

// Run makes every attempt, as the agent's user inside the sandbox. With ClearKeyrings it first
// empties the user's keyrings, which belong to the UID and outlive a review. systemd's unit
// forbids the keyring calls; bubblewrap's new user namespace gives each run keyrings of its own on
// recent kernels, and on older ones this clear, before every review, keeps a key from reaching
// the next.
func Run(a Args) []Check {
	if a.ClearKeyrings {
		for _, id := range []int{unix.KEY_SPEC_USER_KEYRING, unix.KEY_SPEC_USER_SESSION_KEYRING} {
			unix.KeyctlInt(unix.KEYCTL_CLEAR, id, 0, 0, 0)
		}
		if p, err := unix.KeyctlInt(unix.KEYCTL_GET_PERSISTENT, -1, unix.KEY_SPEC_USER_KEYRING, 0, 0); err == nil {
			unix.KeyctlInt(unix.KEYCTL_CLEAR, p, 0, 0, 0)
		}
	}
	var out []Check
	for _, p := range a.Reads {
		_, err := os.ReadFile(p)
		out = append(out, fileCheck("read", p, err))
	}
	for _, p := range a.Writes {
		err := os.WriteFile(p, []byte("tripcoil sandbox probe\n"), 0o600)
		if err == nil {
			os.Remove(p)
		}
		out = append(out, fileCheck("write", p, err))
	}
	for _, p := range a.Private {
		err := os.WriteFile(p, []byte("tripcoil sandbox probe\n"), 0o600)
		c := fileCheck("write", p, err)
		c.Blocked = true
		out = append(out, c)
	}
	if a.Runs != "" {
		es, err := os.ReadDir(a.Runs)
		c := Check{Check: "list", Target: a.Runs, Result: "only the current run", Blocked: true}
		var names []string
		for _, e := range es {
			names = append(names, e.Name())
		}
		if err != nil {
			c = fileCheck("list", a.Runs, err)
		} else if !slices.Equal(names, []string{a.RunID}) {
			c.Result, c.Blocked = "sees "+strings.Join(names, ", "), false
		}
		out = append(out, c)
	}
	if a.Home != "" {
		out = append(out, homeCheck(a.Home))
	}
	if a.RootPID > 0 {
		p := fmt.Sprintf("/proc/%d/cmdline", a.RootPID)
		_, err := os.ReadFile(p)
		out = append(out, fileCheck("read", p, err))
	}
	for _, t := range a.TCP {
		out = append(out, tcpCheck(t))
	}
	for _, t := range a.UDP {
		out = append(out, udpCheck(t))
	}
	return out
}

func homeCheck(home string) Check {
	c := Check{Check: "home", Target: home}
	var st unix.Statfs_t
	if err := unix.Statfs(home, &st); err != nil {
		c.Result = errText(err)
		return c
	}
	if st.Type != unix.TMPFS_MAGIC {
		c.Result = "not a tmpfs"
		return c
	}
	p := filepath.Join(home, ".probe-home")
	if err := os.WriteFile(p, []byte("tripcoil sandbox probe\n"), 0o600); err != nil {
		c.Result = "not writable: " + errText(err)
		return c
	}
	os.Remove(p)
	c.Result, c.Blocked = "a tmpfs it can write to", true
	return c
}

func fileCheck(check, target string, err error) Check {
	c := Check{Check: check, Target: target, Result: "succeeded"}
	if err != nil {
		c.Result = errText(err)
		c.Blocked = errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EROFS) ||
			errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ESRCH)
	}
	return c
}

func tcpCheck(target string) Check {
	c := Check{Check: "tcp", Target: target}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", target, 3*time.Second)
	took := time.Since(start)
	if err == nil {
		conn.Close()
		c.Result = "connected"
		return c
	}
	c.Result = fmt.Sprintf("%s after %v", errText(err), took.Round(time.Millisecond))
	c.Blocked = took < refusedWithin && (errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EPERM))
	return c
}

func udpCheck(target string) Check {
	c := Check{Check: "udp", Target: target}
	conn, err := net.Dial("udp", target)
	if err == nil {
		_, err = conn.Write([]byte("tripcoil sandbox probe"))
		conn.Close()
	}
	if err == nil {
		c.Result = "sent"
		return c
	}
	c.Result = errText(err)
	c.Blocked = errors.Is(err, syscall.EPERM)
	return c
}

func errText(err error) string {
	var en syscall.Errno
	if errors.As(err, &en) {
		return en.Error()
	}
	return err.Error()
}

func Main(args []string, stdout, stderr io.Writer) int {
	var a Args
	if len(args) != 1 || json.Unmarshal([]byte(args[0]), &a) != nil {
		fmt.Fprintln(stderr, "tripcoil sandbox-probe: expects one JSON argument")
		return 2
	}
	data, _ := json.Marshal(Run(a))
	fmt.Fprintln(stdout, string(data))
	return 0
}

func Failures(a Args, output []byte) []string {
	var checks []Check
	if err := json.Unmarshal(output, &checks); err != nil {
		return []string{fmt.Sprintf("the probe's output is not readable: %v", err)}
	}
	var out []string
	for _, c := range checks {
		if !c.Blocked {
			out = append(out, fmt.Sprintf("%s %s: %s", c.Check, c.Target, c.Result))
		}
	}
	if want := len(a.Reads) + len(a.Writes) + len(a.Private) + len(a.TCP) + len(a.UDP) + btoi(a.Runs != "") + btoi(a.RootPID > 0) + btoi(a.Home != ""); len(checks) != want {
		out = append(out, fmt.Sprintf("the probe made %d checks, expected %d", len(checks), want))
	}
	return out
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}
