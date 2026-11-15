// Package probe is the sandbox probe (spec section 8.2): before each review, Tripcoil runs itself
// in the identical sandbox, and the probe tries what the agent must not be able to do. Root
// prepares files the agent may read outside the sandbox and a listener on every address; the
// probe must be blocked from each.
package probe

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Args is what root passes to the probe, as JSON in its one argument.
type Args struct {
	Reads   []string `json:"reads"`   // files the agent could read without the sandbox
	Writes  []string `json:"writes"`  // files it could create without the sandbox, in a folder of its group
	Private []string `json:"private"` // files in folders anyone may write to, which must not show on the host
	Runs    string   `json:"runs"`    // the runs folder, which may show only RunID
	RunID   string   `json:"runId"`   //
	RootPID int      `json:"rootPid"` // Tripcoil's PID, whose command line must stay unreadable
	TCP     []string `json:"tcp"`     // host:port where root listens; a connect must be refused at once
	UDP     []string `json:"udp"`     // host:port a datagram must not leave for (EPERM)
	// ClearKeyrings empties the user's keyrings first: only ever for the agent's user.
	ClearKeyrings bool `json:"clearKeyrings"`
}

// Check is one attempt and its outcome.
type Check struct {
	Check   string `json:"check"`
	Target  string `json:"target"`
	Result  string `json:"result"`
	Blocked bool   `json:"blocked"`
}

// refusedWithin is how fast a blocked TCP connect fails: the table answers with a reset at once,
// while a dropped or unanswered SYN only times out.
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
	for _, p := range a.Private { // whether they show on the host, root checks (Setup.Leaked)
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

// fileCheck counts a permission, read-only or not-found error as blocked.
func fileCheck(check, target string, err error) Check {
	c := Check{Check: check, Target: target, Result: "succeeded"}
	if err != nil {
		c.Result = errText(err)
		c.Blocked = errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EROFS) ||
			errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ESRCH)
	}
	return c
}

// tcpCheck counts a connect to root's live listener as blocked only when it fails at once with a
// reset or the local drop's error.
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

// udpCheck counts a datagram as blocked only when sending it fails with the local drop's EPERM.
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

// Main is the hidden command tripcoil sandbox-probe: it reads Args from its argument and prints
// the checks as JSON.
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

// Failures returns what the probe was not blocked from, or why its output cannot be read.
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
	// Every check must have run: a probe that stopped early proves nothing.
	if want := len(a.Reads) + len(a.Writes) + len(a.Private) + len(a.TCP) + len(a.UDP) + btoi(a.Runs != "") + btoi(a.RootPID > 0); len(checks) != want {
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
