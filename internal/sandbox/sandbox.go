// Package sandbox runs a command as the agent's user in the sandbox of spec section 8.2: a
// transient systemd unit on systemd hosts, bubblewrap in its own cgroup elsewhere (Alpine under
// OpenRC). Both hide everything but the current run's folder, the per-review home and a private
// /tmp, show the agent only its own processes, and cap its memory, CPU and runtime. The network
// rules are the agentnet package's.
package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Path is the fixed system path that sandbox tools and agent CLIs are looked up on.
const Path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// User is the agent's system user.
type User struct {
	Name     string
	UID, GID uint32
}

// Spec is one command to run in the sandbox.
type Spec struct {
	Name      string // unique per run and purpose; names the systemd unit tripcoil-review-<Name>
	StateDir  string // /var/lib/tripcoil
	ConfigDir string // /etc/tripcoil
	RunDir    string // the current run's folder, visible read-only
	User      User
	Env       []string // KEY=value, set in the sandbox
	EnvFile   string   // review.envFile, read by systemd or by Tripcoil
	Timeout   time.Duration
	MemoryMax string // review.memoryMax, such as 2G
	CPUQuota  string // review.cpuQuota, such as 100%
	Command   []string
	Stdout    io.Writer
	Stderr    io.Writer
}

// Home is the per-review home, the only writable place besides a private /tmp.
func (s Spec) Home() string { return filepath.Join(s.StateDir, "agent-home") }

// hidden are the paths that must not be readable inside the sandbox; the runs folder is replaced
// by an empty one that holds only the current run.
func (s Spec) hidden() []string {
	return []string{s.ConfigDir, filepath.Join(s.StateDir, "cache")}
}

func (s Spec) runs() string { return filepath.Join(s.StateDir, "runs") }

// Result is how the command ended.
type Result struct {
	ExitCode int
	TimedOut bool
}

// Sandbox runs commands in the sandbox. An error means the command could not be started or
// waited for; a command that ran and failed is a Result.
type Sandbox interface {
	Run(ctx context.Context, s Spec) (Result, error)
}

// UnitPrefix starts the name of every transient unit Tripcoil starts for a review.
const UnitPrefix = "tripcoil-review-"

// Booted reports whether systemd is the init system (sd_booted).
func Booted() bool {
	fi, err := os.Stat("/run/systemd/system")
	return err == nil && fi.IsDir()
}

// MinSystemd is the oldest systemd whose transient units give the sandbox (spec section 8.2).
const MinSystemd = 247

// SystemdVersion reads the version from the first line of systemctl --version, such as
// "systemd 257 (257.13-1)".
func SystemdVersion(out []byte) (int, error) {
	line, _, _ := bytes.Cut(out, []byte("\n"))
	f := strings.Fields(string(line))
	if len(f) < 2 || f[0] != "systemd" {
		return 0, fmt.Errorf("unexpected systemctl --version output %q", line)
	}
	return strconv.Atoi(f[1])
}

// Bytes turns review.memoryMax (a whole number with an optional K, M, G or T suffix, base 1024)
// into bytes.
func Bytes(size string) (int64, error) {
	mult := int64(1)
	if n := len(size); n > 0 {
		switch size[n-1] {
		case 'K':
			mult = 1 << 10
		case 'M':
			mult = 1 << 20
		case 'G':
			mult = 1 << 30
		case 'T':
			mult = 1 << 40
		}
		if mult > 1 {
			size = size[:n-1]
		}
	}
	v, err := strconv.ParseInt(size, 10, 64)
	if err != nil || v < 1 {
		return 0, fmt.Errorf("invalid size %q", size)
	}
	return v * mult, nil
}

// ParseEnvFile reads KEY=value lines; empty lines and lines starting with # are skipped, and
// a value in matching single or double quotes loses them.
func ParseEnvFile(data []byte) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(strings.TrimPrefix(k, "export "))
		if !ok || k == "" || strings.ContainsAny(k, " \t") {
			return nil, fmt.Errorf("line %d is not KEY=value", n)
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out = append(out, k+"="+v)
	}
	return out, sc.Err()
}

// exists reports whether a path exists; a sandbox only hides paths that do.
func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}
