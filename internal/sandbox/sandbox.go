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

const Path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

type User struct {
	Name     string
	UID, GID uint32
}

type Spec struct {
	Name      string
	StateDir  string
	ConfigDir string
	RunDir    string
	User      User
	Env       []string
	EnvFile   string
	Timeout   time.Duration
	MemoryMax string
	CPUQuota  string
	Command   []string
	Stdout    io.Writer
	Stderr    io.Writer
}

func (s Spec) Home() string { return filepath.Join(s.StateDir, "agent-home") }

func (s Spec) hidden() []string {
	return []string{s.ConfigDir, filepath.Join(s.StateDir, "cache")}
}

func (s Spec) runs() string { return filepath.Join(s.StateDir, "runs") }

type Result struct {
	ExitCode int
	TimedOut bool
}

type Sandbox interface {
	Run(ctx context.Context, s Spec) (Result, error)
}

const UnitPrefix = "tripcoil-review-"

func Booted() bool {
	fi, err := os.Stat("/run/systemd/system")
	return err == nil && fi.IsDir()
}

const MaxTasks = 4096

const MinSystemd = 247

func SystemdVersion(out []byte) (int, error) {
	line, _, _ := bytes.Cut(out, []byte("\n"))
	f := strings.Fields(string(line))
	if len(f) < 2 || f[0] != "systemd" {
		return 0, fmt.Errorf("unexpected systemctl --version output %q", line)
	}
	return strconv.Atoi(f[1])
}

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

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}
