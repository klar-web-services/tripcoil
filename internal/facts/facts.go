// Package facts collects the facts snapshot: what root can read about the host's exposure and
// hardening that the unprivileged review agent cannot (spec section 7).
package facts

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/klar-web-services/tripcoil/internal/dockerapi"
	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/run"
)

// Runner runs a command and returns its standard output. An error carries the command's standard
// error. Tests replace it.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// Docker is what the facts read from the Docker Engine API.
type Docker interface {
	Inspect(ctx context.Context, id string) (dockerapi.Detail, error)
}

// Deps is what Collect reads from the host.
type Deps struct {
	Root string // "/" on the host; a fixture tree in tests
	Run  Runner
	// LookPath finds a tool on the fixed system path.
	LookPath func(name string) (string, error)
	Docker   Docker // nil when the Inventory found no Docker
	// DockerSocket is the socket the Inventory read, to flag containers that mount it.
	DockerSocket string
	// MountInfo is the mount table that says which file systems Tripcoil reads users' files on;
	// empty means /proc/self/mountinfo.
	MountInfo string
}

// Index is facts/index.json: which facts were collected, and which are missing and why.
type Index struct {
	Collected []string  `json:"collected"`
	Missing   []Missing `json:"missing"`
	Notes     []string  `json:"notes"`
}

// Missing is a fact that could not be collected (FACT_MISSING, a coverage gap).
type Missing struct {
	Fact   string `json:"fact"`
	Reason string `json:"reason"`
}

type collector struct {
	ctx    context.Context
	d      Deps
	inv    *inventory.Inventory
	itemOf map[int]string
	sshdT  string // sshd -T output, which users.json reads
}

// Collect writes the facts into runDir/facts and returns the index it wrote. Only a run folder that
// cannot be written is an error: a fact that cannot be collected is listed as missing.
func Collect(ctx context.Context, d Deps, inv *inventory.Inventory, runDir string) (*Index, error) {
	dir, err := run.CreateSubfolder(runDir, "facts")
	if err != nil {
		return nil, err
	}
	c := collector{ctx: ctx, d: d, inv: inv, itemOf: itemsByPID(inv)}
	idx := &Index{Collected: []string{}, Missing: []Missing{}, Notes: []string{}}
	writeJSON := func(name string, v any) error { return run.WriteJSON(filepath.Join(dir, name), v, 0o640) }
	writeText := func(name, s string) error { return run.WriteFile(filepath.Join(dir, name), []byte(s), 0o640) }
	add := func(name string, err error, write func() error) error {
		if err != nil {
			if ctx.Err() != nil {
				err = errors.New("the run was interrupted")
			}
			idx.Missing = append(idx.Missing, Missing{Fact: name, Reason: err.Error()})
			return nil
		}
		if err := write(); err != nil {
			return err
		}
		idx.Collected = append(idx.Collected, name)
		return nil
	}

	net, err := c.network()
	if err := add("network.json", err, func() error { return writeJSON("network.json", net) }); err != nil {
		return nil, err
	}
	fw, err := c.firewall()
	if err := add("firewall.txt", err, func() error { return writeText("firewall.txt", fw) }); err != nil {
		return nil, err
	}
	procs, err := c.processes()
	if err := add("processes.json", err, func() error { return writeJSON("processes.json", procs) }); err != nil {
		return nil, err
	}
	conts, err := c.containers()
	if err := add("containers.json", err, func() error { return writeJSON("containers.json", conts) }); err != nil {
		return nil, err
	}
	kern, err := c.kernel()
	if err := add("kernel.json", err, func() error { return writeJSON("kernel.json", kern) }); err != nil {
		return nil, err
	}
	sshd, installed, err := c.sshd()
	if installed {
		if err := add("sshd.txt", err, func() error { return writeText("sshd.txt", sshd) }); err != nil {
			return nil, err
		}
		if err == nil {
			c.sshdT = sshd
		}
	} else {
		idx.Notes = append(idx.Notes, "sshd is not installed, so there is no sshd.txt")
	}
	users, err := c.users()
	if err := add("users.json", err, func() error { return writeJSON("users.json", users) }); err != nil {
		return nil, err
	}
	if err := writeJSON("index.json", idx); err != nil {
		return nil, err
	}
	return idx, nil
}

// Exec runs a command from the fixed system path, with a minute's timeout.
func Exec(ctx context.Context, name string, args ...string) ([]byte, error) {
	path, err := LookPath(name)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=" + systemPath, "LC_ALL=C"}
	cmd.WaitDelay = waitDelay // a process of systemd-run's transient unit can keep stdout open after the kill
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 500 {
			msg = msg[:500]
		}
		if msg != "" {
			return out, fmt.Errorf("%s: %w: %s", name, err, msg)
		}
		return out, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}

// waitDelay is how long Exec waits for the command's output to close after the timeout; tests
// shorten it.
var waitDelay = 5 * time.Second

// systemPath is where Tripcoil looks for the host's tools, never the caller's PATH.
const systemPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// errNotFound marks a tool that is not installed.
var errNotFound = errors.New("not installed")

// LookPath finds a tool on the fixed system path, never the caller's PATH.
func LookPath(name string) (string, error) {
	for _, dir := range filepath.SplitList(systemPath) {
		p := filepath.Join(dir, name)
		if path, err := exec.LookPath(p); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("%s: %w", name, errNotFound)
}
