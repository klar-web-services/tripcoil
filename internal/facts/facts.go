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

type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

type Docker interface {
	Inspect(ctx context.Context, id string) (dockerapi.Detail, error)
	Networks(ctx context.Context) ([]dockerapi.Network, error)
	Services(ctx context.Context) ([]dockerapi.Service, error)
}

type Deps struct {
	Root         string
	Run          Runner
	LookPath     func(name string) (string, error)
	Docker       Docker
	DockerSocket string
	MountInfo    string
	// Interfaces lists the machine's network interfaces (SystemInterfaces).
	Interfaces func() ([]NetInterface, error)
	// InternetPorts is the owner's exposure.internetPorts; nil when the owner states nothing.
	InternetPorts *[]int
}

type Index struct {
	Collected []string  `json:"collected"`
	Missing   []Missing `json:"missing"`
	Notes     []string  `json:"notes"`
}

type Missing struct {
	Fact   string `json:"fact"`
	Reason string `json:"reason"`
}

type collector struct {
	ctx    context.Context
	d      Deps
	inv    *inventory.Inventory
	itemOf map[int]string
	sshdT  string
}

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

	net, netErr := c.network()
	if err := add("network.json", netErr, func() error { return writeJSON("network.json", net) }); err != nil {
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
	conts, contErr := c.containers()
	if err := add("containers.json", contErr, func() error { return writeJSON("containers.json", conts) }); err != nil {
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
	addrs, addrErr := c.addresses()
	if err := add("addresses.json", addrErr, func() error { return writeJSON("addresses.json", addrs) }); err != nil {
		return nil, err
	}
	// The routes and the default reach need all three; without them the review lowers nothing.
	reachErr := errors.Join(netErr, contErr, addrErr)
	if reachErr != nil {
		reachErr = errors.New("it needs network.json, containers.json and addresses.json")
	}
	var routes Routes
	if reachErr == nil {
		routes = c.routes(net, conts, addrs)
	}
	if err := add("routes.json", reachErr, func() error { return writeJSON("routes.json", routes) }); err != nil {
		return nil, err
	}
	if err := add("reach.json", reachErr, func() error { return writeJSON("reach.json", c.reach(net, conts, addrs, routes)) }); err != nil {
		return nil, err
	}
	if err := writeJSON("index.json", idx); err != nil {
		return nil, err
	}
	return idx, nil
}

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

var waitDelay = 5 * time.Second

const systemPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

var errNotFound = errors.New("not installed")

func LookPath(name string) (string, error) {
	for _, dir := range filepath.SplitList(systemPath) {
		p := filepath.Join(dir, name)
		if path, err := exec.LookPath(p); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("%s: %w", name, errNotFound)
}
