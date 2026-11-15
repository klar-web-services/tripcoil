package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/facts"
	"github.com/klar-web-services/tripcoil/internal/inventory"
)

// Input is what the fingerprint covers. Each fact is nil when it is missing (sshd.txt also when
// sshd is not installed).
type Input struct {
	Inventory     *inventory.Inventory
	Audit         *audit.Audit
	Network       *facts.Network
	Firewall      *string // facts/firewall.txt
	SSHD          *string // facts/sshd.txt
	Users         *[]facts.User
	Containers    *[]facts.Container
	Kernel        *facts.Kernel
	PromptVersion string
	Agent         string
	Model         string
}

// canonical is what gets hashed, with every list sorted.
type canonical struct {
	Findings      []string `json:"findings"`      // ID, risk tier, fix state
	RestartNeeded []string `json:"restartNeeded"` // item IDs
	RebootPending []string `json:"rebootPending"`
	Sockets       []string `json:"sockets"` // protocol, address, port (or "ephemeral"), items; or "missing"
	Firewall      string   `json:"firewall"`
	Containers    []string `json:"containers"` // published ports and privileged mode
	SSHD          string   `json:"sshd"`
	Users         []string `json:"users"`             // name, UID, shell, password state, number of keys; or "missing"
	ContainerSec  []string `json:"containerSecurity"` // added capabilities, Docker socket, host network, PID mode; or "missing"
	Sysctls       []string `json:"sysctls"`           // or "missing"
	Prompt        string   `json:"prompt"`
	Agent         string   `json:"agent"`
	Model         string   `json:"model"`
}

// Compute returns the fingerprint, the SHA-256 of the canonical JSON in hex.
func Compute(in Input) string {
	c := canonical{Findings: []string{}, RestartNeeded: []string{}, RebootPending: []string{}, Sockets: []string{}, Containers: []string{},
		Users: []string{}, ContainerSec: []string{}, Sysctls: []string{}, Prompt: in.PromptVersion, Agent: in.Agent, Model: in.Model}
	if in.Audit != nil {
		for _, f := range in.Audit.Findings {
			c.Findings = append(c.Findings, f.ID+" "+f.Risk+" "+f.Fix.State)
		}
	}
	if in.Inventory != nil {
		for _, it := range in.Inventory.Items {
			if len(it.RestartNeeded) > 0 {
				c.RestartNeeded = append(c.RestartNeeded, it.ID)
			}
			if it.RebootPending != nil && *it.RebootPending {
				c.RebootPending = append(c.RebootPending, it.ID)
			}
			if it.Kind == inventory.KindContainer {
				var ports []string
				for _, p := range it.Ports {
					ports = append(ports, fmt.Sprintf("%s:%d->%d", p.IP, p.HostPort, p.ContainerPort))
				}
				slices.Sort(ports)
				c.Containers = append(c.Containers, fmt.Sprintf("%s privileged=%v ports=%s", it.ID, it.Privileged, strings.Join(ports, ",")))
			}
		}
	}
	if in.Network == nil {
		c.Sockets = append(c.Sockets, "missing")
	} else {
		for _, s := range Exposed(*in.Network) {
			port := fmt.Sprint(s.Port)
			if Ephemeral(*in.Network, s.Port) {
				port = "ephemeral"
			}
			c.Sockets = append(c.Sockets, fmt.Sprintf("%s %s %s %s", s.Proto, s.Address, port, strings.Join(s.Items, ",")))
		}
	}
	if in.Firewall == nil {
		c.Firewall = "missing"
	} else {
		c.Firewall = NormalizeFirewall(*in.Firewall)
	}
	// What limits or widens an attack once a service is reached: who can log in, how sshd lets them,
	// what a container may do on the host, and the kernel's hardening. A change to any of them can
	// turn a review's judgement, so it asks for a new review.
	c.SSHD = "missing"
	if in.SSHD != nil {
		c.SSHD = *in.SSHD
	}
	if in.Users == nil {
		c.Users = append(c.Users, "missing")
	} else {
		for _, u := range *in.Users {
			c.Users = append(c.Users, fmt.Sprintf("%s %d %s %s keys=%d", u.Name, u.UID, u.Shell, u.Password, u.AuthorizedKeys))
		}
	}
	if in.Containers == nil {
		c.ContainerSec = append(c.ContainerSec, "missing")
	} else {
		for _, ct := range *in.Containers {
			caps := slices.Clone(ct.CapAdd)
			slices.Sort(caps)
			c.ContainerSec = append(c.ContainerSec, fmt.Sprintf("%s capAdd=%s dockerSocket=%v hostNetwork=%v pidMode=%s", ct.Item, strings.Join(caps, ","), ct.DockerSocket, ct.HostNetwork, ct.PIDMode))
		}
	}
	if in.Kernel == nil {
		c.Sysctls = append(c.Sysctls, "missing")
	} else {
		for k, v := range in.Kernel.Sysctls {
			c.Sysctls = append(c.Sysctls, k+"="+v)
		}
	}
	for _, l := range [][]string{c.Findings, c.RestartNeeded, c.RebootPending, c.Containers, c.Users, c.ContainerSec, c.Sysctls} {
		slices.Sort(l)
	}
	// One line per exposure: an IDE's language servers on ephemeral ports are one line however many run.
	slices.Sort(c.Sockets)
	c.Sockets = slices.Compact(c.Sockets)
	data, _ := json.Marshal(c)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Exposed are the sockets the fingerprint covers: listening TCP sockets, and bound UDP sockets that
// are not connected and not on a port the kernel hands to clients (Ephemeral), whose ports change
// with every query a client makes.
func Exposed(n facts.Network) []facts.Socket {
	var out []facts.Socket
	for _, s := range n.Sockets {
		if s.Proto == "udp" && (s.Connected || Ephemeral(n, s.Port)) {
			continue
		}
		out = append(out, s)
	}
	return out
}

// Ephemeral reports whether a port is one the kernel hands out when a program binds port 0: at or
// above the start of net.ipv4.ip_local_port_range. Development servers, IDEs and agents listen on
// such ports, a new one at each start, so a listener on one counts by its address and items only.
func Ephemeral(n facts.Network, port int) bool {
	return n.LocalPortRangeStart > 0 && port >= n.LocalPortRangeStart
}
