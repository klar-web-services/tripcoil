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

type Input struct {
	Inventory     *inventory.Inventory
	Audit         *audit.Audit
	Network       *facts.Network
	Firewall      *string
	SSHD          *string
	Users         *[]facts.User
	Containers    *[]facts.Container
	Kernel        *facts.Kernel
	Reach         *facts.Reach
	PromptVersion string
	Agent         string
	Model         string
}

type canonical struct {
	Findings      []string `json:"findings"`
	RestartNeeded []string `json:"restartNeeded"`
	RebootPending []string `json:"rebootPending"`
	Sockets       []string `json:"sockets"`
	Firewall      string   `json:"firewall"`
	Containers    []string `json:"containers"`
	SSHD          string   `json:"sshd"`
	Users         []string `json:"users"`
	ContainerSec  []string `json:"containerSecurity"`
	Sysctls       []string `json:"sysctls"`
	Reach         []string `json:"reach"`
	Prompt        string   `json:"prompt"`
	Agent         string   `json:"agent"`
	Model         string   `json:"model"`
}

func Compute(in Input) string {
	c := canonical{Findings: []string{}, RestartNeeded: []string{}, RebootPending: []string{}, Sockets: []string{}, Containers: []string{},
		Users: []string{}, ContainerSec: []string{}, Sysctls: []string{}, Reach: []string{}, Prompt: in.PromptVersion, Agent: in.Agent, Model: in.Model}
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
	// The default reach, not the addresses behind it: a new DHCP lease or IPv6 prefix changes nothing here.
	if in.Reach == nil {
		c.Reach = append(c.Reach, "missing")
	} else {
		for _, r := range in.Reach.Items {
			c.Reach = append(c.Reach, fmt.Sprintf("%s %s %s unsure=%v stated=%v", r.Item, r.Default, r.Via, r.Unsure != "", r.Stated))
		}
		for _, r := range in.Reach.Routers {
			c.Reach = append(c.Reach, fmt.Sprintf("router %s %s %s complete=%v", r.Item, r.Program, r.Reach, r.Complete))
		}
	}
	for _, l := range [][]string{c.Findings, c.RestartNeeded, c.RebootPending, c.Containers, c.Users, c.ContainerSec, c.Sysctls, c.Reach} {
		slices.Sort(l)
	}
	slices.Sort(c.Sockets)
	c.Sockets = slices.Compact(c.Sockets)
	data, _ := json.Marshal(c)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func Exposed(n facts.Network) []facts.Socket { return n.Exposed() }

func Ephemeral(n facts.Network, port int) bool { return n.Ephemeral(port) }
