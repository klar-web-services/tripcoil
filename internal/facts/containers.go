package facts

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/klar-web-services/tripcoil/internal/dockerapi"
	"github.com/klar-web-services/tripcoil/internal/inventory"
)

type Container struct {
	Item           string           `json:"item"`
	Name           string           `json:"name"`
	Privileged     bool             `json:"privileged"`
	CapAdd         []string         `json:"capAdd"`
	HostNetwork    bool             `json:"hostNetwork"`
	PIDMode        string           `json:"pidMode"`
	User           string           `json:"user"`
	ReadOnlyRootfs bool             `json:"readOnlyRootfs"`
	Ports          []inventory.Port `json:"ports"`
	Mounts         []ContainerMount `json:"mounts"`
	DockerSocket   bool             `json:"dockerSocket"`
	// Names are the names other containers reach it by (its own, its Compose and Swarm service, its
	// aliases), Addresses its addresses on Docker's networks.
	Names     []string `json:"names"`
	Addresses []string `json:"addresses"`
	// OwnAddress: it is on a macvlan or ipvlan network, with an address of its own on the LAN.
	OwnAddress bool `json:"ownAddress,omitempty"`
	// Service is its Swarm service. MeshPorts are the ports that service publishes through the
	// routing mesh, on every node; MeshUnknown says this node cannot list them (it is no manager).
	Service     string           `json:"service,omitempty"`
	MeshPorts   []inventory.Port `json:"meshPorts,omitempty"`
	MeshUnknown bool             `json:"meshUnknown,omitempty"`
	// Routing is what its Traefik labels, and its service's, say about routing to it; nil without any.
	Routing *Routing `json:"routing,omitempty"`
}

type ContainerMount struct {
	Type        string `json:"type"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	RW          bool   `json:"rw"`
}

const (
	swarmServiceLabel   = "com.docker.swarm.service.name"
	composeServiceLabel = "com.docker.compose.service"
)

// Routing is what a container's Traefik labels say about routing to it. Nothing else of a label
// is kept: a rule can hold a header's token, a server's URL a password.
type Routing struct {
	// Enable is the label traefik.enable: "true", "false", or empty when it is not set.
	Enable string `json:"enable,omitempty"`
	// Hostnames are the names in its routers' rules, Ports the ports its services' labels name.
	Hostnames []string `json:"hostnames,omitempty"`
	Ports     []int    `json:"ports,omitempty"`
}

// read takes what Traefik's labels say about routing. Traefik compares label names without case.
func (r *Routing) read(labels map[string]string) *Routing {
	for k, v := range labels {
		parts := strings.Split(strings.ToLower(k), ".")
		last := parts[len(parts)-1]
		routed := len(parts) >= 4 && (parts[1] == "http" || parts[1] == "tcp" || parts[1] == "udp") && (parts[2] == "routers" || parts[2] == "services")
		if parts[0] != "traefik" || !routed && len(parts) != 2 || len(parts) == 2 && last != "enable" {
			continue
		}
		if r == nil {
			r = &Routing{}
		}
		port := ""
		switch {
		case len(parts) == 2:
			if on, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
				r.Enable = strconv.FormatBool(on)
			}
		case parts[2] == "routers" && last == "rule":
			r.Hostnames = append(r.Hostnames, ruleHosts(v)...)
		case parts[2] == "services" && last == "port":
			port = strings.TrimSpace(v)
		case parts[2] == "services" && last == "url":
			if t, ok := target(v); ok {
				_, port, _ = net.SplitHostPort(t)
			}
		}
		if n, err := strconv.Atoi(port); err == nil && n > 0 && n < 65536 {
			r.Ports = append(r.Ports, n)
		}
	}
	if r != nil {
		slices.Sort(r.Hostnames)
		r.Hostnames = slices.Compact(r.Hostnames)
		slices.Sort(r.Ports)
		r.Ports = slices.Compact(r.Ports)
	}
	return r
}

func (c collector) containers() ([]Container, error) {
	out := []Container{}
	var drivers map[string]string
	var services map[string]dockerapi.Service
	manager := false
	for _, it := range c.inv.Items {
		if it.Kind != inventory.KindContainer {
			continue
		}
		if c.d.Docker == nil {
			return nil, errNoDocker
		}
		if drivers == nil {
			nets, err := c.d.Docker.Networks(c.ctx)
			if err != nil {
				return nil, fmt.Errorf("networks: %w", err)
			}
			drivers = map[string]string{}
			for _, n := range nets {
				drivers[n.ID] = n.Driver
			}
			svcs, err := c.d.Docker.Services(c.ctx)
			if err != nil && !errors.Is(err, dockerapi.ErrNotManager) {
				return nil, fmt.Errorf("services: %w", err)
			}
			manager = err == nil
			services = map[string]dockerapi.Service{}
			for _, s := range svcs {
				services[s.Spec.Name] = s
			}
		}
		det, err := c.d.Docker.Inspect(c.ctx, it.ContainerID)
		if errors.Is(err, dockerapi.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("container %s: %w", it.Name, err)
		}
		ct := Container{Item: it.ID, Name: it.Name, Privileged: det.HostConfig.Privileged, CapAdd: det.HostConfig.CapAdd,
			HostNetwork: det.HostConfig.NetworkMode == "host", PIDMode: det.HostConfig.PidMode, User: det.Config.User,
			ReadOnlyRootfs: det.HostConfig.ReadonlyRootfs, Ports: it.Ports, Mounts: []ContainerMount{}}
		if ct.CapAdd == nil {
			ct.CapAdd = []string{}
		}
		if ct.Ports == nil {
			ct.Ports = []inventory.Port{}
		}
		for _, m := range det.Mounts {
			ct.Mounts = append(ct.Mounts, ContainerMount{Type: m.Type, Source: m.Source, Destination: m.Destination, RW: m.RW})
			if m.Type == "bind" && c.isDockerSocket(m.Source) {
				ct.DockerSocket = true
			}
		}
		labels := det.Config.Labels
		ct.Names, ct.Addresses = []string{it.Name}, []string{}
		for _, n := range []string{labels[composeServiceLabel], labels[swarmServiceLabel]} {
			if n != "" {
				ct.Names = append(ct.Names, n)
			}
		}
		for _, ep := range det.NetworkSettings.Networks {
			ct.Names = append(ct.Names, ep.Aliases...)
			ct.Names = append(ct.Names, ep.DNSNames...)
			for _, a := range []string{ep.IPAddress, ep.GlobalIPv6Address} {
				if a != "" {
					ct.Addresses = append(ct.Addresses, a)
				}
			}
			ct.OwnAddress = ct.OwnAddress || drivers[ep.NetworkID] == "macvlan" || drivers[ep.NetworkID] == "ipvlan"
		}
		slices.Sort(ct.Names)
		ct.Names = slices.Compact(ct.Names)
		slices.Sort(ct.Addresses)
		ct.Routing = ct.Routing.read(labels)
		if ct.Service = labels[swarmServiceLabel]; ct.Service != "" {
			ct.MeshUnknown = !manager
			ct.Routing = ct.Routing.read(services[ct.Service].Spec.Labels)
			for _, p := range services[ct.Service].Endpoint.Ports {
				if p.PublishMode == "ingress" && p.PublishedPort > 0 {
					ct.MeshPorts = append(ct.MeshPorts, inventory.Port{HostPort: p.PublishedPort, ContainerPort: p.TargetPort, Protocol: p.Protocol})
				}
			}
		}
		out = append(out, ct)
	}
	slices.SortFunc(out, func(a, b Container) int { return strings.Compare(a.Item, b.Item) })
	return out, nil
}

func (c collector) isDockerSocket(source string) bool {
	for _, sock := range []string{c.d.DockerSocket, "/var/run/docker.sock", "/run/docker.sock"} {
		if sock == "" {
			continue
		}
		rel, err := filepath.Rel(filepath.Clean(source), sock)
		if err == nil && !strings.HasPrefix(rel, "..") {
			return true
		}
	}
	return false
}
