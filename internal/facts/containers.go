package facts

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
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
}

type ContainerMount struct {
	Type        string `json:"type"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	RW          bool   `json:"rw"`
}

func (c collector) containers() ([]Container, error) {
	out := []Container{}
	for _, it := range c.inv.Items {
		if it.Kind != inventory.KindContainer {
			continue
		}
		if c.d.Docker == nil {
			return nil, errNoDocker
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
