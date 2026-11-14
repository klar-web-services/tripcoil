package inventory

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/klar-web-services/tripcoil/internal/dockerapi"
	"github.com/klar-web-services/tripcoil/internal/problem"
)

// DockerAPI is what the container collector needs from the Docker daemon.
type DockerAPI interface {
	Ping(ctx context.Context) error
	Containers(ctx context.Context) ([]dockerapi.Summary, error)
	Inspect(ctx context.Context, id string) (dockerapi.Detail, error)
}

// dockerSocket picks the socket from DOCKER_HOST, or the default.
func dockerSocket(dockerHost string) (string, error) {
	if dockerHost == "" {
		return "/var/run/docker.sock", nil
	}
	if p, ok := strings.CutPrefix(dockerHost, "unix://"); ok {
		return p, nil
	}
	return "", fmt.Errorf("DOCKER_HOST=%s is not a unix socket; Tripcoil only reads the local Docker daemon through its unix socket", dockerHost)
}

func collectDocker(ctx context.Context, dockerHost string, connect func(string) DockerAPI, containerPIDs map[string][]int) ([]Item, []Origin, []problem.Problem) {
	socket, err := dockerSocket(dockerHost)
	if err != nil {
		return nil, nil, []problem.Problem{problem.New(problem.Error, problem.DockerUnavailable, "inventory", "%v", err)}
	}
	fi, err := os.Stat(socket)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, []problem.Problem{problem.New(problem.Error, problem.DockerUnavailable, "inventory",
			"cannot check the Docker socket at %s (%v), so running containers are missing from this run", socket, err)}
	}
	if err != nil || fi.Mode()&fs.ModeSocket == 0 {
		// dockerd stopped with live-restore keeps its containers running without a socket.
		if len(containerPIDs) > 0 {
			return nil, nil, []problem.Problem{problem.New(problem.Error, problem.DockerUnavailable, "inventory",
				"%d container(s) have running processes, but the Docker socket %s is missing or not a socket, so they are not inventoried; start Docker or set DOCKER_HOST to its socket",
				len(containerPIDs), socket)}
		}
		return nil, nil, []problem.Problem{problem.New(problem.Notice, problem.DockerAbsent, "inventory", "no Docker socket at %s, so there are no containers to inventory", socket)}
	}
	api := connect(socket)
	if err := api.Ping(ctx); err != nil {
		return nil, nil, []problem.Problem{problem.New(problem.Error, problem.DockerUnavailable, "inventory",
			"Docker at %s does not answer (%v), so running containers are missing from this run", socket, err)}
	}
	list, err := api.Containers(ctx)
	if err != nil {
		return nil, nil, []problem.Problem{problem.New(problem.Error, problem.DockerUnavailable, "inventory", "cannot list containers: %v", err)}
	}
	var items []Item
	var problems []problem.Problem
	origins := map[string]Origin{}
	for _, s := range list {
		d, err := api.Inspect(ctx, s.ID)
		if errors.Is(err, dockerapi.ErrNotFound) {
			continue // it was removed between the list and the inspect: it is no longer running
		}
		if err != nil {
			problems = append(problems, problem.New(problem.Error, problem.DockerUnavailable, "inventory", "cannot inspect container %.12s: %v", s.ID, err))
			continue
		}
		if !d.State.Running {
			continue // it stopped between the list and the inspect; paused and restarting ones still run
		}
		name := strings.TrimPrefix(d.Name, "/")
		ref := s.Image
		if strings.HasPrefix(ref, "sha256:") && d.Config.Image != "" {
			ref = d.Config.Image // the tag moved to a newer image; keep the reference the container was started from
		}
		it := Item{
			ID: ContainerItemID(name), Kind: KindContainer, Name: name, ContainerID: d.ID,
			Image: ref, ImageID: s.ImageID, User: d.Config.User, Privileged: d.HostConfig.Privileged, NetworkMode: d.HostConfig.NetworkMode,
			Notes: []string{problem.ImageOnly},
		}
		if project, service := d.Config.Labels["com.docker.compose.project"], d.Config.Labels["com.docker.compose.service"]; project != "" || service != "" {
			it.Compose = &Compose{Project: project, Service: service}
		}
		for _, p := range s.Ports {
			if p.PublicPort != 0 {
				it.Ports = append(it.Ports, Port{IP: p.IP, HostPort: p.PublicPort, ContainerPort: p.PrivatePort, Protocol: p.Type})
			}
		}
		for _, m := range d.Mounts {
			it.Mounts = append(it.Mounts, Mount{Type: m.Type, Source: m.Source, Destination: m.Destination, ReadWrite: m.RW})
		}
		// Docker builds both lists from maps: sorted, identical runs give identical inventories.
		slices.SortFunc(it.Ports, func(a, b Port) int {
			return cmp.Or(cmp.Compare(a.ContainerPort, b.ContainerPort), strings.Compare(a.Protocol, b.Protocol),
				strings.Compare(a.IP, b.IP), cmp.Compare(a.HostPort, b.HostPort))
		})
		slices.SortFunc(it.Mounts, func(a, b Mount) int {
			return cmp.Or(strings.Compare(a.Destination, b.Destination), strings.Compare(a.Source, b.Source))
		})
		it.PIDs = append([]int(nil), containerPIDs[d.ID]...)
		sort.Ints(it.PIDs)
		o := Origin{ID: ImageOriginID(s.ImageID), Kind: OriginImage, ImageID: s.ImageID, Ref: ref}
		origins[o.ID] = o
		it.Origins = []string{o.ID}
		items = append(items, it)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	out := make([]Origin, 0, len(origins))
	for _, o := range origins {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return items, out, problems
}
