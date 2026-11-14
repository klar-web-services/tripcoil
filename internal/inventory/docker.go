package inventory

import (
	"cmp"
	"context"
	"errors"
	"io/fs"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/klar-web-services/tripcoil/internal/dockerapi"
	"github.com/klar-web-services/tripcoil/internal/problem"
	"github.com/klar-web-services/tripcoil/internal/procfs"
)

// DockerAPI is what the container collector needs from the Docker daemon.
type DockerAPI interface {
	Ping(ctx context.Context) error
	Containers(ctx context.Context) ([]dockerapi.Summary, error)
	Inspect(ctx context.Context, id string) (dockerapi.Detail, error)
	InspectImage(ctx context.Context, id string) (dockerapi.Image, error)
}

// collectDocker inventories the running containers. Without a running dockerd it never connects:
// with docker.socket active, a connection would start dockerd and every container with a restart
// policy.
func collectDocker(ctx context.Context, dockerHost string, dockerdRunning bool, connect func(string) DockerAPI, containerPIDs map[string][]int, src Source) ([]Item, []Origin, []problem.Problem) {
	if !dockerdRunning {
		// dockerd stopped with live-restore keeps its containers running.
		if len(containerPIDs) > 0 {
			return nil, nil, []problem.Problem{problem.New(problem.Error, problem.DockerUnavailable, "inventory",
				"%d container(s) have running processes, but no Docker daemon (dockerd) is running, so they are not inventoried; start Docker to inventory them",
				len(containerPIDs))}
		}
		return nil, nil, []problem.Problem{problem.New(problem.Notice, problem.DockerAbsent, "inventory", "no Docker daemon is running, so there are no containers to inventory")}
	}
	socket, err := dockerapi.Socket(dockerHost)
	if err != nil {
		return nil, nil, []problem.Problem{problem.New(problem.Error, problem.DockerUnavailable, "inventory", "%v", err)}
	}
	fi, err := os.Stat(socket)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, []problem.Problem{problem.New(problem.Error, problem.DockerUnavailable, "inventory",
			"cannot check the Docker socket at %s (%v), so running containers are missing from this run", socket, err)}
	}
	if err != nil || fi.Mode()&fs.ModeSocket == 0 {
		// dockerd runs, but not on this socket (a custom -H).
		if len(containerPIDs) > 0 {
			return nil, nil, []problem.Problem{problem.New(problem.Error, problem.DockerUnavailable, "inventory",
				"%d container(s) have running processes, but dockerd does not listen on %s, so they are not inventoried; set DOCKER_HOST to its socket",
				len(containerPIDs), socket)}
		}
		return nil, nil, []problem.Problem{problem.New(problem.Notice, problem.DockerAbsent, "inventory", "no Docker socket at %s, so there are no containers to inventory", socket)}
	}
	api := connect(socket)
	if err := api.Ping(ctx); err != nil {
		if interrupted(ctx, err) {
			return nil, nil, nil
		}
		return nil, nil, []problem.Problem{problem.New(problem.Error, problem.DockerUnavailable, "inventory",
			"Docker at %s does not answer (%v), so running containers are missing from this run", socket, err)}
	}
	list, err := api.Containers(ctx)
	if interrupted(ctx, err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, []problem.Problem{problem.New(problem.Error, problem.DockerUnavailable, "inventory", "cannot list containers: %v", err)}
	}
	var items []Item
	var problems []problem.Problem
	origins := map[string]Origin{}
	accounted := map[string]bool{} // listed by Docker
	for _, s := range list {
		accounted[s.ID] = true
		d, err := api.Inspect(ctx, s.ID)
		if errors.Is(err, dockerapi.ErrNotFound) {
			continue // it was removed between the list and the inspect: it is no longer running
		}
		if err != nil {
			if !interrupted(ctx, err) {
				problems = append(problems, problem.New(problem.Error, problem.DockerUnavailable, "inventory", "cannot inspect container %.12s: %v", s.ID, err))
			}
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
		it.Compose = compose(ctx, api, s.ImageID, d.Config.Labels)
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
	if n := stillRunning(src, containerPIDs, accounted); n > 0 {
		problems = append(problems, problem.New(problem.Error, problem.DockerUnavailable, "inventory",
			"%d container(s) have running processes that Docker at %s does not list (a second Docker daemon?), so they are not inventoried", n, socket))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	out := make([]Origin, 0, len(origins))
	for _, o := range origins {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return items, out, problems
}

// compose reads a container's Compose labels, or nil. A container inherits its image's labels, so
// an image can name any project, directory or file. When the directory or file label equals the
// image's own, or the image cannot be read, there is no Compose info. The project and service may
// equal the image's: Compose writes them onto the images it builds.
func compose(ctx context.Context, api DockerAPI, imageID string, labels map[string]string) *Compose {
	project, service := labels["com.docker.compose.project"], labels["com.docker.compose.service"]
	if project == "" && service == "" {
		return nil
	}
	img, err := api.InspectImage(ctx, imageID)
	if err != nil {
		return nil
	}
	const dir, files = "com.docker.compose.project.working_dir", "com.docker.compose.project.config_files"
	for _, k := range []string{dir, files} {
		if v, ok := img.Config.Labels[k]; ok && v == labels[k] {
			return nil
		}
	}
	c := &Compose{Project: project, Service: service, WorkingDir: labels[dir]}
	if f := labels[files]; f != "" {
		c.ConfigFiles = strings.Split(f, ",")
	}
	return c
}

// stillRunning counts the containers outside accounted with a process that still runs in them:
// a container that ended meanwhile is not missing, and its PIDs may have been reused.
func stillRunning(src Source, containerPIDs map[string][]int, accounted map[string]bool) int {
	n := 0
	for id, pids := range containerPIDs {
		if accounted[id] {
			continue
		}
		for _, pid := range pids {
			if cgroup, err := src.Cgroup(pid); err == nil && procfs.DockerContainerID(cgroup) == id {
				n++
				break
			}
		}
	}
	return n
}
