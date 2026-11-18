package inventory

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/dockerapi"
	"github.com/klar-web-services/tripcoil/internal/problem"
)

const (
	shopID    = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9"
	stoppedID = "0000000000000000000000000000000000000000000000000000000000000002"
)

func dockerServer(t *testing.T, h http.Handler) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "tc-docker")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "docker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return sock
}

func engine(ping int) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/_ping", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(ping)
		w.Write([]byte("OK"))
	})
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`[{"Id":"` + shopID + `","Names":["/shop-web-1"],"Image":"ghcr.io/acme/shop:2026.11.3","ImageID":"sha256:abc",` +
			`"State":"running","Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"web","com.docker.compose.project.working_dir":"/srv/shop"},` +
			`"Ports":[{"IP":"::","PrivatePort":3000,"PublicPort":8080,"Type":"tcp"},{"PrivatePort":9229,"Type":"tcp"},` +
			`{"IP":"0.0.0.0","PrivatePort":3000,"PublicPort":8081,"Type":"tcp"},{"IP":"0.0.0.0","PrivatePort":3000,"PublicPort":8080,"Type":"udp"},` +
			`{"IP":"0.0.0.0","PrivatePort":3000,"PublicPort":8080,"Type":"tcp"},{"IP":"0.0.0.0","PrivatePort":443,"PublicPort":8443,"Type":"tcp"}]},` +
			`{"Id":"0000000000000000000000000000000000000000000000000000000000000001","Names":["/gone"],"Image":"busybox","ImageID":"sha256:def","State":"running"},` +
			`{"Id":"` + stoppedID + `","Names":["/stopped"],"Image":"busybox","ImageID":"sha256:def","State":"running"}]`))
	})
	mux.HandleFunc("/containers/"+stoppedID+"/json", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"Id":"` + stoppedID + `","Name":"/stopped","Image":"sha256:def","State":{"Running":false,"Pid":0},"Config":{},"HostConfig":{}}`))
	})
	mux.HandleFunc("/containers/"+shopID+"/json", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"Id":"` + shopID + `","Name":"/shop-web-1","Image":"sha256:abc","State":{"Running":true,"Pid":2201},` +
			`"Config":{"User":"node","Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"web","com.docker.compose.project.working_dir":"/srv/shop",` +
			`"com.docker.compose.project.config_files":"/srv/shop/compose.yml,/srv/shop/compose.prod.yml"}},` +
			`"HostConfig":{"Privileged":false,"NetworkMode":"shop_default"},` +
			`"Mounts":[{"Type":"bind","Source":"/srv/shop/uploads","Destination":"/app/uploads","RW":true},` +
			`{"Type":"volume","Source":"/var/lib/docker/volumes/shop_cache/_data","Destination":"/app/.cache","RW":true}]}`))
	})
	mux.HandleFunc("/images/sha256:abc/json", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"Id":"sha256:abc","Config":{"Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"web","com.docker.compose.version":"2.40.3"}}}`))
	})
	return mux
}

func connect(s string) DockerAPI { return dockerapi.New(s) }

func TestDockerContainers(t *testing.T) {
	sock := dockerServer(t, engine(http.StatusOK))
	items, origins, problems := collectDocker(context.Background(), "unix://"+sock, true, connect, map[string][]int{shopID: {2240, 2201}}, fakeSource{})
	if len(problems) != 0 {
		t.Fatalf("problems %+v", problems)
	}
	if len(items) != 1 {
		t.Fatalf("items %+v", items)
	}
	it := items[0]
	if it.ID != "container:shop-web-1" || it.Kind != KindContainer || it.Name != "shop-web-1" || it.ContainerID != shopID ||
		it.Image != "ghcr.io/acme/shop:2026.11.3" || it.ImageID != "sha256:abc" || it.User != "node" || it.NetworkMode != "shop_default" {
		t.Fatalf("item %+v", it)
	}
	if it.Compose == nil || !reflect.DeepEqual(*it.Compose, Compose{Project: "shop", Service: "web", WorkingDir: "/srv/shop", ConfigFiles: []string{"/srv/shop/compose.yml", "/srv/shop/compose.prod.yml"}}) {
		t.Fatalf("compose %+v", it.Compose)
	}
	if !slices.Equal(it.Ports, []Port{
		{IP: "0.0.0.0", HostPort: 8443, ContainerPort: 443, Protocol: "tcp"},
		{IP: "0.0.0.0", HostPort: 8080, ContainerPort: 3000, Protocol: "tcp"},
		{IP: "0.0.0.0", HostPort: 8081, ContainerPort: 3000, Protocol: "tcp"},
		{IP: "::", HostPort: 8080, ContainerPort: 3000, Protocol: "tcp"},
		{IP: "0.0.0.0", HostPort: 8080, ContainerPort: 3000, Protocol: "udp"},
	}) {
		t.Fatalf("ports %+v (unpublished ports are left out)", it.Ports)
	}
	if !slices.Equal(it.Mounts, []Mount{
		{Type: "volume", Source: "/var/lib/docker/volumes/shop_cache/_data", Destination: "/app/.cache", ReadWrite: true},
		{Type: "bind", Source: "/srv/shop/uploads", Destination: "/app/uploads", ReadWrite: true},
	}) {
		t.Fatalf("mounts %+v", it.Mounts)
	}
	if !slices.Equal(it.PIDs, []int{2201, 2240}) || !slices.Equal(it.Notes, []string{problem.ImageOnly}) {
		t.Fatalf("pids %v notes %v", it.PIDs, it.Notes)
	}
	want := Origin{ID: "image:sha256:abc", Kind: OriginImage, ImageID: "sha256:abc", Ref: "ghcr.io/acme/shop:2026.11.3"}
	if len(origins) != 1 || origins[0].ID != want.ID || origins[0].Ref != want.Ref || !slices.Equal(it.Origins, []string{want.ID}) {
		t.Fatalf("origins %+v", origins)
	}
}

func TestDockerComposeLabelsOfTheImage(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		kept   bool
	}{
		{"the image names the files", http.StatusOK, `{"Id":"sha256:abc","Config":{"Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"web",` +
			`"com.docker.compose.project.config_files":"/srv/shop/compose.yml,/srv/shop/compose.prod.yml"}}}`, false},
		{"the image names the directory", http.StatusOK, `{"Id":"sha256:abc","Config":{"Labels":{"com.docker.compose.project.working_dir":"/srv/shop"}}}`, false},
		{"Compose replaced the image's files", http.StatusOK, `{"Id":"sha256:abc","Config":{"Labels":{"com.docker.compose.project.config_files":"/tmp/evil.yml"}}}`, true},
		{"the image is gone", http.StatusNotFound, `{"message":"No such image: sha256:abc"}`, false},
		{"the image cannot be read", http.StatusInternalServerError, `{"message":"boom"}`, false},
	}
	for _, c := range cases {
		sock := dockerServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/images/sha256:abc/json" {
				engine(http.StatusOK).ServeHTTP(w, r)
				return
			}
			w.WriteHeader(c.status)
			w.Write([]byte(c.body))
		}))
		items, _, p := collectDocker(context.Background(), "unix://"+sock, true, connect, map[string][]int{shopID: {2201}}, fakeSource{})
		if len(items) != 1 || len(p) != 0 {
			t.Errorf("%s: items %+v problems %+v", c.name, items, p)
		} else if (items[0].Compose != nil) != c.kept {
			t.Errorf("%s: compose %+v", c.name, items[0].Compose)
		}
	}
}

func TestDockerProblems(t *testing.T) {
	ctx := context.Background()
	_, _, p := collectDocker(ctx, "unix:///nonexistent/docker.sock", true, connect, nil, fakeSource{})
	if len(p) != 1 || p[0].Code != problem.DockerAbsent || p[0].Kind != problem.Notice {
		t.Fatalf("absent: %+v", p)
	}
	_, _, p = collectDocker(ctx, "unix:///nonexistent/docker.sock", true, connect, map[string][]int{shopID: {2201}}, fakeSource{})
	if len(p) != 1 || p[0].Code != problem.DockerUnavailable || p[0].Kind != problem.Error || p[0].Stage != "inventory" ||
		!strings.Contains(p[0].Message, "1 container(s) have running processes, but dockerd does not listen on /nonexistent/docker.sock") ||
		!strings.Contains(p[0].Message, "set DOCKER_HOST to its socket") {
		t.Fatalf("socket missing with running containers: %+v", p)
	}
	notDir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notDir, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, p = collectDocker(ctx, "unix://"+notDir+"/docker.sock", true, connect, nil, fakeSource{})
	if len(p) != 1 || p[0].Code != problem.DockerUnavailable || p[0].Kind != problem.Error {
		t.Fatalf("stat error: %+v", p)
	}
	_, _, p = collectDocker(ctx, "tcp://10.0.0.5:2375", true, connect, nil, fakeSource{})
	if len(p) != 1 || p[0].Code != problem.DockerUnavailable || p[0].Kind != problem.Error {
		t.Fatalf("tcp: %+v", p)
	}
	sock := dockerServer(t, engine(http.StatusInternalServerError))
	_, _, p = collectDocker(ctx, "unix://"+sock, true, connect, nil, fakeSource{})
	if len(p) != 1 || p[0].Code != problem.DockerUnavailable {
		t.Fatalf("ping failure: %+v", p)
	}
}

func TestDockerNotRunning(t *testing.T) {
	requests := 0
	sock := dockerServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		engine(http.StatusOK).ServeHTTP(w, r)
	}))
	ctx := context.Background()
	_, _, p := collectDocker(ctx, "unix://"+sock, false, connect, nil, fakeSource{})
	if len(p) != 1 || p[0].Code != problem.DockerAbsent || p[0].Kind != problem.Notice || !strings.Contains(p[0].Message, "no Docker daemon") {
		t.Fatalf("no dockerd, no containers: %+v", p)
	}
	_, _, p = collectDocker(ctx, "unix://"+sock, false, connect, map[string][]int{shopID: {2201}}, fakeSource{})
	if len(p) != 1 || p[0].Code != problem.DockerUnavailable || p[0].Kind != problem.Error || p[0].Stage != "inventory" ||
		!strings.Contains(p[0].Message, "1 container(s) have running processes, but no Docker daemon") {
		t.Fatalf("no dockerd, running containers: %+v", p)
	}
	if requests != 0 {
		t.Fatalf("%d requests reached the Docker socket while no dockerd runs", requests)
	}
	items, _, p := collectDocker(ctx, "unix://"+sock, true, connect, map[string][]int{shopID: {2201}}, fakeSource{})
	if len(p) != 0 || len(items) != 1 || requests == 0 {
		t.Fatalf("dockerd running: items %+v problems %+v requests %d", items, p, requests)
	}
}

func TestDockerContainersItDoesNotList(t *testing.T) {
	const otherID = "0000000000000000000000000000000000000000000000000000000000000003"
	sock := dockerServer(t, engine(http.StatusOK))
	pids := map[string][]int{shopID: {2201}, otherID: {3001, 3002}}
	running := fakeSource{3002: {cmdline: []string{"redis-server"}, cgroup: cg("/system.slice/docker-" + otherID + ".scope")}}
	items, _, p := collectDocker(context.Background(), "unix://"+sock, true, connect, pids, running)
	if len(items) != 1 || len(p) != 1 || p[0].Code != problem.DockerUnavailable || p[0].Kind != problem.Error || p[0].Stage != "inventory" ||
		!strings.Contains(p[0].Message, "1 container(s)") {
		t.Fatalf("items %+v problems %+v", items, p)
	}
	ended := fakeSource{3002: {cmdline: []string{"nginx"}, cgroup: cg("/system.slice/nginx.service")}}
	items, _, p = collectDocker(context.Background(), "unix://"+sock, true, connect, pids, ended)
	if len(items) != 1 || len(p) != 0 {
		t.Fatalf("items %+v problems %+v", items, p)
	}
}

func TestDockerListedContainersAreNotUnlisted(t *testing.T) {
	const goneID = "0000000000000000000000000000000000000000000000000000000000000001"
	sock := dockerServer(t, engine(http.StatusOK))
	pids := map[string][]int{shopID: {2201}, stoppedID: {3001}, goneID: {3002}}
	src := fakeSource{
		3001: {cmdline: []string{"sh"}, cgroup: cg("/system.slice/docker-" + stoppedID + ".scope")},
		3002: {cmdline: []string{"sh"}, cgroup: cg("/system.slice/docker-" + goneID + ".scope")},
	}
	items, _, p := collectDocker(context.Background(), "unix://"+sock, true, connect, pids, src)
	if len(items) != 1 || len(p) != 0 {
		t.Fatalf("items %+v problems %+v", items, p)
	}
}
