package dockerapi

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSocket(t *testing.T) {
	for host, want := range map[string]string{"": "/var/run/docker.sock", "unix:///run/user/1000/docker.sock": "/run/user/1000/docker.sock"} {
		if got, err := Socket(host); got != want || err != nil {
			t.Errorf("DOCKER_HOST=%q: %q %v", host, got, err)
		}
	}
	if got, err := Socket("tcp://10.0.0.5:2375"); got != "" || err == nil ||
		err.Error() != "DOCKER_HOST=tcp://10.0.0.5:2375 is not a unix socket; Tripcoil only reads the local Docker daemon through its unix socket" {
		t.Errorf("tcp: %q %v", got, err)
	}
}

func TestNoConnectionLeftOpen(t *testing.T) {
	dir, err := os.MkdirTemp("", "tc-docker") // short path: unix socket paths are limited to 108 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "docker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var open atomic.Int64
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/containers/json" {
				w.Write([]byte("[]"))
				return
			}
			w.Write([]byte("{}"))
		}),
		ConnState: func(_ net.Conn, s http.ConnState) {
			switch s {
			case http.StateNew:
				open.Add(1)
			case http.StateClosed, http.StateHijacked:
				open.Add(-1)
			}
		},
	}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })

	c := New(sock)
	ctx := context.Background()
	for range 3 {
		if err := c.Ping(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Containers(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Inspect(ctx, "web"); err != nil {
			t.Fatal(err)
		}
		if _, err := c.InspectImage(ctx, "sha256:1111"); err != nil {
			t.Fatal(err)
		}
	}
	for deadline := time.Now().Add(2 * time.Second); open.Load() != 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d connections left open after the requests", open.Load())
		}
	}
}

func TestImageExists(t *testing.T) {
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
	var mu sync.Mutex
	var paths []string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/images/sha256:1111/json":
			w.Write([]byte(`{"Id":"sha256:1111"}`))
		case "/images/sha256:2222/json":
			http.Error(w, `{"message":"No such image: sha256:2222"}`, http.StatusNotFound)
		default:
			http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
		}
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })

	c := New(sock)
	ctx := context.Background()
	if ok, err := c.ImageExists(ctx, "sha256:1111"); !ok || err != nil {
		t.Errorf("an image the daemon has: %v %v", ok, err)
	}
	if ok, err := c.ImageExists(ctx, "sha256:2222"); ok || err != nil {
		t.Errorf("a removed image: %v %v", ok, err)
	}
	if ok, err := c.ImageExists(ctx, "sha256:3333"); ok || err == nil {
		t.Errorf("a daemon error: %v %v", ok, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if want := []string{"GET /images/sha256:1111/json", "GET /images/sha256:2222/json", "GET /images/sha256:3333/json"}; !slices.Equal(paths, want) {
		t.Errorf("requests %q", paths)
	}
}

// What the routes and the reach need from Docker: a container's names and addresses, the networks'
// drivers, and a Swarm manager's services. Real answers of Docker 28 (API 1.56), shortened.
func TestNetworksAndServices(t *testing.T) {
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
	manager := true
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/networks":
			w.Write([]byte(`[{"Name":"host","Id":"h1","Driver":"host"},{"Name":"servarr_default","Id":"n1","Driver":"bridge"},{"Name":"lan","Id":"n2","Driver":"macvlan"}]`))
		case r.URL.Path == "/services" && manager:
			w.Write([]byte(`[{"ID":"s1","Spec":{"Name":"dokploy","Labels":{"traefik.enable":"true"}},"Endpoint":{"Ports":[{"Protocol":"tcp","TargetPort":3000,"PublishedPort":3000,"PublishMode":"host"},{"Protocol":"tcp","TargetPort":80,"PublishedPort":8080,"PublishMode":"ingress"}]}}]`))
		case r.URL.Path == "/services":
			http.Error(w, `{"message":"This node is not a swarm manager. Use \"docker swarm init\" or \"docker swarm join\" to connect this node to swarm and try again."}`, http.StatusServiceUnavailable)
		case r.URL.Path == "/containers/c1/json":
			w.Write([]byte(`{"Id":"c1","Name":"/sonarr","NetworkSettings":{"Networks":{"servarr_default":{"NetworkID":"n1","IPAddress":"172.20.0.5","GlobalIPv6Address":"","Aliases":["sonarr"],"DNSNames":["sonarr","0123456789ab"]}}}}`))
		}
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })

	c := New(sock)
	ctx := context.Background()
	nets, err := c.Networks(ctx)
	if err != nil || len(nets) != 3 || nets[2] != (Network{ID: "n2", Name: "lan", Driver: "macvlan"}) {
		t.Errorf("networks: %+v %v", nets, err)
	}
	svcs, err := c.Services(ctx)
	if err != nil || len(svcs) != 1 || svcs[0].Spec.Name != "dokploy" || svcs[0].Spec.Labels["traefik.enable"] != "true" ||
		!slices.Equal(svcs[0].Endpoint.Ports, []ServicePort{{"tcp", 3000, 3000, "host"}, {"tcp", 80, 8080, "ingress"}}) {
		t.Errorf("services: %+v %v", svcs, err)
	}
	manager = false
	if _, err := c.Services(ctx); !errors.Is(err, ErrNotManager) {
		t.Errorf("a worker or a node outside a swarm: %v", err)
	}
	d, err := c.Inspect(ctx, "c1")
	ep := d.NetworkSettings.Networks["servarr_default"]
	if err != nil || ep.NetworkID != "n1" || ep.IPAddress != "172.20.0.5" || !slices.Equal(ep.DNSNames, []string{"sonarr", "0123456789ab"}) {
		t.Errorf("a container's networks: %+v %v", d.NetworkSettings, err)
	}
}

// Which image a tag points to in its registry, and under which digests the daemon got an image:
// together they say whether the tag has moved since.
func TestTagDigestAndRepoDigests(t *testing.T) {
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
	var asked []string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		switch r.URL.Path {
		case "/distribution/ghcr.io/acme/shop:latest/json":
			w.Write([]byte(`{"Descriptor":{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"sha256:aaa","size":1609},"Platforms":[{"architecture":"amd64","os":"linux"}]}`))
		case "/distribution/local/built:latest/json":
			http.Error(w, `{"message":"pull access denied"}`, http.StatusUnauthorized)
		case "/images/sha256:111/json":
			w.Write([]byte(`{"Id":"sha256:111","RepoDigests":["ghcr.io/acme/shop@sha256:bbb","mirror.example/shop@sha256:ccc"]}`))
		default:
			http.NotFound(w, r)
		}
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })

	c := New(sock)
	ctx := context.Background()
	if d, err := c.TagDigest(ctx, "ghcr.io/acme/shop:latest"); err != nil || d != "sha256:aaa" {
		t.Errorf("the tag's digest: %q %v", d, err)
	}
	if _, err := c.TagDigest(ctx, "local/built:latest"); err == nil {
		t.Error("an image that is in no registry")
	}
	// A reference is put into the request's path: nothing that could change the request is sent.
	before := len(asked)
	for _, ref := range []string{"", "shop:latest?x=1", "shop:latest#frag", "shop latest", "../images/x", "shop:latest/../../x"} {
		if _, err := c.TagDigest(ctx, ref); err == nil {
			t.Errorf("%q was asked for", ref)
		}
	}
	if len(asked) != before {
		t.Errorf("a bad reference reached the daemon: %v", asked[before:])
	}
	if got, err := c.RepoDigests(ctx, "sha256:111"); err != nil || len(got) != 2 || got[0] != "sha256:bbb" || got[1] != "sha256:ccc" {
		t.Errorf("the image's digests: %v %v", got, err)
	}
}
