package dockerapi

import (
	"context"
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
