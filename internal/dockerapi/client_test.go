package dockerapi

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
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
