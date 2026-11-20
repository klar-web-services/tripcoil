package zosia

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/api/v1/ping" || req.Header.Get("Authorization") != "Bearer zosia_good" {
			w.WriteHeader(401)
			io.WriteString(w, `{"code":"BAD_SECRET","message":"This secret is unknown or was revoked."}`)
			return
		}
		io.WriteString(w, `{"ok":true,"secret":"taskmaster"}`)
	}))
	defer srv.Close()
	if name, err := Ping(context.Background(), srv.Client(), srv.URL, "zosia_good", "tripcoil/test"); err != nil || name != "taskmaster" {
		t.Fatalf("%q %v", name, err)
	}
	if _, err := Ping(context.Background(), srv.Client(), srv.URL, "zosia_bad", "tripcoil/test"); err == nil || err.(*Error).Code != "BAD_SECRET" {
		t.Fatalf("%v", err)
	}
}
