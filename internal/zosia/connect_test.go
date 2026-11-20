package zosia

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testDeviceCode = "device-code-only-the-machine-knows"

func fastConnect(t *testing.T) {
	old := connectUnit
	connectUnit = time.Millisecond
	t.Cleanup(func() { connectUnit = old })
}

func TestStartConnect(t *testing.T) {
	var got map[string]string
	var agent, path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		agent, path = req.Header.Get("User-Agent"), req.Method+" "+req.URL.Path
		json.NewDecoder(req.Body).Decode(&got)
		w.WriteHeader(201)
		io.WriteString(w, `{"deviceCode":"`+testDeviceCode+`","userCode":"BCDF-GHJK","verificationUri":"https://zosiasec.com/app/connect",
			"verificationUriComplete":"https://zosiasec.com/app/connect?code=BCDF-GHJK","expiresIn":600,"interval":5}`)
	}))
	defer srv.Close()
	r, err := StartConnect(context.Background(), srv.Client(), srv.URL+"/", "tripcoil/1.2.0", HostInfo{Hostname: "web-1", OS: "debian 13", Version: "1.2.0"})
	want := ConnectRequest{DeviceCode: testDeviceCode, UserCode: "BCDF-GHJK", VerificationURI: "https://zosiasec.com/app/connect",
		VerificationURIComplete: "https://zosiasec.com/app/connect?code=BCDF-GHJK", ExpiresIn: 600, Interval: 5}
	if err != nil || r != want {
		t.Fatalf("%+v %v", r, err)
	}
	if path != "POST /api/v1/connect" || agent != "tripcoil/1.2.0" || got["hostname"] != "web-1" || got["os"] != "debian 13" || got["tripcoilVersion"] != "1.2.0" {
		t.Fatalf("%s as %s: %v", path, agent, got)
	}
}

func TestStartConnectErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(429)
		io.WriteString(w, `{"code":"RATE_LIMITED","message":"Too many requests from this address. Try again later."}`)
	}))
	defer srv.Close()
	_, err := StartConnect(context.Background(), srv.Client(), srv.URL, "tripcoil/test", HostInfo{})
	if e, ok := err.(*Error); !ok || e.Code != "RATE_LIMITED" || e.Message != "Too many requests from this address. Try again later." {
		t.Fatalf("%#v", err)
	}
	_, err = StartConnect(context.Background(), http.DefaultClient, "http://127.0.0.1:1", "tripcoil/test", HostInfo{})
	if e, ok := err.(*Error); !ok || e.Code != "NETWORK" {
		t.Fatalf("%#v", err)
	}
}

func TestWaitConnectPollsUntilApproved(t *testing.T) {
	fastConnect(t)
	var n atomic.Int32
	var body, path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		data, _ := io.ReadAll(req.Body)
		body, path = string(data), req.Method+" "+req.URL.Path
		switch n.Add(1) {
		case 1:
			w.WriteHeader(202)
			io.WriteString(w, `{"code":"PENDING"}`)
		case 2:
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(429)
			io.WriteString(w, `{"code":"SLOW_DOWN","message":"Asked again too soon."}`)
		case 3:
			w.WriteHeader(503)
		default:
			io.WriteString(w, `{"secret":"zosia_new","name":"web-1"}`)
		}
	}))
	defer srv.Close()
	start := time.Now()
	secret, name, err := WaitConnect(context.Background(), srv.Client(), srv.URL, "tripcoil/test", ConnectRequest{DeviceCode: testDeviceCode, ExpiresIn: 5000, Interval: 2})
	if err != nil || secret != "zosia_new" || name != "web-1" || n.Load() != 4 {
		t.Fatalf("%q %q %v after %d polls", secret, name, err, n.Load())
	}
	if path != "POST /api/v1/connect/token" || body != `{"deviceCode":"`+testDeviceCode+`"}` {
		t.Fatalf("%s %s", path, body)
	}
	if waited := time.Since(start); waited < 13*time.Millisecond {
		t.Fatalf("waited only %s: the interval before each poll, and Retry-After, must pass", waited)
	}
}

func TestWaitConnectEnds(t *testing.T) {
	fastConnect(t)
	answer := func(status int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(status)
			io.WriteString(w, body)
		}
	}
	for _, c := range []struct {
		name    string
		handler http.HandlerFunc
		expires int
		code    string
	}{
		{"denied", answer(403, `{"code":"DENIED","message":"The request was denied in Zosia."}`), 5000, "DENIED"},
		{"expired", answer(410, `{"code":"EXPIRED","message":"The request has expired."}`), 5000, "EXPIRED"},
		{"plan limit", answer(403, `{"code":"PLAN_LIMIT","message":"The account's plan allows 10 secrets."}`), 5000, "PLAN_LIMIT"},
		{"never answered", answer(202, `{"code":"PENDING"}`), 20, "EXPIRED"},
		{"not a result", answer(200, `<html>`), 5000, "BAD_RESPONSE"},
	} {
		srv := httptest.NewServer(c.handler)
		secret, _, err := WaitConnect(context.Background(), srv.Client(), srv.URL, "tripcoil/test", ConnectRequest{DeviceCode: testDeviceCode, ExpiresIn: c.expires, Interval: 1})
		srv.Close()
		if e, ok := err.(*Error); !ok || e.Code != c.code || secret != "" || strings.Contains(err.Error(), testDeviceCode) {
			t.Errorf("%s: %q %#v", c.name, secret, err)
		}
	}

	srv := httptest.NewServer(answer(202, `{"code":"PENDING"}`))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(10*time.Millisecond, cancel)
	_, _, err := WaitConnect(ctx, srv.Client(), srv.URL, "tripcoil/test", ConnectRequest{DeviceCode: testDeviceCode, ExpiresIn: 60000, Interval: 1})
	if e, ok := err.(*Error); !ok || e.Code != "CANCELLED" {
		t.Fatalf("cancelled: %#v", err)
	}

	_, _, err = WaitConnect(context.Background(), http.DefaultClient, "http://127.0.0.1:1", "tripcoil/test", ConnectRequest{DeviceCode: testDeviceCode, ExpiresIn: 20, Interval: 1})
	if e, ok := err.(*Error); !ok || e.Code != "NETWORK" || strings.Contains(err.Error(), testDeviceCode) {
		t.Fatalf("unreachable: %#v", err)
	}
}
