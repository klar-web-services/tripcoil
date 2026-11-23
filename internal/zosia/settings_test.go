package zosia

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchSettings(t *testing.T) {
	var got struct {
		MachineKey string            `json:"machineKey"`
		Client     map[string]string `json:"client"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost || req.URL.Path != "/api/v1/machine/settings" || req.URL.RawQuery != "" || req.Header.Get("Authorization") != "Bearer zosia_good" {
			w.WriteHeader(401)
			io.WriteString(w, `{"code":"BAD_SECRET","message":"This secret is unknown or was revoked."}`)
			return
		}
		body, _ := io.ReadAll(req.Body)
		_ = json.Unmarshal(body, &got)
		io.WriteString(w, `{"schema":"zosia.settings/1","version":7,"keepWaiting":[{"key":"w:2ffdd1b1d089","until":"2026-12-23T10:00:00Z"}]}`)
	}))
	defer srv.Close()
	key := strings.Repeat("ab", 16)
	data, err := FetchSettings(context.Background(), srv.Client(), srv.URL, "zosia_good", key, "1.6.0")
	if err != nil || !strings.Contains(string(data), `"version":7`) {
		t.Fatalf("%s %v", data, err)
	}
	// The machine's key travels in the body, never in the URL.
	if got.MachineKey != key || got.Client["name"] != "tripcoil" || got.Client["version"] != "1.6.0" {
		t.Errorf("the request body: %+v", got)
	}
	if _, err := FetchSettings(context.Background(), srv.Client(), srv.URL, "zosia_bad", key, "1.6.0"); err == nil || err.(*Error).Code != "BAD_SECRET" {
		t.Errorf("a bad secret: %v", err)
	}
	srv.Close()
	if _, err := FetchSettings(context.Background(), srv.Client(), srv.URL, "zosia_good", key, "1.6.0"); err == nil || err.(*Error).Code != "NETWORK" {
		t.Errorf("no server: %v", err)
	}
}

func TestFetchSettingsRefusesALargeAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, `{"schema":"zosia.settings/1","version":1,"x":"`+strings.Repeat("a", MaxSettings)+`"}`)
	}))
	defer srv.Close()
	if _, err := FetchSettings(context.Background(), srv.Client(), srv.URL, "zosia_good", "k", "1.6.0"); err == nil || err.(*Error).Code != "BAD_RESPONSE" {
		t.Errorf("an answer over the limit: %v", err)
	}
}

func TestParseSettings(t *testing.T) {
	now := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	s, err := ParseSettings([]byte(`{"schema":"zosia.settings/1","version":7,"future":{"run":"rm -rf /"},"keepWaiting":[
		{"key":"w:2ffdd1b1d089","until":"2026-12-23T10:00:00Z"},
		{"key":"w:aaaaaaaaaaaa","until":"2030-01-01T00:00:00Z"},
		{"key":"a:2ffdd1b1d089","until":"2026-12-23T10:00:00Z"},
		{"key":"w:2ffdd1b1d089; rm","until":"2026-12-23T10:00:00Z"},
		{"key":"w:bbbbbbbbbbbb","until":"tomorrow"},
		{"key":"w:cccccccccccc","until":"2026-11-01T00:00:00Z"},
		{"key":"w:2ffdd1b1d089","until":"2026-12-01T00:00:00Z"},
		"junk", 7, null]}`), now)
	if err != nil || s.Version != 7 {
		t.Fatalf("%+v %v", s, err)
	}
	// A time further away than 31 days counts as 31 days; a key that is none, a time that is none or has
	// passed, and a key's second entry are ignored.
	want := map[string]time.Time{"w:2ffdd1b1d089": time.Date(2026, 12, 23, 10, 0, 0, 0, time.UTC), "w:aaaaaaaaaaaa": now.Add(31 * 24 * time.Hour)}
	if len(s.KeepWaiting) != len(want) {
		t.Fatalf("kept %v", s.KeepWaiting)
	}
	for k, until := range want {
		if !s.KeepWaiting[k].Equal(until) {
			t.Errorf("%s until %v, want %v", k, s.KeepWaiting[k], until)
		}
	}
	for name, data := range map[string]string{
		"not JSON":       `settings`,
		"another schema": `{"schema":"zosia.settings/2","version":1,"keepWaiting":[]}`,
		"no version":     `{"schema":"zosia.settings/1","keepWaiting":[]}`,
		"a negative one": `{"schema":"zosia.settings/1","version":-1}`,
		"a list":         `[]`,
	} {
		if _, err := ParseSettings([]byte(data), now); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// No entries is a document like any other.
	if s, err := ParseSettings([]byte(`{"schema":"zosia.settings/1","version":0}`), now); err != nil || s.Version != 0 || len(s.KeepWaiting) != 0 {
		t.Errorf("an empty document: %+v %v", s, err)
	}
	var many []string
	for i := range 300 {
		many = append(many, fmt.Sprintf(`{"key":"w:%012x","until":"2026-12-01T00:00:00Z"}`, i))
	}
	if s, err := ParseSettings([]byte(`{"schema":"zosia.settings/1","version":1,"keepWaiting":[`+strings.Join(many, ",")+`]}`), now); err != nil || len(s.KeepWaiting) != MaxKeepWaiting {
		t.Errorf("300 entries: %d %v", len(s.KeepWaiting), err)
	}
}
