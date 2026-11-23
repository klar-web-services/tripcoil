package zosia

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// What Zosia tells a machine: a small document that Tripcoil fetches before a run. It is data with
// a fixed list of fields. Nothing in it is ever run, opened as a path or written to the
// configuration, and each field can only do what the code that reads it allows.
const (
	SettingsSchema = "zosia.settings/1"
	// MaxSettings is the most bytes of a settings document.
	MaxSettings = 64 << 10
	// MaxKeepWaiting is the most keepWaiting entries that count; the rest is ignored.
	MaxKeepWaiting = 200
	// MaxKeepAhead is the furthest ahead an entry's time counts.
	MaxKeepAhead = 31 * 24 * time.Hour
)

var waitingKey = regexp.MustCompile(`^w:[0-9a-f]{12}$`)

// Settings is a checked settings document. KeepWaiting has, by waiting key, until when a card
// with no fixed release stays waiting past its 30 days.
type Settings struct {
	Version     int
	KeepWaiting map[string]time.Time
}

// FetchSettings asks Zosia for the machine's settings and returns the answer as it came. The
// machine's key travels in the body, never in the URL.
func FetchSettings(ctx context.Context, hc *http.Client, url, secret, machineKey, version string) ([]byte, error) {
	body, err := json.Marshal(map[string]any{"machineKey": machineKey, "client": map[string]string{"name": "tripcoil", "version": version}})
	if err != nil {
		return nil, &Error{Code: "PAYLOAD", Message: err.Error()}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(url, "/")+"/api/v1/machine/settings", bytes.NewReader(body))
	if err != nil {
		return nil, &Error{Code: "NETWORK", Message: "invalid Zosia URL: " + err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "tripcoil/"+version)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, &Error{Code: "NETWORK", Message: "cannot reach Zosia: " + unwrapped(err)}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, MaxSettings+1))
	if resp.StatusCode != http.StatusOK {
		return nil, answerError(resp.StatusCode, resp.Header, data[:min(len(data), 64<<10)])
	}
	if len(data) > MaxSettings {
		return nil, &Error{Code: "BAD_RESPONSE", Message: "Zosia's settings are larger than 64 KiB"}
	}
	return data, nil
}

// ParseSettings checks a settings document. A document of another schema or without a version is
// refused as a whole; an entry that breaks a rule and a field this version does not know are
// ignored.
func ParseSettings(data []byte, now time.Time) (Settings, error) {
	var doc struct {
		Schema      string            `json:"schema"`
		Version     *int              `json:"version"`
		KeepWaiting []json.RawMessage `json:"keepWaiting"`
	}
	if len(data) > MaxSettings {
		return Settings{}, errors.New("the settings are larger than 64 KiB")
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return Settings{}, errors.New("the settings are not a JSON object of the expected form")
	}
	if doc.Schema != SettingsSchema {
		return Settings{}, errors.New("the settings have another schema than " + SettingsSchema)
	}
	if doc.Version == nil || *doc.Version < 0 {
		return Settings{}, errors.New("the settings have no version")
	}
	s := Settings{Version: *doc.Version, KeepWaiting: map[string]time.Time{}}
	for _, raw := range doc.KeepWaiting {
		var e struct {
			Key   string `json:"key"`
			Until string `json:"until"`
		}
		if len(s.KeepWaiting) == MaxKeepWaiting {
			break
		}
		if json.Unmarshal(raw, &e) != nil || !waitingKey.MatchString(e.Key) {
			continue
		}
		until, err := time.Parse(time.RFC3339, e.Until)
		if _, seen := s.KeepWaiting[e.Key]; err != nil || seen || !until.After(now) {
			continue
		}
		if until.After(now.Add(MaxKeepAhead)) {
			until = now.Add(MaxKeepAhead)
		}
		s.KeepWaiting[e.Key] = until.UTC()
	}
	return s, nil
}
