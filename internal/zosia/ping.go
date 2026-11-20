package zosia

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Ping checks a secret with GET /api/v1/ping and returns the secret's name in Zosia.
func Ping(ctx context.Context, hc *http.Client, url, secret, userAgent string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(url, "/")+"/api/v1/ping", nil)
	if err != nil {
		return "", &Error{Code: "NETWORK", Message: "invalid Zosia URL: " + err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("User-Agent", userAgent)
	resp, err := hc.Do(req)
	if err != nil {
		return "", &Error{Code: "NETWORK", Message: "cannot reach Zosia: " + unwrapped(err)}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var body struct {
		OK      bool   `json:"ok"`
		Secret  string `json:"secret"`
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(data, &body)
	if resp.StatusCode == http.StatusOK && body.OK {
		return body.Secret, nil
	}
	if body.Code == "" {
		body.Code, body.Message = fmt.Sprintf("HTTP_%d", resp.StatusCode), "Zosia answered "+resp.Status
	}
	return "", &Error{Code: body.Code, Message: body.Message}
}
