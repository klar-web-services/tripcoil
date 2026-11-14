// Package dockerapi is a minimal client for the parts of the Docker Engine API that Tripcoil reads.
package dockerapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrNotFound is what a request for a container that no longer exists returns.
var ErrNotFound = errors.New("not found")

// Client talks to the Docker daemon over its unix socket.
type Client struct{ hc *http.Client }

// New returns a client for the unix socket at path.
func New(socket string) *Client {
	// Without keep-alives no idle connection outlives a run of the daemon.
	tr := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}}
	return &Client{hc: &http.Client{Transport: tr, Timeout: 30 * time.Second}}
}

func (c *Client) get(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("GET %s: %w", path, ErrNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("GET %s: %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
	}
	if v == nil {
		_, err = io.Copy(io.Discard, resp.Body)
		return err
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// Ping checks that the daemon answers.
func (c *Client) Ping(ctx context.Context) error { return c.get(ctx, "/_ping", nil) }

// Containers lists the running containers.
func (c *Client) Containers(ctx context.Context) ([]Summary, error) {
	var s []Summary
	err := c.get(ctx, "/containers/json", &s)
	return s, err
}

// Inspect returns one container's details.
func (c *Client) Inspect(ctx context.Context, id string) (Detail, error) {
	var d Detail
	err := c.get(ctx, "/containers/"+url.PathEscape(id)+"/json", &d)
	return d, err
}
