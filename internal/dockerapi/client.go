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

var ErrNotFound = errors.New("not found")

func Socket(dockerHost string) (string, error) {
	if dockerHost == "" {
		return "/var/run/docker.sock", nil
	}
	if p, ok := strings.CutPrefix(dockerHost, "unix://"); ok {
		return p, nil
	}
	return "", fmt.Errorf("DOCKER_HOST=%s is not a unix socket; Tripcoil only reads the local Docker daemon through its unix socket", dockerHost)
}

type Client struct{ hc *http.Client }

func New(socket string) *Client {
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

func (c *Client) Ping(ctx context.Context) error { return c.get(ctx, "/_ping", nil) }

func (c *Client) Containers(ctx context.Context) ([]Summary, error) {
	var s []Summary
	err := c.get(ctx, "/containers/json", &s)
	return s, err
}

func (c *Client) Inspect(ctx context.Context, id string) (Detail, error) {
	var d Detail
	err := c.get(ctx, "/containers/"+url.PathEscape(id)+"/json", &d)
	return d, err
}

func (c *Client) InspectImage(ctx context.Context, id string) (Image, error) {
	var img Image
	err := c.get(ctx, "/images/"+url.PathEscape(id)+"/json", &img)
	return img, err
}

func (c *Client) ImageExists(ctx context.Context, id string) (bool, error) {
	err := c.get(ctx, "/images/"+url.PathEscape(id)+"/json", nil)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}
