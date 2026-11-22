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
	"regexp"
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

func (c *Client) Networks(ctx context.Context) ([]Network, error) {
	var n []Network
	err := c.get(ctx, "/networks", &n)
	return n, err
}

// ErrNotManager says that this node cannot list Swarm services: it is a worker, or not in a swarm.
var ErrNotManager = errors.New("this node is not a swarm manager")

func (c *Client) Services(ctx context.Context) ([]Service, error) {
	var s []Service
	err := c.get(ctx, "/services", &s)
	if err != nil && strings.Contains(err.Error(), "503") {
		return nil, ErrNotManager
	}
	return s, err
}

func (c *Client) InspectImage(ctx context.Context, id string) (Image, error) {
	var img Image
	err := c.get(ctx, "/images/"+url.PathEscape(id)+"/json", &img)
	return img, err
}

// plainRef is an image reference that is safe to put into a request's path.
var plainRef = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*(:[A-Za-z0-9._-]+)+$`)

// TagDigest asks the registry, through the daemon and with its credentials, which image a tagged
// reference points to now. Nothing is pulled.
func (c *Client) TagDigest(ctx context.Context, ref string) (string, error) {
	if !plainRef.MatchString(ref) || strings.Contains(ref, "..") {
		return "", fmt.Errorf("%q is not a tagged image reference", ref)
	}
	var out struct {
		Descriptor struct {
			Digest string `json:"digest"`
		} `json:"Descriptor"`
	}
	if err := c.get(ctx, "/distribution/"+ref+"/json", &out); err != nil {
		return "", err
	}
	if !strings.HasPrefix(out.Descriptor.Digest, "sha256:") {
		return "", errors.New("the registry named no digest")
	}
	return out.Descriptor.Digest, nil
}

// RepoDigests are the digests an image was pulled under, without their repositories.
func (c *Client) RepoDigests(ctx context.Context, id string) ([]string, error) {
	img, err := c.InspectImage(ctx, id)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, d := range img.RepoDigests {
		if _, digest, ok := strings.Cut(d, "@"); ok {
			out = append(out, digest)
		}
	}
	return out, nil
}

func (c *Client) ImageExists(ctx context.Context, id string) (bool, error) {
	err := c.get(ctx, "/images/"+url.PathEscape(id)+"/json", nil)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}
