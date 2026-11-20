package zosia

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// HostInfo is what the approval page shows of the machine that asks.
type HostInfo struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Version  string `json:"tripcoilVersion"`
}

// ConnectRequest is a started request to connect this machine: the person opens the URI and
// approves the user code; the device code collects the secret.
type ConnectRequest struct {
	DeviceCode              string `json:"deviceCode"`
	UserCode                string `json:"userCode"`
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	ExpiresIn               int    `json:"expiresIn"`
	Interval                int    `json:"interval"`
}

// connectUnit is the unit of the server's intervals; tests shorten it.
var connectUnit = time.Second

// StartConnect asks Zosia for a request to connect this machine.
func StartConnect(ctx context.Context, hc *http.Client, url, agent string, host HostInfo) (ConnectRequest, error) {
	status, header, data, err := postJSON(ctx, hc, url, "/api/v1/connect", agent, host)
	if err != nil {
		return ConnectRequest{}, err
	}
	var r ConnectRequest
	if status != http.StatusCreated {
		return r, answerError(status, header, data)
	}
	if err := json.Unmarshal(data, &r); err != nil || r.DeviceCode == "" || r.UserCode == "" || r.Interval < 1 || r.ExpiresIn < 1 {
		return ConnectRequest{}, &Error{Code: "BAD_RESPONSE", Message: "Zosia answered with something that is not a connect request"}
	}
	return r, nil
}

// WaitConnect polls until the request is approved and returns the secret and its name in Zosia.
// A denial, an expiry and a cancelled context end it with an Error of that code.
func WaitConnect(ctx context.Context, hc *http.Client, url, agent string, r ConnectRequest) (secret, name string, err error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(r.ExpiresIn)*connectUnit)
	defer cancel()
	wait := time.Duration(r.Interval) * connectUnit
	last := &Error{Code: "EXPIRED", Message: "nobody approved the request in time"}
	for {
		select {
		case <-ctx.Done():
			if ctx.Err() == context.Canceled {
				return "", "", &Error{Code: "CANCELLED", Message: "cancelled"}
			}
			return "", "", last
		case <-time.After(wait):
		}
		wait = time.Duration(r.Interval) * connectUnit
		status, header, data, err := postJSON(ctx, hc, url, "/api/v1/connect/token", agent, map[string]string{"deviceCode": r.DeviceCode})
		if err != nil {
			if ctx.Err() == nil {
				last = err
			}
			continue
		}
		switch {
		case status == http.StatusOK:
			var res struct{ Secret, Name string }
			if err := json.Unmarshal(data, &res); err != nil || res.Secret == "" {
				return "", "", &Error{Code: "BAD_RESPONSE", Message: "Zosia answered with something that is not a secret"}
			}
			return res.Secret, res.Name, nil
		case status == http.StatusAccepted:
		case status == http.StatusTooManyRequests || status >= 500:
			e := answerError(status, header, data)
			if e.after > 0 {
				wait = e.after
			}
		default:
			return "", "", answerError(status, header, data)
		}
	}
}

func postJSON(ctx context.Context, hc *http.Client, url, path, agent string, body any) (int, http.Header, []byte, *Error) {
	data, err := json.Marshal(body)
	if err != nil {
		return 0, nil, nil, &Error{Code: "PAYLOAD", Message: err.Error()}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(url, "/")+path, bytes.NewReader(data))
	if err != nil {
		return 0, nil, nil, &Error{Code: "NETWORK", Message: "invalid Zosia URL: " + err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", agent)
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, nil, &Error{Code: "NETWORK", Message: "cannot reach Zosia: " + unwrapped(err)}
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, resp.Header, answer, nil
}

// answerError reads Zosia's {code, message} body as send.go's post does.
func answerError(status int, header http.Header, data []byte) *Error {
	var e struct{ Code, Message string }
	_ = json.Unmarshal(data, &e)
	if e.Code == "" {
		e.Code = "HTTP_" + strconv.Itoa(status)
	}
	if e.Message == "" {
		e.Message = fmt.Sprintf("Zosia answered %d %s", status, http.StatusText(status))
	}
	out := &Error{Code: e.Code, Message: e.Message}
	if s, err := strconv.Atoi(header.Get("Retry-After")); err == nil && s > 0 {
		out.after = time.Duration(s) * connectUnit
	}
	return out
}
