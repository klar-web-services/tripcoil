// stubcli stands in for the agent CLIs in the sandbox tests. Installed as claude or codex, it
// answers --version, and otherwise tries a few things the sandbox must allow or stop, writes a
// marker into its home, and returns a review in the CLI's format that confirms every finding.
// /etc/tripcoil-stub selects another behaviour: "sleep" (run past the timeout) or "auth" (no
// credentials). Run as "stubcli listen <addr>" or "stubcli dns <listen> <upstream>", it is a TCP
// listener or a UDP DNS forwarder for the tests.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	switch {
	case len(os.Args) == 3 && os.Args[1] == "listen":
		listen(os.Args[2])
		return
	case len(os.Args) == 4 && os.Args[1] == "dns":
		forward(os.Args[2], os.Args[3])
		return
	}
	name := filepath.Base(os.Args[0])
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		if name == "codex" {
			fmt.Println("codex-cli 0.154.0")
		} else {
			fmt.Println("2.1.309 (Claude Code)")
		}
		return
	}
	mode, _ := os.ReadFile("/etc/tripcoil-stub")
	switch strings.TrimSpace(string(mode)) {
	case "sleep":
		time.Sleep(time.Hour)
	case "auth":
		if name == "codex" {
			fmt.Fprintln(os.Stderr, "ERROR: unexpected status 401 Unauthorized: Missing bearer or basic authentication in header")
		} else {
			fmt.Println(`{"type":"result","subtype":"success","is_error":true,"api_error_status":null,"result":"Not logged in · Please run /login"}`)
		}
		os.Exit(1)
	}
	out, _ := json.Marshal(review())
	if name == "codex" {
		fmt.Println(string(out))
		return
	}
	env, _ := json.Marshal(map[string]any{"type": "result", "subtype": "success", "is_error": false, "stop_reason": "end_turn",
		"result": string(out), "structured_output": json.RawMessage(out)})
	fmt.Println(string(env))
}

// review tries what the tests check and confirms every finding in audit.json.
func review() map[string]any {
	var checks []string
	err := os.WriteFile("/etc/tripcoil-stub-wrote", []byte("x"), 0o644)
	checks = append(checks, "write-etc="+errText(err))
	marker := filepath.Join(os.Getenv("HOME"), "marker")
	if _, err := os.Stat(marker); err == nil {
		checks = append(checks, "marker=present")
	} else {
		checks = append(checks, "marker=absent")
	}
	os.WriteFile(marker, []byte("x"), 0o600)
	_, err = net.LookupHost("deb.debian.org")
	checks = append(checks, "dns="+errText(err))
	checks = append(checks, "allowed="+dial("127.0.0.2:7777"), "blocked="+dial("127.0.0.1:7777"))
	es, _ := os.ReadDir("/proc")
	pids := 0
	for _, e := range es {
		if e.Name()[0] >= '0' && e.Name()[0] <= '9' {
			pids++
		}
	}
	checks = append(checks, fmt.Sprintf("pids=%d", pids))
	// A key in the user's keyring would outlive the review: it must be refused (systemd), or gone
	// by the next review (bubblewrap's user namespace, or the probe's clear).
	if _, err := unix.KeyctlSearch(unix.KEY_SPEC_USER_KEYRING, "user", "tripcoil-marker", 0); err == nil {
		checks = append(checks, "keyring=present")
	} else if _, err := unix.AddKey("user", "tripcoil-marker", []byte("x"), unix.KEY_SPEC_USER_KEYRING); err != nil {
		checks = append(checks, "keyring="+errText(err))
	} else {
		checks = append(checks, "keyring=absent")
	}

	var aud struct {
		Findings []struct {
			ID string `json:"id"`
		} `json:"findings"`
	}
	data, _ := os.ReadFile("audit.json")
	json.Unmarshal(data, &aud)
	findings := []map[string]any{}
	for _, f := range aud.Findings {
		findings = append(findings, map[string]any{"findingId": f.ID, "verdict": "confirmed", "exploitability": "unknown", "priority": "scheduled",
			"reasoning": "stub review", "evidence": []string{}, "fix": []string{"upgrade"}, "sources": []string{}, "corrections": []any{},
			"item": nil, "vulnerability": nil})
	}
	return map[string]any{"summary": strings.Join(checks, " "), "findings": findings, "coverageNotes": []string{}}
}

func dial(addr string) string {
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return errText(err)
	}
	c.Close()
	return "connected"
}

func errText(err error) string {
	if err == nil {
		return "ok"
	}
	var en syscall.Errno
	if errors.As(err, &en) {
		return strings.ReplaceAll(en.Error(), " ", "-")
	}
	return "error"
}

func listen(addr string) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		c.Close()
	}
}

// forward relays DNS queries over UDP to upstream, one at a time.
func forward(addr, upstream string) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		up, err := net.Dial("udp", upstream)
		if err != nil {
			continue
		}
		up.SetDeadline(time.Now().Add(5 * time.Second))
		up.Write(buf[:n])
		resp := make([]byte, 65535)
		if m, err := up.Read(resp); err == nil {
			pc.WriteTo(resp[:m], from)
		}
		up.Close()
	}
}
