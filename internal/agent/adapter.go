// Package agent runs the AI Review: it finds the agent CLI, prepares the per-review home and the
// network table, proves the sandbox with the probe, and runs the CLI through its adapter (spec
// sections 8.2 and 8.3).
package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/klar-web-services/tripcoil/internal/problem"
	"github.com/klar-web-services/tripcoil/internal/review"
)

// Adapter builds one CLI's command line and reads its result.
type Adapter interface {
	// Args are the CLI's arguments for a review.
	Args(in Inputs) []string
	// Env are variables the sandbox sets for the CLI, such as turning off its self-update.
	Env() []string
	// Files are written into the per-review home before the CLI starts, by name.
	Files(in Inputs) map[string][]byte
	// Parse reads the review JSON from the CLI's output, or returns a *review.Failure.
	Parse(stdout, stderr []byte, exitCode int) ([]byte, error)
	// Version names the CLI and its version from its --version output, such as "claude 2.1.309".
	Version(out []byte) string
}

// Inputs are what every review passes to the adapter.
type Inputs struct {
	Prompt string
	Schema []byte
	Home   string
	Model  string
	Extra  []string
}

// For returns the adapter of review.agent.
func For(agent string) Adapter {
	switch agent {
	case "claude":
		return claude{}
	case "codex":
		return codex{}
	}
	return nil
}

// version reads "<name> <version>" from the first field of --version output that starts with a
// digit, or returns name alone.
func version(name string, out []byte) string {
	line, _, _ := bytes.Cut(out, []byte("\n"))
	for _, f := range strings.Fields(string(line)) {
		if f[0] >= '0' && f[0] <= '9' {
			return name + " " + f
		}
	}
	return name
}

// lastLine is the last non-empty line of a CLI's error output, shortened, for an error message.
func lastLine(b []byte) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	l := strings.TrimSpace(lines[len(lines)-1])
	if r := []rune(l); len(r) > 300 {
		l = string(r[:300]) + "…"
	}
	return l
}

func fail(code, format string, args ...any) error {
	return &review.Failure{Code: code, Message: fmt.Sprintf(format, args...)}
}

// claude is Claude Code in headless print mode, verified with 2.1.309: --json-schema puts the
// object in structured_output, and dontAsk denies every tool outside --allowedTools.
type claude struct{}

const claudeTools = "Read,Grep,Glob,Bash,WebSearch,WebFetch"

func (claude) Args(in Inputs) []string {
	a := []string{"-p", in.Prompt, "--output-format", "json", "--json-schema", string(in.Schema),
		"--tools", claudeTools, "--allowedTools", claudeTools, "--disallowedTools", "Write,Edit,NotebookEdit",
		"--permission-mode", "dontAsk", "--no-session-persistence", "--strict-mcp-config", "--setting-sources", ""}
	if in.Model != "" {
		a = append(a, "--model", in.Model)
	}
	return append(a, in.Extra...)
}

func (claude) Env() []string {
	return []string{"DISABLE_AUTOUPDATER=1", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1"}
}

func (claude) Files(Inputs) map[string][]byte { return nil }

func (claude) Version(out []byte) string { return version("claude", out) }

func (claude) Parse(stdout, stderr []byte, exitCode int) ([]byte, error) {
	var r struct {
		IsError          bool            `json:"is_error"`
		Subtype          string          `json:"subtype"`
		StopReason       string          `json:"stop_reason"`
		APIErrorStatus   *int            `json:"api_error_status"`
		Result           string          `json:"result"`
		StructuredOutput json.RawMessage `json:"structured_output"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(stdout), &r); err != nil {
		return nil, fail(problem.AgentFailed, "claude exited with %d and printed no result: %s", exitCode, lastLine(append(stderr, stdout...)))
	}
	switch {
	case r.IsError && (r.APIErrorStatus != nil && (*r.APIErrorStatus == 401 || *r.APIErrorStatus == 403) || strings.Contains(r.Result, "Not logged in")):
		return nil, fail(problem.AgentAuth, "claude has no working credentials: %s", lastLine([]byte(r.Result)))
	case r.StopReason == "refusal":
		return nil, fail(problem.AgentRefused, "the model refused the review: %s", lastLine([]byte(r.Result)))
	case r.IsError || exitCode != 0:
		return nil, fail(problem.AgentFailed, "claude failed (exit %d, %s): %s", exitCode, r.Subtype, lastLine([]byte(r.Result)))
	case len(r.StructuredOutput) == 0 || string(r.StructuredOutput) == "null":
		return nil, fail(problem.AgentOutputInvalid, "claude returned no structured output")
	}
	return r.StructuredOutput, nil
}

// codex is codex exec, verified with 0.154.0: the final message, which --output-schema shapes,
// is printed on stdout; progress and log lines go to stderr. exec reads CODEX_API_KEY. Its own
// sandbox lets it write to the home (--add-dir), for the entries file; the working directory, the
// run folder, stays read-only in the OS sandbox, which is the security boundary (spec section 8.2).
type codex struct{}

const codexSchema = "tripcoil-schema.json"

func (codex) Args(in Inputs) []string {
	a := []string{"--search", "exec", "--skip-git-repo-check", "--ephemeral", "--ignore-user-config", "--sandbox", "workspace-write",
		"--add-dir", in.Home, "--color", "never", "-c", "check_for_update_on_startup=false", "--output-schema", in.Home + "/" + codexSchema}
	if in.Model != "" {
		a = append(a, "-m", in.Model)
	}
	a = append(a, in.Extra...)
	return append(a, in.Prompt)
}

func (codex) Env() []string { return nil }

func (codex) Files(in Inputs) map[string][]byte { return map[string][]byte{codexSchema: in.Schema} }

func (codex) Version(out []byte) string { return version("codex", out) }

func (codex) Parse(stdout, stderr []byte, exitCode int) ([]byte, error) {
	if exitCode != 0 {
		if bytes.Contains(stderr, []byte("401 Unauthorized")) || bytes.Contains(stderr, []byte("Missing bearer")) {
			return nil, fail(problem.AgentAuth, "codex has no working credentials (codex exec reads CODEX_API_KEY): %s", lastLine(stderr))
		}
		return nil, fail(problem.AgentFailed, "codex failed (exit %d): %s", exitCode, lastLine(stderr))
	}
	out := bytes.TrimSpace(stdout)
	if len(out) == 0 {
		return nil, fail(problem.AgentOutputInvalid, "codex printed no final message")
	}
	return out, nil
}
