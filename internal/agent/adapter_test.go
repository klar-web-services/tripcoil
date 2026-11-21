package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/problem"
	"github.com/klar-web-services/tripcoil/internal/review"
)

func fixture(t *testing.T, path string) []byte {
	data, err := os.ReadFile(filepath.Join("../../testdata", path))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func code(err error) string {
	var f *review.Failure
	if errors.As(err, &f) {
		return f.Code
	}
	return ""
}

func TestClaudeArgs(t *testing.T) {
	in := Inputs{Prompt: "PROMPT", Schema: []byte(`{"type":"object"}`), Home: "/var/lib/tripcoil/agent-home", Model: "opus", Extra: []string{"--max-turns", "200"}}
	want := []string{"-p", "PROMPT", "--output-format", "json", "--json-schema", `{"type":"object"}`,
		"--tools", "Read,Grep,Glob,Bash,WebSearch,WebFetch", "--allowedTools", "Read,Grep,Glob,Bash,WebSearch,WebFetch",
		"--disallowedTools", "Write,Edit,NotebookEdit", "--permission-mode", "dontAsk", "--no-session-persistence",
		"--strict-mcp-config", "--setting-sources", "", "--model", "opus", "--max-turns", "200"}
	a := For("claude")
	if got := a.Args(in); !slices.Equal(got, want) {
		t.Fatalf("got %q", got)
	}
	if !slices.Equal(a.Env(), []string{"DISABLE_AUTOUPDATER=1", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1"}) || a.Files(in) != nil {
		t.Errorf("env %q files %v", a.Env(), a.Files(in))
	}
	in.Model, in.Extra = "", nil
	if got := a.Args(in); got[len(got)-1] != "" || slices.Contains(got, "--model") {
		t.Errorf("without a model: %q", got)
	}
}

func TestCodexArgs(t *testing.T) {
	in := Inputs{Prompt: "PROMPT", Schema: []byte(`{"type":"object"}`), Home: "/var/lib/tripcoil/agent-home", Model: "gpt-5", Extra: []string{"-c", "model_reasoning_effort=\"high\""}}
	want := []string{"--search", "exec", "--skip-git-repo-check", "--ephemeral", "--ignore-user-config", "--sandbox", "workspace-write",
		"--add-dir", "/var/lib/tripcoil/agent-home", "--color", "never", "-c", "check_for_update_on_startup=false", "--output-schema", "/var/lib/tripcoil/agent-home/tripcoil-schema.json",
		"-m", "gpt-5", "-c", "model_reasoning_effort=\"high\"", "PROMPT"}
	a := For("codex")
	if got := a.Args(in); !slices.Equal(got, want) {
		t.Fatalf("got %q", got)
	}
	if files := a.Files(in); len(files) != 1 || string(files["tripcoil-schema.json"]) != `{"type":"object"}` || a.Env() != nil {
		t.Errorf("files %v env %v", files, a.Env())
	}
	if For("none") != nil {
		t.Error("an adapter for none")
	}
}

func TestVersion(t *testing.T) {
	if v := For("claude").Version([]byte("2.1.309 (Claude Code)\n")); v != "claude 2.1.309" {
		t.Errorf("claude: %q", v)
	}
	if v := For("codex").Version([]byte("codex-cli 0.154.0\n")); v != "codex 0.154.0" {
		t.Errorf("codex: %q", v)
	}
	if v := For("codex").Version(nil); v != "codex" {
		t.Errorf("no output: %q", v)
	}
}

func TestClaudeParse(t *testing.T) {
	a := For("claude")
	data, err := a.Parse(fixture(t, "agent/claude-success.json"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := review.Validate(data, nil, nil, nil); err != nil {
		t.Errorf("the structured output does not validate: %v", err)
	}
	var r map[string]any
	if json.Unmarshal(data, &r) != nil || !strings.HasPrefix(r["summary"].(string), "audit.json holds") {
		t.Errorf("got %s", data)
	}
	cases := []struct {
		name, stdout string
		exit         int
		code, msg    string
	}{
		{"not logged in", string(fixture(t, "agent/claude-noauth.json")), 1, problem.AgentAuth, "Not logged in · Please run /login"},
		{"invalid key", string(fixture(t, "agent/claude-badkey.json")), 1, problem.AgentAuth, "Invalid API key · Fix external API key"},
		{"max turns", `{"type":"result","subtype":"error_max_turns","is_error":true,"result":""}`, 1, problem.AgentFailed, "error_max_turns"},
		{"refusal", `{"type":"result","subtype":"success","is_error":false,"stop_reason":"refusal","result":"I can't help with that."}`, 0, problem.AgentRefused, "I can't help"},
		{"no structured output", `{"type":"result","subtype":"success","is_error":false,"result":"done"}`, 0, problem.AgentOutputInvalid, "no structured output"},
		{"no JSON", "", 1, problem.AgentFailed, "printed no result: Error: unknown option"},
	}
	for _, tc := range cases {
		_, err := a.Parse([]byte(tc.stdout), []byte("Error: unknown option\n"), tc.exit)
		if code(err) != tc.code || !strings.Contains(err.Error(), tc.msg) {
			t.Errorf("%s: %s %v", tc.name, code(err), err)
		}
	}
}

func TestCodexParse(t *testing.T) {
	a := For("codex")
	final := fixture(t, "review/codex-0.154.0.json")
	data, err := a.Parse(append(final, '\n'), []byte("OpenAI Codex v0.154.0\n"), 0)
	if err != nil || string(data) != strings.TrimSpace(string(final)) {
		t.Fatalf("%v %s", err, data)
	}
	_, err = a.Parse(nil, fixture(t, "agent/codex-noauth.stderr"), 1)
	if code(err) != problem.AgentAuth || !strings.Contains(err.Error(), "CODEX_API_KEY") || !strings.Contains(err.Error(), "401 Unauthorized") {
		t.Errorf("no credentials: %v", err)
	}
	if _, err := a.Parse(nil, []byte("ERROR: stream disconnected\n"), 1); code(err) != problem.AgentFailed || !strings.Contains(err.Error(), "stream disconnected") {
		t.Errorf("failure: %v", err)
	}
	if _, err := a.Parse([]byte("\n"), nil, 0); code(err) != problem.AgentOutputInvalid {
		t.Errorf("no message: %v", err)
	}
}

func TestLastLine(t *testing.T) {
	if l := lastLine([]byte("a\nb  \n\n")); l != "b" {
		t.Errorf("got %q", l)
	}
	if l := lastLine([]byte(strings.Repeat("é", 400))); len([]rune(l)) != 301 {
		t.Errorf("not shortened: %d", len([]rune(l)))
	}
}
