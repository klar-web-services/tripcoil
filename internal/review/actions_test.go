package review

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/inventory"
)

func actionsAudit() (*audit.Audit, *inventory.Inventory) {
	aud, inv := fixtureAudit()
	aud.Actions = []audit.Action{{ID: "a:111111111111", Kind: audit.ActionImage}, {ID: "a:222222222222", Kind: audit.ActionPackages}}
	aud.Findings[0].Action, aud.Findings[0].Package = "a:111111111111", audit.Package{Name: "chromium", Version: "148.0"}
	aud.Findings[1].Action, aud.Findings[1].Package = "a:111111111111", audit.Package{Name: "libbrotli1", Version: "1.0.9"}
	aud.Findings[2].Action, aud.Findings[2].Package = "a:222222222222", audit.Package{Name: "openssl", Version: "3.5.1"}
	return aud, inv
}

func action(over map[string]any) map[string]any {
	a := map[string]any{"action": "a:111111111111", "title": "Update the flaresolverr image",
		"changes":  []any{map[string]any{"name": "chromium", "from": "148.0", "to": "153.0"}},
		"also":     []string{"Bind port 8891 to 127.0.0.1"},
		"steps":    []any{map[string]any{"text": "Pull the image", "command": "docker compose -p servarr pull flaresolverr"}, map[string]any{"text": "Check the log", "command": nil}},
		"upstream": map[string]any{"state": "available", "note": "v3.6.1 ships Chromium 153", "source": "https://github.com/FlareSolverr/FlareSolverr/releases"},
		"why":      "An unauthenticated API drives this Chromium to any URL."}
	for k, v := range over {
		if v == "DELETE" {
			delete(a, k)
		} else {
			a[k] = v
		}
	}
	return a
}

func withActions(actions ...map[string]any) []byte {
	data, _ := json.Marshal(map[string]any{"summary": "s", "findings": []any{entry(nil)}, "coverageNotes": []string{}, "reach": []any{}, "actions": actions})
	return data
}

func TestValidateActions(t *testing.T) {
	aud, inv := actionsAudit()
	r, warns, err := Validate(withActions(action(nil)), nil, aud, inv)
	if err != nil || len(warns) != 0 {
		t.Fatalf("%v %+v", err, warns)
	}
	want := []ActionEntry{{Action: "a:111111111111", Title: "Update the flaresolverr image",
		Changes:  []ActionChange{{Name: "chromium", From: "148.0", To: "153.0"}},
		Also:     []string{"Bind port 8891 to 127.0.0.1"},
		Steps:    []audit.Step{{Text: "Pull the image", Command: "docker compose -p servarr pull flaresolverr"}, {Text: "Check the log"}},
		Upstream: Upstream{State: "available", Note: "v3.6.1 ships Chromium 153", Source: "https://github.com/FlareSolverr/FlareSolverr/releases"},
		Why:      "An unauthenticated API drives this Chromium to any URL."}}
	if !reflect.DeepEqual(r.Actions, want) {
		t.Errorf("actions:\n got %+v\nwant %+v", r.Actions, want)
	}
}

func TestValidateDropsActions(t *testing.T) {
	aud, inv := actionsAudit()
	data := withActions(
		action(nil),
		action(map[string]any{"title": "again"}),
		action(map[string]any{"action": "a:999999999999"}),
		action(map[string]any{"action": "added:7"}),
		action(map[string]any{"action": "a:222222222222", "steps": []any{}}),
		action(map[string]any{"action": "a:222222222222", "title": " \n "}),
		action(map[string]any{"action": "a:222222222222", "steps": "upgrade"}),
		action(map[string]any{"action": "a:222222222222", "why": "DELETE"}),
		action(map[string]any{"action": "a:222222222222", "upstream": map[string]any{"state": "available", "note": "n"}}),
	)
	r, warns, err := Validate(data, nil, aud, inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Actions) != 1 || r.Actions[0].Title != "Update the flaresolverr image" {
		t.Errorf("kept %+v", r.Actions)
	}
	if len(warns) != 1 || !strings.HasPrefix(warns[0].Message, "8 review entries were dropped") {
		t.Fatalf("warnings %+v", warns)
	}
	for _, want := range []string{"it addresses an action twice", "action a:999999999999 (audit.json has no such action", "action added:7 (", "it has no steps", "it has no title",
		"actions[6] (", `actions[7] (an action lacks "why")`, `actions[8] (upstream lacks "source")`} {
		if !strings.Contains(warns[0].Message, want) {
			t.Errorf("the warning lacks %q: %s", want, warns[0].Message)
		}
	}
}

func TestValidateTidiesActions(t *testing.T) {
	aud, inv := actionsAudit()
	long := strings.Repeat("ä", 400)
	// Eight more packages in the action: more than a card names.
	for i := range 8 {
		aud.Findings = append(aud.Findings, audit.Finding{ID: fmt.Sprintf("f:00000000000001%02d", i), Action: "a:111111111111", Package: audit.Package{Name: fmt.Sprintf("pkg%d", i), Version: "1.0"}})
	}
	// A version the action does not have, a package of another action, eight real ones, one of them twice.
	changes := []any{map[string]any{"name": "chromium", "from": "147.0", "to": "153.0"}, map[string]any{"name": "openssl", "from": "3.5.1", "to": "3.5.5"}}
	for i := range 8 {
		changes = append(changes, map[string]any{"name": fmt.Sprintf("pkg%d", i), "from": "1.0", "to": nil})
	}
	changes = append(changes[:3:3], append([]any{map[string]any{"name": "pkg0", "from": "1.0", "to": "2.0"}}, changes[3:]...)...)
	var steps []any
	steps = append(steps,
		map[string]any{"text": long, "command": "echo one\necho two"},
		map[string]any{"text": "tab", "command": "echo\tone"},
		map[string]any{"text": "a right-to-left override", "command": "rm -rf /tmp/x\u202e"},
		map[string]any{"text": "long", "command": strings.Repeat("x", audit.MaxCommand+1)},
		map[string]any{"text": "  ", "command": "true"},
		map[string]any{"text": "two\nlines", "command": "  systemctl restart nginx  "})
	for range 20 {
		steps = append(steps, map[string]any{"text": "more", "command": nil})
	}
	r, warns, err := Validate(withActions(action(map[string]any{"title": long, "changes": changes, "also": []string{long, "", "b", "c", "d", "e"}, "steps": steps,
		"upstream": map[string]any{"state": "soon", "note": long, "source": "http://example.com/x"}, "why": long})), nil, aud, inv)
	if err != nil || len(warns) != 0 {
		t.Fatalf("%v %+v", err, warns)
	}
	a := r.Actions[0]
	if len(a.Title) > audit.MaxTitle || !strings.HasSuffix(a.Title, "…") || len(a.Why) > audit.MaxWhy || len(a.Upstream.Note) > audit.MaxNote {
		t.Errorf("texts are not cut: %d %d %d", len(a.Title), len(a.Why), len(a.Upstream.Note))
	}
	// Only changes that name a package and version of one of the action's findings stay, each once.
	if len(a.Changes) != MaxCardChanges || a.Changes[0] != (ActionChange{Name: "pkg0", From: "1.0"}) || a.Changes[1] != (ActionChange{Name: "pkg1", From: "1.0"}) {
		t.Errorf("changes %+v", a.Changes)
	}
	if len(a.Also) != audit.MaxAlsoLines || len(a.Also[0]) > audit.MaxAlso || a.Also[1] != "b" {
		t.Errorf("also %q", a.Also)
	}
	if len(a.Steps) != audit.MaxSteps || len(a.Steps[0].Text) > audit.MaxStepText {
		t.Errorf("%d steps", len(a.Steps))
	}
	for i, wantCommand := range []string{"", "", "", "", "systemctl restart nginx"} {
		if a.Steps[i].Command != wantCommand {
			t.Errorf("step %d has the command %q, want %q", i, a.Steps[i].Command, wantCommand)
		}
	}
	if a.Steps[4].Text != "two lines" {
		t.Errorf("step text %q", a.Steps[3].Text)
	}
	if a.Upstream.State != UpstreamUnknown || a.Upstream.Source != "" {
		t.Errorf("upstream %+v", a.Upstream)
	}
}

func TestValidateActionForAnAddedFinding(t *testing.T) {
	aud, inv := actionsAudit()
	added := entry(map[string]any{"findingId": "added:1", "verdict": "added", "item": "proc:aaaa", "vulnerability": "CVE-2026-1", "sources": []string{"https://x"}})
	data, _ := json.Marshal(map[string]any{"summary": "s", "findings": []any{entry(nil), added}, "coverageNotes": []string{}, "reach": []any{},
		"actions": []any{action(map[string]any{"action": "added:1"})}})
	r, warns, err := Validate(data, nil, aud, inv)
	if err != nil || len(warns) != 0 || len(r.Actions) != 1 {
		t.Fatalf("%v %+v %+v", err, warns, r)
	}
	if len(r.Actions[0].Changes) != 0 {
		t.Errorf("an added finding has no package to change: %+v", r.Actions[0].Changes)
	}
}

func TestValidateAddedIDIsShort(t *testing.T) {
	aud, inv := actionsAudit()
	long := entry(map[string]any{"findingId": "added:" + strings.Repeat("x", 60), "verdict": "added", "item": "proc:aaaa", "vulnerability": "CVE-2026-1", "sources": []string{"https://x"}})
	data, _ := json.Marshal(map[string]any{"summary": "s", "findings": []any{entry(nil), long}, "coverageNotes": []string{}, "reach": []any{}, "actions": []any{}})
	r, warns, err := Validate(data, nil, aud, inv)
	if err != nil || len(r.Findings) != 1 || len(warns) != 1 || !strings.Contains(warns[0].Message, "an added finding's ID is longer than 64 bytes") {
		t.Errorf("%v %+v %+v", err, r, warns)
	}
}

func TestValidateFixIsOptional(t *testing.T) {
	aud, inv := actionsAudit()
	added := entry(map[string]any{"findingId": "added:1", "verdict": "added", "item": "proc:aaaa", "vulnerability": "CVE-2026-1", "sources": []string{"https://x"}, "fix": []string{}})
	data, _ := json.Marshal(map[string]any{"summary": "s", "findings": []any{entry(map[string]any{"fix": []string{}}), added}, "coverageNotes": []string{}, "reach": []any{}, "actions": []any{}})
	r, warns, err := Validate(data, nil, aud, inv)
	if err != nil || len(r.Findings) != 1 || r.Findings[0].FindingID != "f:0000000000000001" {
		t.Fatalf("%v %+v", err, r)
	}
	if len(warns) != 1 || !strings.Contains(warns[0].Message, "added:1 (an added finding needs fix steps)") {
		t.Errorf("warnings %+v", warns)
	}
}

func TestCarryActions(t *testing.T) {
	aud, inv := actionsAudit()
	prev := &Review{Summary: "s", Findings: []Entry{{FindingID: "f:0000000000000001", Verdict: Confirmed},
		{FindingID: "added:1", Verdict: Added, Item: "proc:aaaa"}, {FindingID: "added:2", Verdict: Added, Item: "proc:gone"}},
		Actions: []ActionEntry{{Action: "a:111111111111", Title: "kept"}, {Action: "a:333333333333", Title: "its action is gone"},
			{Action: "added:1", Title: "kept too"}, {Action: "added:2", Title: "its finding is gone"}}}
	r := Carry(prev, aud, inv)
	var got []string
	for _, a := range r.Actions {
		got = append(got, a.Title)
	}
	if !reflect.DeepEqual(got, []string{"kept", "kept too"}) {
		t.Errorf("carried %v", got)
	}
	if r := Carry(&Review{}, aud, inv); r.Actions == nil {
		t.Error("a review from before prompt 4 carries a null list")
	}
}

func TestSchemaActions(t *testing.T) {
	var s map[string]any
	if err := json.Unmarshal(Schema, &s); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s["required"], []any{"summary", "findings", "coverageNotes", "actions", "reach"}) {
		t.Errorf("required %v", s["required"])
	}
	check := func(what string, obj any, keys []string) {
		t.Helper()
		o := obj.(map[string]any)
		req := []string{}
		for _, k := range o["required"].([]any) {
			req = append(req, k.(string))
		}
		if !reflect.DeepEqual(req, keys) || o["additionalProperties"] != false || len(o["properties"].(map[string]any)) != len(keys) {
			t.Errorf("%s: the schema and the validation disagree: %v", what, req)
		}
	}
	item := s["properties"].(map[string]any)["actions"].(map[string]any)["items"]
	check("an action", item, actionKeys)
	props := item.(map[string]any)["properties"].(map[string]any)
	check("a change", props["changes"].(map[string]any)["items"], changeKeys)
	check("a step", props["steps"].(map[string]any)["items"], stepKeys)
	check("upstream", props["upstream"], upstreamKeys)
	// Strict structured outputs know no length limits.
	if strings.Contains(string(Schema), "maxLength") || strings.Contains(string(Schema), "maxItems") {
		t.Error("the schema has a limit that strict structured outputs refuse")
	}
}

func TestPromptNamesTheActionLimits(t *testing.T) {
	if MaxCardChanges != 6 || audit.MaxAlsoLines != 4 || audit.MaxSteps != 12 {
		t.Fatal("the limits changed: change the prompt's words with them")
	}
	for _, want := range []string{"six at most", "four at most", "twelve at most", "Never write a version in `to` that you did not see published", "at most three sentences",
		"Give the command for everything a person can type", "A step does one thing", "names the file and what to change"} {
		if !strings.Contains(Prompt, want) {
			t.Errorf("the prompt lacks %q", want)
		}
	}
}
