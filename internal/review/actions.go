package review

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/klar-web-services/tripcoil/internal/audit"
)

// MaxCardChanges is how many changes the reviewer names on one action.
const MaxCardChanges = 6

const (
	UpstreamAvailable = "available"
	UpstreamNone      = "none"
	UpstreamUnknown   = "unknown"
)

// ActionEntry is what the reviewer writes for one action of audit.json, or for a finding it
// added: the heading, what changes, and how to do it on this machine.
type ActionEntry struct {
	Action   string         `json:"action"`
	Title    string         `json:"title"`
	Changes  []ActionChange `json:"changes"`
	Also     []string       `json:"also"`
	Steps    []audit.Step   `json:"steps"`
	Upstream Upstream       `json:"upstream"`
	Why      string         `json:"why"`
}

type ActionChange struct {
	Name string `json:"name"`
	From string `json:"from"`
	To   string `json:"to,omitempty"`
	// Needs is set on a report's card only, for an image: the version that fixes the package, where
	// the update does not bring it or what it brings was not checked. To is then what the update
	// brings, or empty.
	Needs string `json:"needs,omitempty"`
}

type Upstream struct {
	State  string `json:"state"`
	Note   string `json:"note,omitempty"`
	Source string `json:"source,omitempty"`
}

var (
	actionKeys   = []string{"action", "title", "changes", "also", "steps", "upstream", "why"}
	changeKeys   = []string{"name", "from", "to"}
	stepKeys     = []string{"text", "command"}
	upstreamKeys = []string{"state", "note", "source"}
)

type agentAction struct {
	Action  string `json:"action"`
	Title   string `json:"title"`
	Changes []struct {
		Name string  `json:"name"`
		From string  `json:"from"`
		To   *string `json:"to"`
	} `json:"changes"`
	Also  []string `json:"also"`
	Steps []struct {
		Text    string  `json:"text"`
		Command *string `json:"command"`
	} `json:"steps"`
	Upstream struct {
		State  string  `json:"state"`
		Note   string  `json:"note"`
		Source *string `json:"source"`
	} `json:"upstream"`
	Why string `json:"why"`
}

func keysOf(what string, raw json.RawMessage, keys []string) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return fmt.Errorf("%s: %v", what, err)
	}
	return exactKeys(what, obj, keys)
}

// decodeAction reads one action entry as the schema defines it. Its texts are not yet cut.
func decodeAction(raw json.RawMessage) (ActionEntry, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return ActionEntry{}, err
	}
	if err := exactKeys("an action", top, actionKeys); err != nil {
		return ActionEntry{}, err
	}
	if err := keysOf("upstream", top["upstream"], upstreamKeys); err != nil {
		return ActionEntry{}, err
	}
	for name, keys := range map[string][]string{"changes": changeKeys, "steps": stepKeys} {
		var list []json.RawMessage
		if err := json.Unmarshal(top[name], &list); err != nil || list == nil {
			return ActionEntry{}, fmt.Errorf("%s must be a list", name)
		}
		for _, item := range list {
			if err := keysOf("one of its "+name, item, keys); err != nil {
				return ActionEntry{}, err
			}
		}
	}
	var a agentAction
	if err := strict(raw, &a); err != nil {
		return ActionEntry{}, err
	}
	if a.Also == nil {
		return ActionEntry{}, errors.New("also must be a list")
	}
	deref := func(s *string) string {
		if s == nil {
			return ""
		}
		return *s
	}
	out := ActionEntry{Action: a.Action, Title: a.Title, Changes: []ActionChange{}, Also: a.Also, Steps: []audit.Step{},
		Upstream: Upstream{State: a.Upstream.State, Note: a.Upstream.Note, Source: deref(a.Upstream.Source)}, Why: a.Why}
	for _, c := range a.Changes {
		out.Changes = append(out.Changes, ActionChange{Name: c.Name, From: c.From, To: deref(c.To)})
	}
	for _, s := range a.Steps {
		out.Steps = append(out.Steps, audit.Step{Text: s.Text, Command: deref(s.Command)})
	}
	return out, nil
}

// unprintable reports a control or format character: a line break, an escape, a zero-width or
// bidirectional mark. None belongs in a text that is shown, least of all in a command.
func unprintable(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }

func hasUnprintable(s string) bool { return strings.ContainsFunc(s, unprintable) }

// oneLine makes a text safe to show on one line and cuts it to n bytes.
func oneLine(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if unprintable(r) {
			return ' '
		}
		return r
	}, s)
	return audit.Cut(strings.Join(strings.Fields(s), " "), n)
}

// tidy applies the limits to an entry: changes that match no finding of the action or repeat one go, lists
// are cut to their lengths, texts to their limits, and a command or a source that cannot be
// shown safely is removed. It says why when nothing usable is left.
func (e *ActionEntry) tidy(packages map[string]bool) string {
	if e.Title = oneLine(e.Title, audit.MaxTitle); e.Title == "" {
		return "it has no title"
	}
	named := map[string]bool{}
	e.Changes = slices.DeleteFunc(e.Changes, func(c ActionChange) bool {
		key := c.Name + "\x00" + c.From
		again := named[key]
		named[key] = true
		return again || !packages[key]
	})
	e.Changes = e.Changes[:min(len(e.Changes), MaxCardChanges)]
	for i, c := range e.Changes {
		e.Changes[i] = ActionChange{Name: audit.Cut(c.Name, audit.MaxChangeName), From: audit.Cut(c.From, audit.MaxVersion), To: oneLine(c.To, audit.MaxVersion)}
	}
	also := []string{}
	for _, s := range e.Also {
		if s = oneLine(s, audit.MaxAlso); s != "" && len(also) < audit.MaxAlsoLines {
			also = append(also, s)
		}
	}
	e.Also = also
	steps := []audit.Step{}
	for _, s := range e.Steps {
		s.Text = oneLine(s.Text, audit.MaxStepText)
		if s.Command = strings.TrimSpace(s.Command); len(s.Command) > audit.MaxCommand || hasUnprintable(s.Command) {
			s.Command = ""
		}
		if s.Text != "" && len(steps) < audit.MaxSteps {
			steps = append(steps, s)
		}
	}
	if e.Steps = steps; len(steps) == 0 {
		return "it has no steps"
	}
	if !slices.Contains([]string{UpstreamAvailable, UpstreamNone, UpstreamUnknown}, e.Upstream.State) {
		e.Upstream.State = UpstreamUnknown
	}
	e.Upstream.Note = oneLine(e.Upstream.Note, audit.MaxNote)
	if s := e.Upstream.Source; !strings.HasPrefix(s, "https://") || len(s) > audit.MaxSource || hasUnprintable(s) || strings.Contains(s, " ") {
		e.Upstream.Source = ""
	}
	e.Why = oneLine(e.Why, audit.MaxWhy)
	return ""
}

// actionPackages maps each action of the audit to the packages its findings name, as
// name NUL version.
func actionPackages(aud *audit.Audit) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	if aud == nil {
		return out
	}
	for _, a := range aud.Actions {
		out[a.ID] = map[string]bool{}
	}
	for _, f := range aud.Findings {
		if m := out[f.Action]; m != nil {
			m[f.Package.Name+"\x00"+f.Package.Version] = true
		}
	}
	return out
}
