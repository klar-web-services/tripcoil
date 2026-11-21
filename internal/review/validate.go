package review

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/problem"
)

const MaxOutput = 16 << 20

var ErrInvalid = errors.New("the review does not match the schema")

type agentEntry struct {
	FindingID      string       `json:"findingId"`
	Verdict        string       `json:"verdict"`
	Exploitability *string      `json:"exploitability"`
	Priority       *string      `json:"priority"`
	Reasoning      string       `json:"reasoning"`
	Evidence       []string     `json:"evidence"`
	Fix            []string     `json:"fix"`
	Sources        []string     `json:"sources"`
	Corrections    []Correction `json:"corrections"`
	Item           *string      `json:"item"`
	Vulnerability  *string      `json:"vulnerability"`
}

var (
	topKeys        = []string{"summary", "findings", "coverageNotes", "actions"}
	entryKeys      = []string{"findingId", "verdict", "exploitability", "priority", "reasoning", "evidence", "fix", "sources", "corrections", "item", "vulnerability"}
	correctionKeys = []string{"field", "old", "new", "why"}
)

const MaxEntriesFile = 64 << 20

const maxBadLines = 10000

const (
	maxEntryLine = 64 << 10
	maxListItems = 100
	maxReasoning = 16 << 10
)

// maxAddedID bounds the ID of a finding the review added: it is the ID of its card.
const maxAddedID = 64

const EntriesFile = "entries.jsonl"

func Validate(data, entries []byte, aud *audit.Audit, inv *inventory.Inventory) (*Review, []problem.Problem, error) {
	if len(data) > MaxOutput {
		return nil, nil, fmt.Errorf("%w: it is larger than %d MiB", ErrInvalid, MaxOutput>>20)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := exactKeys("the review", top, topKeys); err != nil {
		return nil, nil, err
	}
	out := &Review{SchemaVersion: "1", Findings: []Entry{}, Actions: []ActionEntry{}}
	var rawEntries, rawActions []json.RawMessage
	if err := strict(top["summary"], &out.Summary); err != nil || string(top["summary"]) == "null" {
		return nil, nil, fmt.Errorf("%w: summary must be a string", ErrInvalid)
	}
	if err := strict(top["coverageNotes"], &out.CoverageNotes); err != nil || out.CoverageNotes == nil {
		return nil, nil, fmt.Errorf("%w: coverageNotes must be a list of strings", ErrInvalid)
	}
	if err := strict(top["findings"], &rawEntries); err != nil || rawEntries == nil {
		return nil, nil, fmt.Errorf("%w: findings must be a list", ErrInvalid)
	}
	if err := strict(top["actions"], &rawActions); err != nil || rawActions == nil {
		return nil, nil, fmt.Errorf("%w: actions must be a list", ErrInvalid)
	}
	var all []Entry
	for i, raw := range rawEntries {
		e, err := decodeEntry(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: findings[%d]: %v", ErrInvalid, i, err)
		}
		all = append(all, e)
	}
	// Only the first messages are kept: the agent controls the file, and each line could cost one.
	var dropped []string
	ndropped, bad, rest := 0, 0, ""
	drop := func(msg string) {
		if ndropped++; len(dropped) < 10 {
			dropped = append(dropped, msg)
		}
	}
	n := 0
	for line := range bytes.Lines(entries) {
		if n++; len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if bad == maxBadLines {
			rest = fmt.Sprintf(", and the rest of %s was ignored after %d lines that are not entries", EntriesFile, maxBadLines)
			break
		}
		var e Entry
		var err error
		if len(line) > maxEntryLine {
			err = fmt.Errorf("it is longer than %d KiB", maxEntryLine>>10)
		} else {
			e, err = decodeEntry(line)
		}
		if err != nil {
			bad++
			why := strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": ")
			drop(fmt.Sprintf("%s line %d (%s)", EntriesFile, n, shorten(why)))
			continue
		}
		all = append(all, e)
	}
	ids, items := findingIDs(aud), itemIDs(inv)
	seen := map[string]bool{}
	for _, e := range all {
		why := ""
		switch {
		case seen[e.FindingID]:
			why = "it addresses a finding twice"
		case e.Verdict == Added && !strings.HasPrefix(e.FindingID, "added:"):
			why = "an added finding's ID must start with added:"
		case e.Verdict == Added && len(e.FindingID) > maxAddedID:
			why = fmt.Sprintf("an added finding's ID is longer than %d bytes", maxAddedID)
		case e.Verdict != Added && !ids[e.FindingID]:
			why = "audit.json has no such finding"
		case e.Verdict == Added && !items[e.Item]:
			why = "inventory.json has no such item"
		default:
			why = e.broken()
		}
		if why != "" {
			drop(fmt.Sprintf("%s (%s)", shorten(e.FindingID), why))
			continue
		}
		seen[e.FindingID] = true
		out.Findings = append(out.Findings, e)
	}
	packages := actionPackages(aud)
	for _, e := range out.Findings {
		if e.Verdict == Added {
			packages[e.FindingID] = nil
		}
	}
	done := map[string]bool{}
	for i, raw := range rawActions {
		a, err := decodeAction(raw)
		if err != nil {
			drop(fmt.Sprintf("actions[%d] (%s)", i, shorten(strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": "))))
			continue
		}
		why := ""
		if _, ok := packages[a.Action]; !ok {
			why = "audit.json has no such action, and the review added no such finding"
		} else if done[a.Action] {
			why = "it addresses an action twice"
		} else {
			why = a.tidy(packages[a.Action])
		}
		if why != "" {
			drop(fmt.Sprintf("action %s (%s)", shorten(a.Action), why))
			continue
		}
		done[a.Action] = true
		out.Actions = append(out.Actions, a)
	}
	out.NotReviewed = notReviewed(aud, out.Findings)
	if len(ids) > 0 && len(out.NotReviewed) == len(ids) {
		return nil, nil, fmt.Errorf("%w: it addresses none of the %d findings in audit.json (%d entries dropped%s%s)", ErrInvalid, len(ids), ndropped, firstReasons(dropped), rest)
	}
	var warns []problem.Problem
	if ndropped > 0 {
		more := ""
		if ndropped > len(dropped) {
			more = fmt.Sprintf(" and %d more", ndropped-len(dropped))
		}
		warns = append(warns, problem.New(problem.Warning, problem.ReviewEntriesDropped, "review",
			"%d review entries were dropped: %s%s%s", ndropped, strings.Join(dropped, "; "), more, rest))
	}
	return out, warns, nil
}

func firstReasons(dropped []string) string {
	if len(dropped) == 0 {
		return ""
	}
	return ": " + strings.Join(dropped[:min(3, len(dropped))], "; ")
}

func shorten(id string) string {
	if len(id) > 80 {
		return strings.ToValidUTF8(id[:80], "") + "…"
	}
	return id
}

func decodeEntry(raw json.RawMessage) (Entry, error) {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return Entry{}, err
	}
	if err := exactKeys("an entry", keys, entryKeys); err != nil {
		return Entry{}, err
	}
	var corrections []json.RawMessage
	if err := json.Unmarshal(keys["corrections"], &corrections); err != nil {
		return Entry{}, fmt.Errorf("corrections: %v", err)
	}
	for _, c := range corrections {
		var ck map[string]json.RawMessage
		if err := json.Unmarshal(c, &ck); err != nil {
			return Entry{}, fmt.Errorf("corrections: %v", err)
		}
		if err := exactKeys("a correction", ck, correctionKeys); err != nil {
			return Entry{}, err
		}
	}
	var a agentEntry
	if err := strict(raw, &a); err != nil {
		return Entry{}, err
	}
	for name, list := range map[string][]string{"evidence": a.Evidence, "fix": a.Fix, "sources": a.Sources} {
		if list == nil {
			return Entry{}, fmt.Errorf("%s must be a list", name)
		}
	}
	if a.Corrections == nil {
		return Entry{}, errors.New("corrections must be a list")
	}
	switch {
	case !slices.Contains(verdicts, a.Verdict):
		return Entry{}, fmt.Errorf("verdict %q is not one of %s", a.Verdict, strings.Join(verdicts, ", "))
	case a.Exploitability != nil && !slices.Contains(exploitability, *a.Exploitability):
		return Entry{}, fmt.Errorf("exploitability %q is not one of %s", *a.Exploitability, strings.Join(exploitability, ", "))
	case a.Priority != nil && !slices.Contains(priorities, *a.Priority):
		return Entry{}, fmt.Errorf("priority %q is not one of %s", *a.Priority, strings.Join(priorities, ", "))
	}
	deref := func(s *string) string {
		if s == nil {
			return ""
		}
		return *s
	}
	return Entry{FindingID: a.FindingID, Verdict: a.Verdict, Exploitability: deref(a.Exploitability), Priority: deref(a.Priority),
		Reasoning: a.Reasoning, Evidence: a.Evidence, Fix: a.Fix, Sources: a.Sources, Corrections: a.Corrections,
		Item: deref(a.Item), Vulnerability: deref(a.Vulnerability)}, nil
}

func (e Entry) broken() string {
	switch {
	case strings.TrimSpace(e.Reasoning) == "":
		return "it has no reasoning"
	case len(e.Reasoning) > maxReasoning:
		return fmt.Sprintf("its reasoning is longer than %d KiB", maxReasoning>>10)
	case max(len(e.Evidence), len(e.Fix), len(e.Sources), len(e.Corrections)) > maxListItems:
		return fmt.Sprintf("its evidence, fix, sources or corrections have more than %d items", maxListItems)
	case e.Verdict != FalsePositive && (e.Exploitability == "" || e.Priority == ""):
		return "it needs exploitability and priority"
	case e.Verdict == Added && len(e.Fix) == 0:
		return "an added finding needs fix steps"
	case e.Verdict == Corrected && len(e.Corrections) == 0:
		return "a correction needs its corrections"
	case e.Verdict == Added && (e.Vulnerability == "" || len(e.Sources) == 0):
		return "an added finding needs its vulnerability and a source"
	}
	return ""
}

func exactKeys(what string, obj map[string]json.RawMessage, keys []string) error {
	for _, k := range keys {
		if _, ok := obj[k]; !ok {
			return fmt.Errorf("%w: %s lacks %q", ErrInvalid, what, k)
		}
	}
	for k := range obj {
		if !slices.Contains(keys, k) {
			return fmt.Errorf("%w: %s has the unknown key %q", ErrInvalid, what, k)
		}
	}
	return nil
}

func strict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
