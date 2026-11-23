// Package waiting keeps, across runs, since when each action has had no fixed release and nothing
// left to do. Such an action waits instead of being a to-do; after audit.WaitingDays it comes back.
package waiting

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/run"
)

// File is the clock's file in the state folder.
const File = "waiting.json"

var key = regexp.MustCompile(`^w:[0-9a-f]{12}$`)

// State is since when each action waits, by audit.WaitingKey.
type State map[string]time.Time

// Read reads the clock. A missing file is an empty clock; a damaged one too, with an error to
// report.
func Read(stateDir string) (State, error) {
	data, err := os.ReadFile(filepath.Join(stateDir, File))
	if errors.Is(err, fs.ErrNotExist) {
		return State{}, nil
	}
	if err != nil {
		return State{}, err
	}
	var raw map[string]time.Time
	if err := json.Unmarshal(data, &raw); err != nil {
		return State{}, err
	}
	st := State{}
	for k, since := range raw {
		if key.MatchString(k) {
			st[k] = since
		}
	}
	return st, nil
}

func Write(stateDir string, st State) error {
	return run.WritePrivate(filepath.Join(stateDir, File), st)
}

// Mark gives each action that has waited its clock, before the review: the reviewer reads it, and
// an overdue action's steps say what to do instead of waiting. keep is until when Zosia's settings
// keep a key waiting; it counts for an overdue action only.
func Mark(aud *audit.Audit, st State, keep map[string]time.Time, now time.Time) {
	for i := range aud.Actions {
		a := &aud.Actions[i]
		k := audit.WaitingKey(*a)
		since, ok := st[k]
		if !ok {
			continue
		}
		w := &audit.Waiting{Key: k, Since: since.UTC(), Days: max(0, int(now.Sub(since)/(24*time.Hour)))}
		w.Overdue = w.Days >= audit.WaitingDays
		if until, ok := keep[k]; ok && w.Overdue && until.After(now) {
			u := until.UTC()
			w.Until = &u
		}
		a.Waiting = w
	}
}

// Overdue lists the keys of the actions whose waiting time has passed, sorted. It is part of the
// fingerprint: an action that becomes overdue is reviewed afresh, once.
func Overdue(aud *audit.Audit) []string {
	out := []string{}
	for _, a := range aud.Actions {
		if a.Waiting != nil && a.Waiting.Overdue {
			out = append(out, a.Waiting.Key)
		}
	}
	slices.Sort(out)
	return out
}

// Card is what a reviewed report says of one action: whether it waits, and whether no fixed
// release exists.
type Card struct {
	Key   string
	Waits bool
	NoFix bool
}

// Update moves the clock on after a reviewed run. A card that waits for the first time starts
// now. A clock goes when its card is gone or a fixed release exists; while no fix exists it stays,
// also when the card is a to-do again.
func Update(st State, cards []Card, now time.Time) {
	noFix := map[string]bool{}
	for _, c := range cards {
		if c.NoFix {
			noFix[c.Key] = true
		}
		if _, known := st[c.Key]; c.Waits && c.NoFix && !known {
			st[c.Key] = now.UTC()
		}
	}
	for k := range st {
		if !noFix[k] {
			delete(st, k)
		}
	}
}
