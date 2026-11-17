package run

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// State is state.json (spec section 13): the last finished run, the last reviewed run and how
// many finished runs in a row were not complete. The daemon schedules from it and status shows it.
type State struct {
	LastRun             string    `json:"lastRun,omitempty"`
	LastRunAt           time.Time `json:"lastRunAt,omitzero"` // the run's start
	LastStatus          string    `json:"lastStatus,omitempty"`
	LastReviewed        string    `json:"lastReviewed,omitempty"`
	LastReviewedAt      time.Time `json:"lastReviewedAt,omitzero"`
	ConsecutiveFailures int       `json:"consecutiveFailures"`
}

func statePath(stateDir string) string { return filepath.Join(stateDir, "state.json") }

// ReadState reads state.json; a missing file is the empty state.
func ReadState(stateDir string) (State, error) {
	var s State
	data, err := os.ReadFile(statePath(stateDir))
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(data, &s)
	return s, err
}

// WriteState writes state.json, root's alone (0600), atomically.
func WriteState(stateDir string, s State) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(statePath(stateDir), append(data, '\n'), 0o600, false)
}

// Record counts a run. An interrupted run did not finish (the daemon was stopped, or Ctrl-C), so
// it changes nothing: the next scheduled run is still due, and it is no failure of the host.
func (s *State) Record(r *Record) {
	if r.Status == Interrupted {
		return
	}
	s.LastRun, s.LastRunAt, s.LastStatus = r.RunID, r.StartedAt, r.Status
	if r.Status == Complete {
		s.ConsecutiveFailures = 0
	} else {
		s.ConsecutiveFailures++
	}
	if r.Reviewed { // also a failed run can carry a review of its own
		s.LastReviewed, s.LastReviewedAt = r.RunID, r.ReviewedAt
	}
}
