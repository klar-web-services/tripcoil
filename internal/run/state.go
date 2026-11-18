package run

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

type State struct {
	LastRun             string    `json:"lastRun,omitempty"`
	LastRunAt           time.Time `json:"lastRunAt,omitzero"`
	LastStatus          string    `json:"lastStatus,omitempty"`
	LastReviewed        string    `json:"lastReviewed,omitempty"`
	LastReviewedAt      time.Time `json:"lastReviewedAt,omitzero"`
	ConsecutiveFailures int       `json:"consecutiveFailures"`
}

func statePath(stateDir string) string { return filepath.Join(stateDir, "state.json") }

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

func WriteState(stateDir string, s State) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(statePath(stateDir), append(data, '\n'), 0o600, false)
}

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
	if r.Reviewed {
		s.LastReviewed, s.LastReviewedAt = r.RunID, r.ReviewedAt
	}
}
