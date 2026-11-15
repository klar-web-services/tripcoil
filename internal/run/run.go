// Package run holds what every run shares: run.json, run IDs, how stage results become the run's
// status and exit code, the run lock and the run folder (spec sections 4, 9, 11 and 12).
package run

import (
	"encoding/hex"
	"io"
	"time"

	"github.com/klar-web-services/tripcoil/internal/problem"
)

// Stage results.
const (
	StageOK      = "ok"
	StagePartial = "partial"
	StageFailed  = "failed"
	StageSkipped = "skipped"
)

// Run statuses.
const (
	Complete    = "complete"
	Partial     = "partial"
	Failed      = "failed"
	Interrupted = "interrupted"
)

// Record is run.json.
type Record struct {
	SchemaVersion string            `json:"schemaVersion"`
	RunID         string            `json:"runId"`
	StartedAt     time.Time         `json:"startedAt"`
	EndedAt       time.Time         `json:"endedAt"`
	Trigger       string            `json:"trigger"` // schedule or manual
	Versions      map[string]string `json:"versions"`
	Stages        map[string]string `json:"stages"`
	Status        string            `json:"status"`
	Counts        map[string]int    `json:"counts"`
	// Fingerprint is the change check's fingerprint (spec section 8.6); empty when the run has none.
	Fingerprint string `json:"fingerprint,omitempty"`
	// Reviewed says the run has a review of its own. CarriedFrom names the run whose review it carries
	// forward instead. ReviewedAt is when the review it shows was made.
	Reviewed    bool              `json:"reviewed"`
	CarriedFrom string            `json:"carriedFrom,omitempty"`
	ReviewedAt  time.Time         `json:"reviewedAt,omitzero"`
	Errors      []problem.Problem `json:"errors"`
	Warnings    []problem.Problem `json:"warnings"`
	Notices     []problem.Problem `json:"notices"`
	ExitCode    int               `json:"exitCode"`
}

// NewRecord starts a run.json.
func NewRecord(id string, started time.Time, trigger string, versions map[string]string) *Record {
	return &Record{
		SchemaVersion: "1", RunID: id, StartedAt: started.UTC(), Trigger: trigger, Versions: versions,
		Stages: map[string]string{}, Counts: map[string]int{},
		Errors: []problem.Problem{}, Warnings: []problem.Problem{}, Notices: []problem.Problem{},
	}
}

// Add records problems by kind. Gaps are not recorded here; they live on items and origins.
func (r *Record) Add(ps ...problem.Problem) {
	errs, warns, notices := problem.Split(ps)
	r.Errors = append(r.Errors, errs...)
	r.Warnings = append(r.Warnings, warns...)
	r.Notices = append(r.Notices, notices...)
}

// Finish sets the end time and derives the status and exit code from the stages.
func (r *Record) Finish(ended time.Time) {
	r.EndedAt = ended.UTC()
	r.Status, r.ExitCode = Outcome(r.Stages)
}

// Interrupt ends a run that a signal stopped during stage: status interrupted, exit 2.
func (r *Record) Interrupt(ended time.Time, stage string) {
	r.EndedAt = ended.UTC()
	r.Stages[stage] = StageFailed
	r.Add(problem.New(problem.Error, problem.Interrupted, stage, "the run was stopped by a signal during the %s stage", stage))
	r.Status, r.ExitCode = Interrupted, 2
}

// fatalStages fail the whole run when they fail: without an inventory or an audit there is
// nothing to report. Any other failed or partial stage leaves the run partial.
var fatalStages = map[string]bool{"inventory": true, "audit": true}

// Outcome returns the run status and exit code for stage results.
func Outcome(stages map[string]string) (string, int) {
	status, code := Complete, 0
	for name, s := range stages {
		switch {
		case s == StageFailed && fatalStages[name]:
			return Failed, 2
		case s == StageFailed || s == StagePartial:
			status, code = Partial, 1
		}
	}
	return status, code
}

// NewID returns a run ID: the UTC start time and 4 random hex digits, such as 20261114T061500Z-3fa2.
func NewID(now time.Time, random io.Reader) (string, error) {
	b := make([]byte, 2)
	if _, err := io.ReadFull(random, b); err != nil {
		return "", err
	}
	return now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b), nil
}
