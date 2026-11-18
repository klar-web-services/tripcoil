package run

import (
	"encoding/hex"
	"io"
	"time"

	"github.com/klar-web-services/tripcoil/internal/problem"
)

const (
	StageOK      = "ok"
	StagePartial = "partial"
	StageFailed  = "failed"
	StageSkipped = "skipped"
)

const (
	Complete    = "complete"
	Partial     = "partial"
	Failed      = "failed"
	Interrupted = "interrupted"
)

type Record struct {
	SchemaVersion string            `json:"schemaVersion"`
	RunID         string            `json:"runId"`
	StartedAt     time.Time         `json:"startedAt"`
	EndedAt       time.Time         `json:"endedAt"`
	Trigger       string            `json:"trigger"`
	Versions      map[string]string `json:"versions"`
	Stages        map[string]string `json:"stages"`
	Status        string            `json:"status"`
	Counts        map[string]int    `json:"counts"`
	Fingerprint   string            `json:"fingerprint,omitempty"`
	Reviewed      bool              `json:"reviewed"`
	CarriedFrom   string            `json:"carriedFrom,omitempty"`
	ReviewedAt    time.Time         `json:"reviewedAt,omitzero"`
	Errors        []problem.Problem `json:"errors"`
	Warnings      []problem.Problem `json:"warnings"`
	Notices       []problem.Problem `json:"notices"`
	ExitCode      int               `json:"exitCode"`
}

func NewRecord(id string, started time.Time, trigger string, versions map[string]string) *Record {
	return &Record{
		SchemaVersion: "1", RunID: id, StartedAt: started.UTC(), Trigger: trigger, Versions: versions,
		Stages: map[string]string{}, Counts: map[string]int{},
		Errors: []problem.Problem{}, Warnings: []problem.Problem{}, Notices: []problem.Problem{},
	}
}

func (r *Record) Add(ps ...problem.Problem) {
	errs, warns, notices := problem.Split(ps)
	r.Errors = append(r.Errors, errs...)
	r.Warnings = append(r.Warnings, warns...)
	r.Notices = append(r.Notices, notices...)
}

func (r *Record) Finish(ended time.Time) {
	r.EndedAt = ended.UTC()
	r.Status, r.ExitCode = Outcome(r.Stages)
}

func (r *Record) Interrupt(ended time.Time, stage string) {
	r.EndedAt = ended.UTC()
	r.Stages[stage] = StageFailed
	r.Add(problem.New(problem.Error, problem.Interrupted, stage, "the run was stopped by a signal during the %s stage", stage))
	r.Status, r.ExitCode = Interrupted, 2
}

var fatalStages = map[string]bool{"inventory": true, "audit": true}

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

func NewID(now time.Time, random io.Reader) (string, error) {
	b := make([]byte, 2)
	if _, err := io.ReadFull(random, b); err != nil {
		return "", err
	}
	return now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b), nil
}
