package run

import (
	"bytes"
	"testing"
	"time"

	"github.com/klar-web-services/tripcoil/internal/problem"
)

func TestNewID(t *testing.T) {
	id, err := NewID(time.Date(2026, 11, 14, 7, 15, 0, 0, time.FixedZone("CET", 3600)), bytes.NewReader([]byte{0x3f, 0xa2}))
	if err != nil || id != "20261114T061500Z-3fa2" {
		t.Fatalf("%q %v", id, err)
	}
}

func TestOutcome(t *testing.T) {
	cases := []struct {
		stages map[string]string
		status string
		code   int
	}{
		{map[string]string{"inventory": StageOK}, Complete, 0},
		{map[string]string{"inventory": StagePartial}, Partial, 1},
		{map[string]string{"inventory": StageFailed}, Failed, 2},
		{map[string]string{"inventory": StageOK, "review": StageFailed}, Partial, 1},
		{map[string]string{"inventory": StageOK, "audit": StageFailed, "review": StageSkipped}, Failed, 2},
		{map[string]string{"inventory": StageOK, "review": StageSkipped}, Complete, 0},
	}
	for _, tc := range cases {
		if s, c := Outcome(tc.stages); s != tc.status || c != tc.code {
			t.Errorf("Outcome(%v) = %s %d, want %s %d", tc.stages, s, c, tc.status, tc.code)
		}
	}
}

func TestRecord(t *testing.T) {
	start := time.Date(2026, 11, 14, 6, 15, 0, 0, time.UTC)
	r := NewRecord("20261114T061500Z-3fa2", start, "manual", map[string]string{"tripcoil": "dev"})
	r.Stages["inventory"] = StagePartial
	r.Add(problem.New(problem.Error, problem.DockerUnavailable, "inventory", "x"), problem.New(problem.Notice, problem.DockerAbsent, "inventory", "y"))
	r.Finish(start.Add(time.Minute))
	if r.Status != Partial || r.ExitCode != 1 || len(r.Errors) != 1 || len(r.Notices) != 1 || r.Warnings == nil || !r.EndedAt.Equal(start.Add(time.Minute)) {
		t.Fatalf("%+v", r)
	}
	i := NewRecord("20261114T061500Z-3fa2", start, "manual", nil)
	i.Interrupt(start.Add(time.Second), "inventory")
	if i.Status != Interrupted || i.ExitCode != 2 || i.Stages["inventory"] != StageFailed || len(i.Errors) != 1 || i.Errors[0].Code != problem.Interrupted {
		t.Fatalf("interrupted %+v", i)
	}
}
