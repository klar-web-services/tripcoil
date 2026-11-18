package daemon

import (
	"context"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 14, 6, 0, 0, 0, time.UTC)

func TestWait(t *testing.T) {
	h := time.Hour
	for _, c := range []struct {
		name          string
		last, attempt time.Time
		want          time.Duration
	}{
		{"no run yet", time.Time{}, time.Time{}, 0},
		{"no finished run, one attempt", time.Time{}, t0.Add(-h), 5 * h},
		{"last run 2h ago", t0.Add(-2 * h), time.Time{}, 4 * h},
		{"last run 7h ago", t0.Add(-7 * h), time.Time{}, -h},
		{"the last attempt did not finish", t0.Add(-7 * h), t0.Add(-h), 5 * h},
		{"an older attempt", t0.Add(-2 * h), t0.Add(-3 * h), 4 * h},
		{"a last run in the future (the clock was set back)", t0.Add(400 * 24 * h), time.Time{}, 0},
		{"an attempt in the future", t0.Add(-7 * h), t0.Add(24 * h), -h},
	} {
		if got := Wait(c.last, c.attempt, 6*h, t0); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

type fake struct {
	now      time.Time
	last     time.Time
	interval time.Duration
	runs     []time.Time
	waits    []time.Time
	reloads  int
	finishes bool
	hangup   chan struct{}
	cancel   context.CancelFunc
	stopAt   int
}

func (f *fake) scheduler() Scheduler {
	return Scheduler{
		Now: func() time.Time { return f.now },
		After: func(d time.Duration) <-chan time.Time {
			f.now = f.now.Add(d)
			c := make(chan time.Time, 1)
			c <- f.now
			return c
		},
		Interval: func() time.Duration { return f.interval },
		Last:     func() time.Time { return f.last },
		Run: func(context.Context) {
			f.runs = append(f.runs, f.now)
			if f.finishes {
				f.last = f.now
			}
			f.now = f.now.Add(10 * time.Minute)
		},
		Hangup: f.hangup,
		Reload: func() { f.reloads++; f.interval = time.Hour },
		Waiting: func(at time.Time) {
			f.waits = append(f.waits, at)
			if len(f.waits) == f.stopAt {
				f.cancel()
			}
		},
	}
}

func TestLoopRunsEveryInterval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &fake{now: t0, last: t0.Add(-2 * time.Hour), interval: 6 * time.Hour, finishes: true, cancel: cancel, stopAt: 3}
	f.scheduler().Loop(ctx)
	want := []time.Time{t0.Add(4 * time.Hour), t0.Add(10 * time.Hour)}
	if len(f.runs) != 2 || f.runs[0] != want[0] || f.runs[1] != want[1] {
		t.Fatalf("runs %v", f.runs)
	}
}

func TestLoopDoesNotRetryARunThatCouldNotStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &fake{now: t0, interval: 6 * time.Hour, cancel: cancel, stopAt: 2}
	f.scheduler().Loop(ctx)
	if len(f.runs) != 2 || f.runs[1].Sub(f.runs[0]) != 6*time.Hour {
		t.Fatalf("runs %v", f.runs)
	}
}

func TestLoopReloadsOnHangup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &fake{now: t0, last: t0.Add(-time.Hour), interval: 6 * time.Hour, finishes: true, hangup: make(chan struct{}, 1), cancel: cancel, stopAt: 2}
	f.hangup <- struct{}{}
	s := f.scheduler()
	s.After = func(time.Duration) <-chan time.Time { return nil }
	f.stopAt = 0
	s.Waiting = func(at time.Time) {
		f.waits = append(f.waits, at)
		if len(f.waits) == 2 {
			cancel()
		}
	}
	s.Loop(ctx)
	if f.reloads != 1 || len(f.runs) != 1 || f.runs[0] != t0 {
		t.Fatalf("reloads %d, runs %v", f.reloads, f.runs)
	}
	if f.waits[0] != t0.Add(5*time.Hour) || f.waits[1] != t0.Add(time.Hour) {
		t.Fatalf("waits %v", f.waits)
	}
}

func TestLoopRunsAfterTheClockWasSetBack(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &fake{now: t0, last: t0.Add(400 * 24 * time.Hour), interval: 6 * time.Hour, finishes: true, cancel: cancel, stopAt: 1}
	f.scheduler().Loop(ctx)
	if len(f.runs) != 1 || f.runs[0] != t0 || f.waits[0] != t0.Add(6*time.Hour) {
		t.Fatalf("runs %v, waits %v", f.runs, f.waits)
	}
}

func TestLoopStopsDuringAWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &fake{now: t0, last: t0, interval: 6 * time.Hour, cancel: cancel, stopAt: 1}
	s := f.scheduler()
	s.After = func(time.Duration) <-chan time.Time { return nil }
	s.Loop(ctx)
	if len(f.runs) != 0 {
		t.Fatalf("runs %v", f.runs)
	}
}
