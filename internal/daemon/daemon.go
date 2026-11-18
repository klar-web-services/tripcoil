package daemon

import (
	"context"
	"time"
)

type Scheduler struct {
	Now      func() time.Time
	After    func(time.Duration) <-chan time.Time
	Interval func() time.Duration
	Last     func() time.Time
	Run      func(ctx context.Context)
	Hangup   <-chan struct{}
	Reload   func()
	Waiting  func(at time.Time)
}

// Wait is how long until a run is due, after the last finished run and after the last attempt: a
// run that could not even start (a full disk) is not retried before the next interval. A time
// after now (a clock that was set back) counts as none, so a run is due and its own time then
// puts the schedule right.
func Wait(last, attempt time.Time, interval time.Duration, now time.Time) time.Duration {
	if last.After(now) {
		last = time.Time{}
	}
	if attempt.After(now) {
		attempt = time.Time{}
	}
	var next time.Time
	if !last.IsZero() {
		next = last.Add(interval)
	}
	if a := attempt.Add(interval); !attempt.IsZero() && a.After(next) {
		next = a
	}
	if next.IsZero() {
		return 0
	}
	return next.Sub(now)
}

func (s Scheduler) Loop(ctx context.Context) {
	var attempt time.Time
	for ctx.Err() == nil {
		wait := Wait(s.Last(), attempt, s.Interval(), s.Now())
		if wait <= 0 {
			attempt = s.Now()
			s.Run(ctx)
			continue
		}
		s.Waiting(s.Now().Add(wait))
		select {
		case <-ctx.Done():
		case <-s.Hangup:
			s.Reload()
		case <-s.After(wait):
		}
	}
}
