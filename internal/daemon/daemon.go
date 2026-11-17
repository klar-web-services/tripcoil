// Package daemon schedules runs (spec section 13): a run is due once the last finished run is at
// least one interval old, so a manual run pushes the next scheduled run back, and runs missed
// while the host was off are not made up.
package daemon

import (
	"context"
	"time"
)

// Scheduler holds what the loop takes from the outside world, so tests can replace it.
type Scheduler struct {
	Now      func() time.Time
	After    func(time.Duration) <-chan time.Time
	Interval func() time.Duration // the current config's interval
	Last     func() time.Time     // the start of the last finished run; zero when there is none
	// Run runs once if a run is still due when it holds the run lock (a manual run may have
	// finished while it waited for it).
	Run    func(ctx context.Context)
	Hangup <-chan struct{} // SIGHUP
	Reload func()
	// Waiting is told when the next run is due, before each wait.
	Waiting func(at time.Time)
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

// Loop schedules runs until ctx is done.
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
