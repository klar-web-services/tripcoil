// Package priority makes a run light on the host: nice 10 and the idle IO class (spec section 13).
package priority

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"
)

// Nice is the CPU priority of a run, as the service unit's Nice=10.
const Nice = 10

const (
	ioprioWhoProcess = 1
	ioprioClassShift = 13
	ioprioClassIdle  = 3
)

// Lower gives every thread of this process nice 10 (unless it is already nicer) and the idle IO
// class. Linux keeps both per thread, and a new thread or child process takes them from the
// thread that creates it, so every thread is changed, until a pass finds no new one. It keeps
// going after a failure and returns what failed, each distinct error once.
func Lower() error {
	done := map[int]bool{}
	seen := map[string]bool{}
	var errs []error
	for {
		entries, err := os.ReadDir("/proc/self/task")
		if err != nil {
			return errors.Join(append(errs, err)...)
		}
		changed := false
		for _, e := range entries {
			tid, err := strconv.Atoi(e.Name())
			if err != nil || done[tid] {
				continue
			}
			done[tid], changed = true, true
			for _, err := range lowerThread(tid) {
				if !errors.Is(err, syscall.ESRCH) && !seen[err.Error()] {
					seen[err.Error()] = true
					errs = append(errs, err)
				}
			}
		}
		if !changed {
			return errors.Join(errs...)
		}
	}
}

func lowerThread(tid int) []error {
	var errs []error
	// The raw getpriority value is 20 minus the nice value.
	raw, err := syscall.Getpriority(syscall.PRIO_PROCESS, tid)
	if err != nil {
		errs = append(errs, fmt.Errorf("read the CPU priority: %w", err))
	} else if 20-raw < Nice {
		if err := syscall.Setpriority(syscall.PRIO_PROCESS, tid, Nice); err != nil {
			errs = append(errs, fmt.Errorf("set the CPU priority: %w", err))
		}
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOPRIO_SET, ioprioWhoProcess, uintptr(tid), ioprioClassIdle<<ioprioClassShift); errno != 0 {
		errs = append(errs, fmt.Errorf("set the IO priority: %w", errno))
	}
	return errs
}
