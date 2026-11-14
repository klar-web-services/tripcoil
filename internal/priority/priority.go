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
// thread that creates it, so every thread is changed, until a pass finds no new one.
func Lower() error { return lower("/proc/self/task") }

func lower(taskDir string) error {
	done := map[int]bool{}
	for {
		entries, err := os.ReadDir(taskDir)
		if err != nil {
			return err
		}
		changed := false
		for _, e := range entries {
			tid, err := strconv.Atoi(e.Name())
			if err != nil || done[tid] {
				continue
			}
			done[tid], changed = true, true
			if err := lowerThread(tid); err != nil && !errors.Is(err, syscall.ESRCH) {
				return err
			}
		}
		if !changed {
			return nil
		}
	}
}

func lowerThread(tid int) error {
	// The raw getpriority value is 20 minus the nice value.
	raw, err := syscall.Getpriority(syscall.PRIO_PROCESS, tid)
	if err != nil {
		return fmt.Errorf("read the CPU priority: %w", err)
	}
	if 20-raw < Nice {
		if err := syscall.Setpriority(syscall.PRIO_PROCESS, tid, Nice); err != nil {
			return fmt.Errorf("set the CPU priority: %w", err)
		}
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOPRIO_SET, ioprioWhoProcess, uintptr(tid), ioprioClassIdle<<ioprioClassShift); errno != 0 {
		return fmt.Errorf("set the IO priority: %w", errno)
	}
	return nil
}
