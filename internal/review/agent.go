package review

import (
	"context"

	"github.com/klar-web-services/tripcoil/internal/problem"
)

// Agent runs one review of a run folder in the sandbox and returns the agent's output, the JSON
// that Validate reads. The agent package implements it; an error that is a *Failure names its code.
type Agent interface {
	Review(ctx context.Context, runDir string) (Output, error)
}

// Output is what an agent returned. Warnings are recorded whether or not the review failed.
type Output struct {
	Data     []byte
	Entries  []byte // the agent's entries file (EntriesFile), if it wrote one
	CLI      string // the agent CLI and its version, such as "claude 2.1.309"
	Warnings []problem.Problem
}

// Failure is a review that failed, with its code (AGENT_AUTH, AGENT_TIMEOUT, ...).
type Failure struct {
	Code    string
	Message string
}

func (f *Failure) Error() string { return f.Message }
