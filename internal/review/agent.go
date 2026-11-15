package review

import "context"

// Agent runs one review of a run folder in the sandbox and returns the agent's output, the JSON
// that Validate reads. Plan 3b adds the agents; an error that is a *Failure names its code.
type Agent interface {
	Review(ctx context.Context, runDir string) (Output, error)
}

// Output is what an agent returned.
type Output struct {
	Data []byte
	CLI  string // the agent CLI and its version, such as "claude 2.1.309"
}

// Failure is a review that failed, with its code (AGENT_AUTH, AGENT_TIMEOUT, ...).
type Failure struct {
	Code    string
	Message string
}

func (f *Failure) Error() string { return f.Message }
