package review

import (
	"context"

	"github.com/klar-web-services/tripcoil/internal/problem"
)

type Agent interface {
	Review(ctx context.Context, runDir string) (Output, error)
}

type Output struct {
	Data     []byte
	Entries  []byte
	CLI      string
	Warnings []problem.Problem
}

type Failure struct {
	Code    string
	Message string
}

func (f *Failure) Error() string { return f.Message }
