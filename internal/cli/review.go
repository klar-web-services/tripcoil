package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/config"
	"github.com/klar-web-services/tripcoil/internal/facts"
	"github.com/klar-web-services/tripcoil/internal/fingerprint"
	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/problem"
	"github.com/klar-web-services/tripcoil/internal/review"
	"github.com/klar-web-services/tripcoil/internal/run"
)

const notInBuild = "the AI review is not part of this build"

type reviewRun struct {
	d        deps
	cfg      config.Config
	rec      *run.Record
	dir      string
	inv      *inventory.Inventory
	aud      *audit.Audit
	idx      *facts.Index
	noReview bool
	force    bool
	cli      string
}

func (r *reviewRun) run(ctx context.Context) (*review.Review, string) {
	rec := r.rec
	r.rec.Versions["prompt"] = review.PromptVersion
	switch {
	case rec.Status == run.Interrupted:
		return nil, ""
	case r.aud == nil || rec.Stages["audit"] == run.StageFailed:
		rec.Stages["review"] = run.StageSkipped
		return nil, ""
	}
	in := fingerprint.Input{Inventory: r.inv, Audit: r.aud, Firewall: r.text("firewall.txt"), SSHD: r.text("sshd.txt"),
		PromptVersion: review.PromptVersion, Agent: r.cfg.Review.Agent, Model: r.cfg.Review.Model}
	var network facts.Network
	if r.fact("network.json", &network) {
		in.Network = &network
	}
	var users []facts.User
	if r.fact("users.json", &users) {
		in.Users = &users
	}
	var containers []facts.Container
	if r.fact("containers.json", &containers) {
		in.Containers = &containers
	}
	var kernel facts.Kernel
	if r.fact("kernel.json", &kernel) {
		in.Kernel = &kernel
	}
	rec.Fingerprint = fingerprint.Compute(in)
	switch {
	case r.cfg.Review.Agent == "none":
		rec.Stages["review"] = run.StageSkipped
		return nil, "review.agent is none"
	case r.noReview:
		rec.Stages["review"] = run.StageSkipped
		return nil, "--no-review"
	}
	now := r.d.now()
	prev := review.LastReviewed(r.d.stateDir)
	if review.NeedsReview(prev, rec.Fingerprint, now, time.Duration(r.cfg.Review.MaxAge), r.force) == "" {
		rev := review.Carry(prev.Review, r.aud, r.inv)
		if err := run.WriteJSON(filepath.Join(r.dir, "review.json"), rev, 0o640); err != nil {
			rec.Add(problem.New(problem.Error, problem.RunFolderUnwritable, "", "cannot write review.json: %v", err))
			rec.Stages["review"] = run.StageFailed
			return nil, "review.json could not be written"
		}
		rec.CarriedFrom, rec.ReviewedAt = prev.RunID, prev.Record.ReviewedAt
		rec.Stages["review"] = run.StageOK
		r.cli = prev.Record.Versions["agentCli"]
		for _, k := range []string{"agentCli", "model"} {
			if v := prev.Record.Versions[k]; v != "" {
				rec.Versions[k] = v
			}
		}
		countReview(rec, rev)
		return rev, ""
	}
	agent := r.d.agent(r.cfg)
	if agent == nil {
		rec.Stages["review"] = run.StageSkipped
		return nil, notInBuild
	}
	if err := run.WriteJSON(filepath.Join(r.dir, "groups.json"), review.GroupFindings(r.aud, r.inv), 0o640); err != nil {
		rec.Add(problem.New(problem.Error, problem.RunFolderUnwritable, "", "cannot write groups.json: %v", err))
	}
	out, err := agent.Review(ctx, r.dir)
	rec.Add(out.Warnings...)
	if ctx.Err() != nil {
		rec.Interrupt(r.d.now(), "review")
		return nil, ""
	}
	var unsupported *review.Failure
	if errors.As(err, &unsupported) && unsupported.Code == problem.ReviewUnsupported {
		rec.Add(problem.New(problem.Notice, problem.ReviewUnsupported, "review", "%s", unsupported.Message))
		rec.Stages["review"] = run.StageSkipped
		return nil, "no AI review: " + unsupported.Message
	}
	if out.CLI != "" {
		rec.Versions["agentCli"], r.cli = out.CLI, out.CLI
	}
	if r.cfg.Review.Model != "" {
		rec.Versions["model"] = r.cfg.Review.Model
	}
	var rev *review.Review
	if err == nil {
		var warns []problem.Problem
		rev, warns, err = review.Validate(out.Data, out.Entries, r.aud, r.inv)
		rec.Add(warns...)
		if errors.Is(err, review.ErrInvalid) {
			err = &review.Failure{Code: problem.AgentOutputInvalid, Message: err.Error()}
		}
	}
	if err != nil {
		code := problem.AgentFailed
		var f *review.Failure
		if errors.As(err, &f) {
			code = f.Code
		}
		rec.Add(problem.New(problem.Error, code, "review", "%s", err.Error()))
		rec.Stages["review"] = run.StageFailed
		return nil, "AI review failed: " + code
	}
	if err := run.WriteJSON(filepath.Join(r.dir, "review.json"), rev, 0o640); err != nil {
		rec.Add(problem.New(problem.Error, problem.RunFolderUnwritable, "", "cannot write review.json: %v", err))
		rec.Stages["review"] = run.StageFailed
		return nil, "review.json could not be written"
	}
	rec.Reviewed, rec.ReviewedAt = true, r.d.now().UTC()
	rec.Stages["review"] = run.StageOK
	countReview(rec, rev)
	return rev, ""
}

func countReview(rec *run.Record, rev *review.Review) {
	for _, k := range []string{"reviewExploitable", "reviewConditional", "reviewConditionalLowerPriority", "reviewNotExploitable", "reviewUnknown", "reviewFalsePositive", "reviewAdded"} {
		rec.Counts[k] = 0
	}
	for _, e := range rev.Findings {
		switch {
		case e.Verdict == review.FalsePositive:
			rec.Counts["reviewFalsePositive"]++
		case e.Exploitability == review.Exploitable:
			rec.Counts["reviewExploitable"]++
		case e.Exploitability == review.Conditional:
			rec.Counts["reviewConditional"]++
			if e.Priority != "now" && e.Priority != "soon" {
				rec.Counts["reviewConditionalLowerPriority"]++
			}
		case e.Exploitability == review.NotExploitable:
			rec.Counts["reviewNotExploitable"]++
		default:
			rec.Counts["reviewUnknown"]++
		}
		if e.Verdict == review.Added {
			rec.Counts["reviewAdded"]++
		}
	}
	rec.Counts["notReviewed"] = len(rev.NotReviewed)
}

func (r *reviewRun) agentName() string {
	if r.cli == "" {
		return ""
	}
	if r.cfg.Review.Model != "" {
		return r.cli + ", model " + r.cfg.Review.Model
	}
	return r.cli
}

func (r *reviewRun) collected(name string) bool {
	if r.idx == nil {
		return false
	}
	for _, c := range r.idx.Collected {
		if c == name {
			return true
		}
	}
	return false
}

func (r *reviewRun) fact(name string, v any) bool {
	if !r.collected(name) {
		return false
	}
	data, err := os.ReadFile(filepath.Join(r.dir, "facts", name))
	return err == nil && json.Unmarshal(data, v) == nil
}

func (r *reviewRun) text(name string) *string {
	if !r.collected(name) {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(r.dir, "facts", name))
	if err != nil {
		return nil
	}
	s := string(data)
	return &s
}
