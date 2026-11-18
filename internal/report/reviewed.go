package report

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/review"
)

// maxEntries is how many entries a section of the reviewed report lists in full; review.json holds
// them all.
const maxEntries = 200

var priorities = []string{"now", "soon", "scheduled", "none"}

// reviewed is one entry of the report: an audit finding with its review, or a finding the agent added.
type reviewed struct {
	entry   review.Entry
	finding *audit.Finding // nil for an added finding
}

// renderReviewed writes report.md for a run with a review (spec section 11.3).
func renderReviewed(in Input) string {
	var b strings.Builder
	gaps := Gaps(in.Inventory, in.Audit, in.Facts)
	byID := map[string]*audit.Finding{}
	for i := range in.Audit.Findings {
		byID[in.Audit.Findings[i].ID] = &in.Audit.Findings[i]
	}
	groups := map[string][]reviewed{}
	for _, e := range in.Review.Findings {
		r := reviewed{entry: e, finding: byID[e.FindingID]}
		key := e.Exploitability
		if e.Verdict == review.FalsePositive {
			key = review.FalsePositive
		}
		groups[key] = append(groups[key], r)
	}
	var notReviewed []audit.Finding
	for _, id := range in.Review.NotReviewed {
		if f := byID[id]; f != nil {
			notReviewed = append(notReviewed, *f)
		}
	}
	unassessed := len(groups[review.Unknown]) + len(notReviewed)
	// Only conditional findings worth acting on soon count in the verdict and are listed in full.
	var conditional, lower []reviewed
	for _, r := range groups[review.Conditional] {
		if r.entry.Priority == "now" || r.entry.Priority == "soon" {
			conditional = append(conditional, r)
		} else {
			lower = append(lower, r)
		}
	}

	b.WriteString(reviewVerdict(len(groups[review.Exploitable]), len(conditional), unassessed, len(lower)) + suffixes(in.Run, len(gaps), true) + "\n\n")
	b.WriteString(hostLine(in) + reviewHost(in) + "\n\n")
	writeErrors(&b, in)
	writeReviewWarnings(&b, in)
	b.WriteString("## Summary\n\n" + escapeBlockStart(md(in.Review.Summary)) + "\n")
	if len(in.Review.CoverageNotes) > 0 {
		b.WriteString("\n")
		for _, n := range in.Review.CoverageNotes {
			b.WriteString("- " + escapeBlockStart(md(n)) + "\n")
		}
	}
	b.WriteString("\n")
	names := itemNamesByID(in.Inventory)
	writeEntries(&b, "Exploitable now", groups[review.Exploitable], names)
	writeEntries(&b, "Exploitable under conditions", conditional, names)
	writeCollapsed(&b, "Conditional, lower priority", lower, names)
	if unassessed > 0 {
		fmt.Fprintf(&b, "## Not assessed (%d)\n\n", unassessed)
		if len(groups[review.Unknown]) > 0 {
			b.WriteString("The review could not tell whether these are exploitable here:\n\n")
			writeList(&b, groups[review.Unknown], names)
		}
		if len(notReviewed) > 0 {
			fmt.Fprintf(&b, "The review did not address %s:\n\n", plural(len(notReviewed), "finding", "findings"))
			writeFindingsAt(&b, "###", notReviewed, in.Inventory)
		}
	}
	writeRestarts(&b, in.Inventory)
	writeCollapsed(&b, "Not exploitable here", groups[review.NotExploitable], names)
	writeCollapsed(&b, "Discarded", groups[review.FalsePositive], names)
	writeGaps(&b, gaps, in.Audit, in.Inventory)
	writeFreshness(&b, in.Audit)
	return strings.TrimRight(b.String(), "\n") + "\n"
}

// reviewVerdict is the verdict line of a reviewed run: the first rule of spec section 11.3 that applies.
// conditional counts only conditional findings with priority now or soon; lower counts the other
// conditional findings, which every line names at its end.
func reviewVerdict(exploitable, conditional, unassessed, lower int) string {
	var s string
	switch {
	case exploitable > 0:
		s = fmt.Sprintf("🔴 %s exploitable now", plural(exploitable, "issue", "issues"))
		if unassessed > 0 {
			s += fmt.Sprintf("; %d not assessed", unassessed)
		}
	case conditional > 0:
		s = fmt.Sprintf("🟠 No issue exploitable now; %d exploitable under conditions", conditional)
		if unassessed > 0 {
			s += fmt.Sprintf("; %d not assessed", unassessed)
		}
	case unassessed > 0:
		s = fmt.Sprintf("🟡 No issue found exploitable, but %s not assessed", plural(unassessed, "finding was", "findings were"))
	default:
		s = "🟢 No exploitable issues found"
	}
	if lower > 0 {
		s += fmt.Sprintf("; %d lower-priority conditional", lower)
	}
	return s
}

// reviewHost ends the host line with the agent and, for a carried-forward review, where it is from.
func reviewHost(in Input) string {
	s := ""
	if in.Agent != "" {
		s += " · reviewed by " + md(in.Agent)
	}
	if in.Run.CarriedFrom != "" {
		s += " · review carried forward from " + stamp(in.Run.ReviewedAt) + " (run " + in.Run.CarriedFrom + ")"
	}
	return s
}

func writeErrors(b *strings.Builder, in Input) {
	if len(in.Run.Errors) == 0 {
		return
	}
	b.WriteString("## Errors\n\n")
	for _, e := range in.Run.Errors {
		fmt.Fprintf(b, "- %s, `%s`: %s\n", titleCase(cmp.Or(e.Stage, "run")), e.Code, md(e.Message))
	}
	b.WriteString("\n")
}

// writeReviewWarnings lists the review stage's warnings, such as entries that were dropped.
func writeReviewWarnings(b *strings.Builder, in Input) {
	var lines []string
	for _, w := range in.Run.Warnings {
		if w.Stage == "review" {
			lines = append(lines, fmt.Sprintf("- `%s`: %s", w.Code, md(w.Message)))
		}
	}
	if len(lines) > 0 {
		b.WriteString("## Review warnings\n\n" + strings.Join(lines, "\n") + "\n\n")
	}
}

// sortEntries orders entries by priority, then by the finding's risk tier (added findings last).
func sortEntries(rs []reviewed) {
	tier := func(r reviewed) int {
		if r.finding == nil {
			return len(audit.Tiers)
		}
		return slices.Index(audit.Tiers, r.finding.Risk)
	}
	prio := func(r reviewed) int {
		if i := slices.Index(priorities, r.entry.Priority); i >= 0 {
			return i
		}
		return len(priorities)
	}
	slices.SortStableFunc(rs, func(a, b reviewed) int {
		return cmp.Or(cmp.Compare(prio(a), prio(b)), cmp.Compare(tier(a), tier(b)), cmp.Compare(a.entry.FindingID, b.entry.FindingID))
	})
}

func writeEntries(b *strings.Builder, title string, rs []reviewed, names map[string]string) {
	if len(rs) == 0 {
		return
	}
	fmt.Fprintf(b, "## %s (%d)\n\n", title, len(rs))
	writeList(b, rs, names)
}

// writeList writes entries in full, at most maxEntries.
func writeList(b *strings.Builder, rs []reviewed, names map[string]string) {
	sortEntries(rs)
	for i, r := range rs {
		if i == maxEntries {
			fmt.Fprintf(b, "- … and %d more, in review.json.\n", len(rs)-i)
			break
		}
		e := r.entry
		fmt.Fprintf(b, "- %s: %s\n", entryTitle(r, names), md(e.Reasoning))
		if len(e.Evidence) > 0 {
			b.WriteString("  - Evidence: " + mdList(e.Evidence) + "\n")
		}
		for _, c := range e.Corrections {
			fmt.Fprintf(b, "  - Corrected %s: %s → %s (%s)\n", md(c.Field), md(c.Old), md(c.New), md(c.Why))
		}
		for _, f := range e.Fix {
			b.WriteString("  - Fix: " + escapeBlockStart(md(f)) + "\n")
		}
		if len(e.Sources) > 0 {
			b.WriteString("  - Sources: " + mdList(e.Sources) + "\n")
		}
	}
	b.WriteString("\n")
}

// entryTitle names an entry: vulnerability, package and version, items, risk tier and priority.
func entryTitle(r reviewed, names map[string]string) string {
	e := r.entry
	var s string
	if f := r.finding; f != nil {
		s = fmt.Sprintf("%s in %s %s", vulnLink(f.Vulnerability), escapeBlockStart(md(f.Package.Name)), md(f.Package.Version))
		if items := itemList(*f, names); items != "" {
			s += " (" + md(items) + ")"
		}
		s += ", " + f.Risk + " risk"
	} else {
		s = fmt.Sprintf("%s in %s (added by the review)", escapeBlockStart(md(e.Vulnerability)), md(cmp.Or(names[e.Item], e.Item)))
	}
	if e.Priority != "" {
		s += ", priority " + e.Priority
	}
	return "**" + s + "**"
}

// writeCollapsed writes the entries the review found harmless here, one line each, collapsed.
func writeCollapsed(b *strings.Builder, title string, rs []reviewed, names map[string]string) {
	if len(rs) == 0 {
		return
	}
	sortEntries(rs)
	fmt.Fprintf(b, "## %s (%d)\n\n<details>\n<summary>%s</summary>\n\n", title, len(rs), plural(len(rs), "finding", "findings"))
	for i, r := range rs {
		if i == maxEntries {
			fmt.Fprintf(b, "- … and %d more, in review.json.\n", len(rs)-i)
			break
		}
		fmt.Fprintf(b, "- %s: %s\n", entryTitle(r, names), md(r.entry.Reasoning))
	}
	b.WriteString("\n</details>\n\n")
}

func mdList(s []string) string {
	out := make([]string, len(s))
	for i, x := range s {
		out[i] = md(x)
	}
	return strings.Join(out, "; ")
}
