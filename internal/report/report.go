// Package report renders report.md from what a run produced (spec section 11.3).
package report

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/problem"
	"github.com/klar-web-services/tripcoil/internal/run"
)

// Input is what a run produced. Inventory and Audit are nil when their stage wrote nothing.
type Input struct {
	Run       *run.Record
	Inventory *inventory.Inventory
	Audit     *audit.Audit
	// NoReview says why the report is audit-only.
	NoReview string
}

// maxItems is how many items a finding names; the C library belongs to nearly every process.
const maxItems = 5

// Gap is one coverage gap: something Tripcoil could not audit, by design or because it could not
// identify it (spec section 12).
type Gap struct {
	Code    string
	Subject string
	Detail  string
}

// Gaps lists the coverage gaps of a run: unresolved and unidentified origins, items without an
// app directory, and containers audited by their image only.
func Gaps(inv *inventory.Inventory, aud *audit.Audit) []Gap {
	if inv == nil {
		return nil
	}
	names := itemNames(inv)
	origins := originsByID(inv)
	var gaps []Gap
	for _, o := range inv.Origins {
		if o.Kind == inventory.OriginUnresolved {
			gaps = append(gaps, Gap{problem.OriginUnresolved, describe(o, names[o.ID]), o.Reason})
		}
	}
	if aud != nil {
		for _, o := range aud.Origins {
			if o.Status == audit.Unidentified {
				gaps = append(gaps, Gap{problem.OriginUnidentified, describe(origins[o.ID], names[o.ID]), cmp.Or(o.Reason, "no packages were identified in it")})
			}
		}
	}
	for _, it := range inv.Items {
		for _, n := range it.Notes {
			switch n {
			case problem.AppDirNotFound:
				gaps = append(gaps, Gap{n, it.Name + " (" + it.Exe + ")", "no app directory was found, so only the interpreter is audited"})
			case problem.ImageOnly:
				gaps = append(gaps, Gap{n, "container " + it.Name, "only the image is audited, not bind-mounted code or changes made in the running container"})
			}
		}
	}
	return gaps
}

// Render writes report.md. It always renders, whatever the run produced.
func Render(in Input) string {
	var b strings.Builder
	gaps := Gaps(in.Inventory, in.Audit)
	b.WriteString(verdict(in, len(gaps)) + "\n\n")
	b.WriteString(hostLine(in) + "\n\n")
	if len(in.Run.Errors) > 0 {
		b.WriteString("## Errors\n\n")
		for _, e := range in.Run.Errors {
			stage := e.Stage
			if stage == "" {
				stage = "run"
			}
			fmt.Fprintf(&b, "- %s, `%s`: %s\n", titleCase(stage), e.Code, md(e.Message))
		}
		b.WriteString("\n")
	}
	if in.Audit != nil {
		writeUpgrades(&b, in.Audit.Upgrades)
		writeFindings(&b, in.Audit.Findings, itemNamesByID(in.Inventory))
	}
	writeRestarts(&b, in.Inventory)
	writeGaps(&b, gaps, in.Audit, in.Inventory)
	writeFreshness(&b, in.Audit)
	return strings.TrimRight(b.String(), "\n") + "\n"
}

func verdict(in Input, gaps int) string {
	r := in.Run
	switch {
	case r.Status == run.Interrupted:
		return "⛔ Run incomplete: the run was interrupted" + suffixes(r, gaps, false)
	case in.Audit == nil || r.Stages["audit"] == run.StageFailed:
		return "⛔ Run incomplete: " + failure(r) + suffixes(r, gaps, false)
	}
	counts := map[string]int{}
	for _, f := range in.Audit.Findings {
		counts[f.Risk]++
	}
	var parts []string
	for _, t := range audit.Tiers {
		parts = append(parts, fmt.Sprintf("%d %s", counts[t], t))
	}
	return fmt.Sprintf("⚠️ Audit only (%s): %s findings%s", in.NoReview, strings.Join(parts, ", "), suffixes(r, gaps, true))
}

// failure is the reason a run has no audit results: the error that fails a whole audit (an
// unwritable run folder, Grype unavailable, a stale database), else the first error of the audit,
// or of an earlier stage that stopped it.
func failure(r *run.Record) string {
	for _, code := range []string{problem.RunFolderUnwritable, problem.GrypeUnavailable, problem.DBStale} {
		for _, e := range r.Errors {
			if e.Code == code {
				return md(e.Message) + " (" + e.Code + ")"
			}
		}
	}
	for _, stage := range []string{"audit", "inventory", ""} {
		for _, e := range r.Errors {
			if e.Stage == stage {
				return md(e.Message) + " (" + e.Code + ")"
			}
		}
	}
	return "the audit did not run"
}

// suffixes notes a partial run, and a failed one that still has audit results (otherwise the
// verdict already gives the failure).
func suffixes(r *run.Record, gaps int, withAudit bool) string {
	s := ""
	if r.Status == run.Partial || r.Status == run.Failed && withAudit {
		var codes []string
		for _, e := range r.Errors {
			if !slices.Contains(codes, e.Code) {
				codes = append(codes, e.Code)
			}
		}
		s += " (run " + r.Status + ": " + strings.Join(codes, ", ") + ")"
	}
	if gaps > 0 {
		s += " (" + plural(gaps, "coverage gap", "coverage gaps") + ")"
	}
	return s
}

func hostLine(in Input) string {
	parts := []string{}
	if inv := in.Inventory; inv != nil {
		parts = append(parts, "**"+md(inv.Host.Hostname)+"**", md(distroName(inv.Host.Distro)))
		for _, it := range inv.Items {
			if it.Kind == inventory.KindKernel {
				parts = append(parts, "kernel "+md(it.Release))
			}
		}
	}
	parts = append(parts, "run "+in.Run.RunID+", "+in.Run.StartedAt.UTC().Format("2006-01-02 15:04 UTC"))
	return strings.Join(parts, " · ")
}

func distroName(d inventory.Distro) string {
	if d.VersionID == "" {
		return d.ID
	}
	return d.ID + " " + d.VersionID
}

func writeUpgrades(b *strings.Builder, ups []audit.Upgrade) {
	if len(ups) == 0 {
		return
	}
	b.WriteString("## Upgrades\n\n")
	for _, u := range ups {
		installed := make([]string, len(u.Installed))
		for i, v := range u.Installed {
			installed[i] = md(v)
		}
		fmt.Fprintf(b, "- Upgrade %s %s in %s to %s to clear %s.\n", md(u.Package), strings.Join(installed, ", "), md(u.Path), md(u.Version), clears(u.Findings))
	}
	b.WriteString("\n")
}

func clears(n int) string {
	if n == 1 {
		return "its finding"
	}
	return fmt.Sprintf("all %d of its findings", n)
}

func writeFindings(b *strings.Builder, findings []audit.Finding, names map[string]string) {
	byTier := map[string][]audit.Finding{}
	for _, f := range findings {
		byTier[f.Risk] = append(byTier[f.Risk], f)
	}
	for _, tier := range audit.Tiers {
		fs := byTier[tier]
		if len(fs) == 0 {
			continue
		}
		slices.SortFunc(fs, func(a, b audit.Finding) int {
			return cmp.Or(cmp.Compare(b.Vulnerability.EPSS, a.Vulnerability.EPSS), cmp.Compare(a.Vulnerability.ID, b.Vulnerability.ID), cmp.Compare(a.ID, b.ID))
		})
		fmt.Fprintf(b, "## %s risk (%d)\n\n", titleCase(tier), len(fs))
		for _, f := range fs {
			var items []string
			for _, id := range f.Items {
				items = append(items, names[id])
			}
			slices.Sort(items)
			items = slices.Compact(items)
			fmt.Fprintf(b, "- %s in %s %s", vulnLink(f.Vulnerability), md(f.Package.Name), md(f.Package.Version))
			if len(items) > maxItems {
				items = append(items[:maxItems], fmt.Sprintf("and %d more", len(items)-maxItems))
			}
			if len(items) > 0 {
				fmt.Fprintf(b, " (%s)", md(strings.Join(items, ", ")))
			}
			fmt.Fprintf(b, ": %s.\n  %s\n", signals(f), md(f.Remediation))
		}
		b.WriteString("\n")
	}
}

func signals(f audit.Finding) string {
	s := []string{"severity " + f.Vulnerability.Severity}
	if f.Vulnerability.KnownExploited {
		s = append(s, "known exploited (CISA KEV)")
	}
	switch e := f.Vulnerability.EPSS; {
	case e > 0 && e < 0.0005: // would round to 0.0%
		s = append(s, "EPSS <0.1%")
	case e > 0:
		s = append(s, fmt.Sprintf("EPSS %.1f%%", e*100))
	}
	if f.Source == "kernel-cna" {
		s = append(s, "matched by upstream kernel version")
	}
	return strings.Join(s, ", ")
}

func writeRestarts(b *strings.Builder, inv *inventory.Inventory) {
	if inv == nil {
		return
	}
	var lines []string
	for _, it := range inv.Items {
		switch {
		case it.Kind == inventory.KindKernel && it.RebootPending != nil && *it.RebootPending:
			lines = append(lines, fmt.Sprintf("- Reboot: the running kernel %s is not the newest installed (%s).", md(it.Release), md(strings.Join(it.RebootReasons, "; "))))
		case len(it.RestartNeeded) > 0:
			who := md(it.Name)
			if units := systemUnits(it.Units); len(units) > 0 {
				who = md(strings.Join(units, ", "))
			}
			line := fmt.Sprintf("- Restart %s: it still runs replaced files: %s.", who, md(strings.Join(it.RestartNeeded, ", ")))
			if !slices.Contains(lines, line) {
				lines = append(lines, line)
			}
		}
	}
	if len(lines) == 0 {
		return
	}
	b.WriteString("## Restart or reboot needed\n\n" + strings.Join(lines, "\n") + "\n\n")
}

// systemUnits drops a user's own manager unit (user@1000.service), which is not restarted for a replaced file.
func systemUnits(units []string) []string {
	return slices.DeleteFunc(slices.Clone(units), func(u string) bool { return strings.HasPrefix(u, "user@") })
}

func writeGaps(b *strings.Builder, gaps []Gap, aud *audit.Audit, inv *inventory.Inventory) {
	var failed []string
	if aud != nil && inv != nil && aud.Status != audit.Failed { // a failed audit's verdict says why
		names := itemNames(inv)
		origins := originsByID(inv)
		for _, o := range aud.Origins {
			if o.Status == audit.ScanFailed {
				failed = append(failed, fmt.Sprintf("- Not audited: %s: %s", md(describe(origins[o.ID], names[o.ID])), md(o.Error)))
			}
		}
	}
	if len(gaps) == 0 && len(failed) == 0 {
		return
	}
	b.WriteString("## Coverage gaps\n\n")
	for _, g := range gaps {
		fmt.Fprintf(b, "- `%s` %s: %s\n", g.Code, md(g.Subject), md(g.Detail))
	}
	for _, f := range failed {
		b.WriteString(f + "\n")
	}
	b.WriteString("\n")
}

func writeFreshness(b *strings.Builder, aud *audit.Audit) {
	if aud == nil {
		return
	}
	b.WriteString("## Data freshness\n\n")
	if aud.Grype.DBBuilt.IsZero() {
		fmt.Fprintf(b, "- No vulnerability database was loaded (Grype %s).\n", aud.Grype.Version)
	} else {
		fmt.Fprintf(b, "- Vulnerability database built %s (Grype %s).\n", stamp(aud.Grype.DBBuilt), aud.Grype.Version)
	}
	if k := aud.KernelData; k != nil {
		fmt.Fprintf(b, "- Kernel CNA data checked %s (vulns repository at %.12s). It holds the CVEs the Linux kernel CNA published; "+
			"kernel CVEs that other CNAs assigned, mostly before 2024, are not matched by upstream version.\n", stamp(k.Checked), k.Commit)
	}
}

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

// describe names an origin for the report, with the items it belongs to.
func describe(o inventory.Origin, items []string) string {
	var what string
	switch o.Kind {
	case inventory.OriginPackage:
		what = "package " + o.Name + " " + o.Version
	case inventory.OriginBinary, inventory.OriginUnresolved:
		what = strings.Join(o.Paths, ", ")
	case inventory.OriginAppDir:
		what = o.Path
	case inventory.OriginImage:
		what = "image " + cmp.Or(o.Ref, o.ImageID)
	case inventory.OriginKernelUpstream:
		what = "Linux " + o.UpstreamVersion
	}
	if len(items) == 0 {
		return cmp.Or(what, o.ID)
	}
	if len(items) > maxItems {
		items = append(items[:maxItems:maxItems], fmt.Sprintf("and %d more", len(items)-maxItems))
	}
	if what == "" {
		return strings.Join(items, ", ")
	}
	return strings.Join(items, ", ") + ": " + what
}

func originsByID(inv *inventory.Inventory) map[string]inventory.Origin {
	m := map[string]inventory.Origin{}
	for _, o := range inv.Origins {
		m[o.ID] = o
	}
	return m
}

// itemNames lists, for each origin, the names of its items.
func itemNames(inv *inventory.Inventory) map[string][]string {
	m := map[string][]string{}
	for _, it := range inv.Items {
		for _, id := range it.Origins {
			if !slices.Contains(m[id], it.Name) {
				m[id] = append(m[id], it.Name)
			}
		}
	}
	for id := range m {
		slices.Sort(m[id])
	}
	return m
}

func itemNamesByID(inv *inventory.Inventory) map[string]string {
	m := map[string]string{}
	if inv != nil {
		for _, it := range inv.Items {
			m[it.ID] = it.Name
		}
	}
	return m
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func vulnLink(v audit.Vulnerability) string {
	id := md(v.ID)
	for _, u := range v.URLs {
		if strings.HasPrefix(u, "https://") && !strings.ContainsFunc(u, unsafeURLRune) {
			return "[" + id + "](" + u + ")"
		}
	}
	return escapeBlockStart(id)
}

// escapeBlockStart keeps text printed at the start of a list item from opening a Markdown block.
// Leading spaces go first: clean turns control characters into spaces, and spaces before a block
// marker still open the block.
func escapeBlockStart(s string) string {
	s = strings.TrimLeft(s, " ")
	if s == "" {
		return s
	}
	if strings.ContainsRune("#+-=>", rune(s[0])) {
		return `\` + s
	}
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i > 0 && i < len(s) && (s[i] == '.' || s[i] == ')') {
		return s[:i] + `\` + s[i:]
	}
	return s
}

func unsafeURLRune(r rune) bool {
	return r <= ' ' || r >= 0x7f || strings.ContainsRune("()<>\"'|\\`[]", r)
}

// clean replaces control and Unicode format characters (bidi controls, zero-width characters), so
// untrusted text can neither drive the terminal nor spoof a name.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, s)
}

var mdEscaper = strings.NewReplacer(`\`, `\\`, "|", `\|`, "*", `\*`, "_", `\_`, "`", "\\`", "~", `\~`, "[", `\[`, "]", `\]`, "<", "&lt;", ">", "&gt;")

// md escapes untrusted text for Markdown.
func md(s string) string { return mdEscaper.Replace(clean(s)) }
