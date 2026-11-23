package report

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/review"
	"github.com/klar-web-services/tripcoil/internal/waiting"
)

const (
	UrgencyNow        = "now"
	UrgencySoon       = "soon"
	UrgencyRoutine    = "routine"
	UrgencyUnassessed = "unassessed"
	// UrgencyWaiting: no fixed release exists and nothing is left to do on the machine. Such a card
	// is no to-do, and a report with only such cards is clean.
	UrgencyWaiting = "waiting"
	UrgencyNone    = "none"

	// CardFinding is the kind of a card for a finding the review added.
	CardFinding = "finding"
)

var urgencies = []string{UrgencyNow, UrgencySoon, UrgencyRoutine, UrgencyUnassessed, UrgencyWaiting, UrgencyNone}

// Card is one action as the report shows it: what to do, what changes, how, and how urgent it is.
type Card struct {
	ID          string                `json:"id"`
	Kind        string                `json:"kind"`
	Name        string                `json:"name"`
	Target      string                `json:"target,omitempty"`
	Items       []string              `json:"items"`
	MoreItems   int                   `json:"moreItems,omitempty"`
	Urgency     string                `json:"urgency"`
	Reviewed    bool                  `json:"reviewed"`
	Title       string                `json:"title"`
	Changes     []review.ActionChange `json:"changes"`
	MoreChanges int                   `json:"moreChanges,omitempty"`
	Also        []string              `json:"also"`
	Steps       []audit.Step          `json:"steps"`
	Upstream    review.Upstream       `json:"upstream"`
	Why         string                `json:"why,omitempty"`
	// Reach is from where the card's items can be reached together; empty for the kernel and
	// where no review established it.
	Reach  string         `json:"reach,omitempty"`
	Via    string         `json:"via,omitempty"`
	Counts map[string]int `json:"counts"`
	// Update says, for an image, what pulling its tag brings; nil when that was not looked at.
	Update *CardUpdate `json:"update,omitempty"`
	// Waiting is the card's clock while no fixed release exists; nil for a card that never waited.
	Waiting *CardWaiting `json:"waiting,omitempty"`

	tier int
	// waited is for how many days no fixed release has existed, as of the run.
	waited int
}

// CardWaiting says since when a card has had no fixed release. Overdue: its 30 days have passed.
// Until: Zosia's settings keep it waiting past them.
type CardWaiting struct {
	Key     string     `json:"key"`
	Since   time.Time  `json:"since"`
	Overdue bool       `json:"overdue"`
	Until   *time.Time `json:"until,omitempty"`
}

// settle decides whether an action's card waits. It waits when the review found no fixed release,
// none of its findings is exploitable as things stand or unassessed, no newer image clears
// findings, and either the review left it without steps or, once its 30 days have passed, Zosia's
// settings keep it waiting. The settings can keep such a card quiet and never hide a to-do.
func (c *Card) settle(a audit.Action, start time.Time) {
	mark := a.Waiting
	noFix := c.Reviewed && c.Upstream.State == review.UpstreamNone
	clears := a.Update != nil && a.Update.State == audit.UpdateScanned && a.Update.Clears > 0
	quiet := noFix && !clears && c.Urgency != UrgencyNone && c.Counts["exploitable"] == 0 && c.Counts["unassessed"] == 0
	overdue := mark != nil && mark.Overdue
	kept := overdue && mark.Until != nil && mark.Until.After(start)
	if quiet && (kept || !overdue && len(c.Steps) == 0) {
		c.Urgency, c.Waiting = UrgencyWaiting, &CardWaiting{Key: audit.WaitingKey(a), Since: start.UTC()}
		if mark != nil {
			c.Waiting.Since, c.Waiting.Overdue = mark.Since, mark.Overdue
		}
		if kept {
			c.Waiting.Until = mark.Until
		}
		return
	}
	if len(c.Steps) == 0 {
		c.Steps = a.Steps
	}
	if mark != nil && noFix {
		c.Waiting, c.waited = &CardWaiting{Key: mark.Key, Since: mark.Since, Overdue: mark.Overdue}, mark.Days
	}
}

// WaitingCards is what a reviewed report says of each action that has a card, for the waiting
// clock: whether it waits, and whether no fixed release exists.
func WaitingCards(in Input) []waiting.Card {
	out := []waiting.Card{}
	if !reviewedReport(in) {
		return out
	}
	byID := map[string]Card{}
	for _, c := range Cards(in) {
		byID[c.ID] = c
	}
	for _, a := range in.Audit.Actions {
		if c, ok := byID[a.ID]; ok {
			out = append(out, waiting.Card{Key: audit.WaitingKey(a), Waits: c.Urgency == UrgencyWaiting, NoFix: c.Reviewed && c.Upstream.State == review.UpstreamNone})
		}
	}
	return out
}

// CardUpdate is an image action's audit.Update as a card carries it: the state, and for a scanned
// newer image how many of the card's findings it no longer has and how many stay.
type CardUpdate struct {
	State            string `json:"state"`
	Note             string `json:"note,omitempty"`
	Clears           int    `json:"clears"`
	Remains          int    `json:"remains"`
	RemainsExploited int    `json:"remainsExploited"`
}

// imageChanges makes an image card's changes say only what is known. `to` is the version the newer
// image has, when it was scanned; `needs` is the version that fixes the package, where the update
// does not bring it or what it brings was not checked. The version that would fix a package is
// never shown as what pulling the image brings.
func imageChanges(changes []review.ActionChange, a audit.Action) []review.ActionChange {
	known := map[string]audit.Change{}
	for _, ch := range a.Changes {
		known[audit.Cut(ch.Name, audit.MaxChangeName)+"\x00"+audit.Cut(ch.From, audit.MaxVersion)] = ch
	}
	scanned := a.Update != nil && a.Update.State == audit.UpdateScanned
	out := []review.ActionChange{}
	for _, c := range changes {
		n := review.ActionChange{Name: c.Name, From: c.From, Needs: c.To}
		if ch, ok := known[c.Name+"\x00"+c.From]; ok {
			n.Needs = audit.Cut(ch.To, audit.MaxVersion)
			switch {
			case !scanned:
			case ch.Gone:
				n.To, n.Needs = "removed", ""
			case ch.Gets != "" && ch.Gets != ch.From:
				if n.To = audit.Cut(ch.Gets, audit.MaxVersion); ch.Reaches {
					n.Needs = ""
				}
			}
		}
		out = append(out, n)
	}
	return out
}

func cardUpdate(u *audit.Update) *CardUpdate {
	if u == nil {
		return nil
	}
	return &CardUpdate{State: u.State, Note: audit.Cut(oneLine(u.Reason), audit.MaxNote), Clears: u.Clears, Remains: u.Remains, RemainsExploited: u.RemainsExploited}
}

// updateLine says in one sentence what an image card's update brings, or that it was not checked.
func updateLine(u *CardUpdate) string {
	switch {
	case u == nil:
		return "What the newer image holds was not checked."
	case u.State == audit.UpdateScanned && u.Remains == 0:
		return fmt.Sprintf("The newer image was scanned: it clears all %s.", plural(u.Clears, "finding", "findings"))
	case u.State == audit.UpdateScanned:
		s := fmt.Sprintf("The newer image was scanned: it clears %d of %s; %d still open", u.Clears, plural(u.Clears+u.Remains, "finding", "findings"), u.Remains)
		if u.RemainsExploited > 0 {
			s += fmt.Sprintf(", %d of them known exploited", u.RemainsExploited)
		}
		return s + "."
	case u.State == audit.UpdateCurrent:
		return "The tag still points to the running image, so pulling changes nothing. What another tag holds was not checked."
	case u.Note != "":
		return "What the newer image holds was not checked: " + u.Note + "."
	}
	return "What the newer image holds was not checked."
}

// sectionOf is the report section a finding's review entry puts it in. A finding without an
// entry, or of a run without a review, is unassessed.
func sectionOf(e review.Entry, reviewed bool) string {
	switch {
	case !reviewed:
		return "unassessed"
	case e.Verdict == review.FalsePositive:
		return "falsePositive"
	case e.Exploitability == review.Exploitable:
		return "exploitable"
	case e.Exploitability == review.Conditional && (e.Priority == "now" || e.Priority == "soon"):
		return "conditional"
	case e.Exploitability == review.Conditional:
		return "conditionalLower"
	case e.Exploitability == review.NotExploitable:
		return "notExploitable"
	}
	return "unassessed"
}

// urgencyOf is how soon a finding asks for its action, as an index into urgencies.
func urgencyOf(e review.Entry, reviewed bool) int {
	switch sectionOf(e, reviewed) {
	case "exploitable":
		return 0
	case "conditional":
		if e.Priority == "now" {
			return 0
		}
		return 1
	case "conditionalLower":
		return 2
	case "unassessed":
		return 3
	}
	return len(urgencies) - 1
}

func newCounts() map[string]int {
	return map[string]int{"findings": 0, "open": 0, "knownExploited": 0, "exploitable": 0, "conditional": 0, "conditionalLower": 0,
		"notExploitable": 0, "falsePositive": 0, "unassessed": 0}
}

func (c *Card) count(e review.Entry, reviewed, kev bool, tier int) {
	section := sectionOf(e, reviewed)
	c.Counts["findings"]++
	c.Counts[section]++
	if section != "notExploitable" && section != "falsePositive" {
		c.Counts["open"]++
		if kev {
			c.Counts["knownExploited"]++
		}
		c.tier = min(c.tier, tier)
	}
	if u := urgencyOf(e, reviewed); u < slices.Index(urgencies, c.Urgency) {
		c.Urgency = urgencies[u]
	}
}

// Cards are the report's actions: one per action of the audit and one per finding the review
// added, without those that need nothing done, most urgent first. A run from before the audit
// had actions has none.
func Cards(in Input) []Card {
	out := []Card{}
	if in.Audit == nil || len(in.Audit.Actions) == 0 {
		return out
	}
	reviewed := reviewedReport(in)
	entries := map[string]review.Entry{}
	texts := map[string]review.ActionEntry{}
	if reviewed {
		entries = in.Review.Index()
		for _, a := range in.Review.Actions {
			texts[a.Action] = a
		}
	}
	names := itemNamesByID(in.Inventory)
	byID := map[string]*Card{}
	for _, a := range in.Audit.Actions {
		c := Card{ID: a.ID, Kind: a.Kind, Name: audit.Cut(a.Name, audit.MaxName), Target: audit.Cut(a.Target, audit.MaxTarget), Items: []string{},
			MoreItems: a.MoreItems, Urgency: UrgencyNone, Counts: newCounts(), tier: len(audit.Tiers)}
		for _, id := range a.Items {
			c.Items = append(c.Items, audit.Cut(cmp.Or(names[id], id), audit.MaxItemName))
		}
		if t, ok := texts[a.ID]; ok {
			c.Reviewed, c.Title, c.Changes, c.Also, c.Steps, c.Upstream, c.Why = true, t.Title, t.Changes, t.Also, t.Steps, t.Upstream, t.Why
		} else {
			c.Title, c.Also, c.Steps, c.Upstream = audit.Cut(defaultTitle(a), audit.MaxTitle), []string{}, a.Steps, review.Upstream{State: review.UpstreamUnknown}
			c.Changes = []review.ActionChange{}
			for _, ch := range a.Changes[:min(len(a.Changes), review.MaxCardChanges)] {
				c.Changes = append(c.Changes, review.ActionChange{Name: audit.Cut(ch.Name, audit.MaxChangeName), From: audit.Cut(ch.From, audit.MaxVersion), To: audit.Cut(ch.To, audit.MaxVersion)})
			}
		}
		if a.Kind == audit.ActionImage {
			c.Changes, c.Update = imageChanges(c.Changes, a), cardUpdate(a.Update)
		}
		c.MoreChanges = max(0, len(a.Changes)+a.MoreChanges-len(c.Changes))
		byID[a.ID] = &c
	}
	itemsOf := map[string][]string{}
	for _, f := range in.Audit.Findings {
		if c := byID[f.Action]; c != nil {
			e, ok := entries[f.ID]
			c.count(e, reviewed && ok, f.Vulnerability.KnownExploited, slices.Index(audit.Tiers, f.Risk))
			for _, item := range f.Items {
				if !slices.Contains(itemsOf[f.Action], item) {
					itemsOf[f.Action] = append(itemsOf[f.Action], item)
				}
			}
		}
	}
	withReach := reviewed && in.Reach != nil
	established := review.Established(in.Review, in.Reach)
	asked := map[string]bool{}
	if reviewed {
		for _, e := range in.Review.Reach {
			asked[e.Item] = true
		}
	}
	for _, a := range in.Audit.Actions {
		if c := byID[a.ID]; c.Urgency != UrgencyNone {
			if reviewed {
				c.settle(a, in.Run.StartedAt)
			}
			if withReach && a.Kind != audit.ActionKernel {
				c.Reach, c.Via = cardReach(itemsOf[a.ID], established, in.Reach, asked)
			}
			out = append(out, *c)
		}
	}
	if reviewed {
		for _, e := range in.Review.Findings {
			if e.Verdict != review.Added {
				continue
			}
			item := audit.Cut(cmp.Or(names[e.Item], e.Item), audit.MaxItemName)
			c := Card{ID: e.FindingID, Kind: CardFinding, Name: item, Items: []string{item}, Urgency: UrgencyNone, Reviewed: true, Counts: newCounts(),
				tier: len(audit.Tiers), Changes: []review.ActionChange{}, Also: []string{}, Upstream: review.Upstream{State: review.UpstreamUnknown}}
			if t, ok := texts[e.FindingID]; ok {
				c.Title, c.Also, c.Steps, c.Upstream, c.Why = t.Title, t.Also, t.Steps, t.Upstream, t.Why
			} else {
				c.Title = audit.Cut(oneLine("Fix "+e.Vulnerability+" in "+item), audit.MaxTitle)
				c.Why = audit.Cut(oneLine(e.Reasoning), audit.MaxWhy)
				c.Steps = []audit.Step{}
				for _, f := range e.Fix[:min(len(e.Fix), audit.MaxSteps)] {
					if text := audit.Cut(oneLine(f), audit.MaxStepText); text != "" {
						c.Steps = append(c.Steps, audit.Step{Text: text})
					}
				}
			}
			if c.count(e, true, false, len(audit.Tiers)); c.Urgency != UrgencyNone {
				if withReach {
					c.Reach, c.Via = cardReach([]string{e.Item}, established, in.Reach, asked)
				}
				out = append(out, c)
			}
		}
	}
	slices.SortStableFunc(out, func(x, y Card) int {
		return cmp.Or(cmp.Compare(slices.Index(urgencies, x.Urgency), slices.Index(urgencies, y.Urgency)),
			cmp.Compare(y.Counts["knownExploited"], x.Counts["knownExploited"]), cmp.Compare(x.tier, y.tier), cmp.Compare(x.Name, y.Name), cmp.Compare(x.ID, y.ID))
	})
	return out[:min(len(out), audit.MaxCards)]
}

// oneLine turns control characters into spaces and runs of spaces into one.
func oneLine(s string) string { return strings.Join(strings.Fields(clean(s)), " ") }

func defaultTitle(a audit.Action) string {
	switch a.Kind {
	case audit.ActionKernel:
		return "Update the kernel and reboot"
	case audit.ActionPackages:
		return "Update system packages"
	case audit.ActionImage:
		return "Update the " + a.Name + " image"
	case audit.ActionAppDir:
		return "Update packages in " + a.Name
	}
	return "Replace " + a.Name
}

// cardCounts is how many cards each urgency has, under the keys of the verdict's counts.
func cardCounts(cards []Card) map[string]int {
	c := map[string]int{"actionsNow": 0, "actionsSoon": 0, "actionsRoutine": 0, "actionsUnassessed": 0, "actionsWaiting": 0}
	for _, card := range cards {
		switch card.Urgency {
		case UrgencyNow:
			c["actionsNow"]++
		case UrgencySoon:
			c["actionsSoon"]++
		case UrgencyRoutine:
			c["actionsRoutine"]++
		case UrgencyUnassessed:
			c["actionsUnassessed"]++
		case UrgencyWaiting:
			c["actionsWaiting"]++
		}
	}
	return c
}

var verdictMarks = map[string]string{VerdictExploitable: "🔴", VerdictConditional: "🟠", VerdictUnassessed: "🟡", VerdictClean: "🟢"}

// actionsVerdict is the verdict line of a reviewed report whose audit has actions, without its
// suffixes: the code's mark and how many cards wait at each urgency.
func actionsVerdict(code string, c map[string]int) string {
	var parts []string
	if n := c["actionsNow"]; n > 0 {
		parts = append(parts, plural(n, "thing to fix now", "things to fix now"))
	}
	if n := c["actionsSoon"]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d to fix this week", n))
	}
	if n := c["actionsRoutine"]; n > 0 {
		parts = append(parts, plural(n, "routine update", "routine updates"))
	}
	if n := c["actionsUnassessed"]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d not assessed", n))
	}
	if len(parts) == 0 {
		parts = []string{"Nothing to do"}
	}
	if n := c["actionsWaiting"]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d waiting for a fix", n))
	}
	return verdictMarks[code] + " " + strings.Join(parts, ", ")
}

var urgencyTitles = map[string]string{UrgencyNow: "Do now", UrgencySoon: "Do this week", UrgencyRoutine: "Routine updates", UrgencyUnassessed: "Not assessed", UrgencyWaiting: "Waiting for a fix"}

// waitingLine says since when a card has had no fixed release, and what happens next.
func waitingLine(c Card) string {
	w, day := c.Waiting, "2006-01-02"
	switch {
	case c.Urgency != UrgencyWaiting:
		return fmt.Sprintf("No fixed release for %d days, since %s.", c.waited, w.Since.UTC().Format(day))
	case w.Until != nil:
		return fmt.Sprintf("No fixed release since %s. Kept waiting until %s.", w.Since.UTC().Format(day), w.Until.UTC().Format(day))
	}
	return fmt.Sprintf("No fixed release since %s. Without one, this comes back on %s.", w.Since.UTC().Format(day), w.Since.UTC().AddDate(0, 0, audit.WaitingDays).Format(day))
}

// codeSpan is a command as Markdown code, so that it prints as it is typed: fenced by more
// backticks than any run of them in it.
func codeSpan(s string) string {
	s = clean(s)
	longest, run := 0, 0
	for _, r := range s {
		if r != '`' {
			run = 0
			continue
		}
		run++
		longest = max(longest, run)
	}
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		s = " " + s + " "
	}
	fence := strings.Repeat("`", longest+1)
	return fence + s + fence
}

// writeActions prints the cards: per card its title, what changes, and the steps.
func writeActions(b *strings.Builder, cards []Card) {
	if len(cards) == 0 {
		return
	}
	b.WriteString("## Actions\n\n")
	for _, u := range urgencies {
		var of []Card
		for _, c := range cards {
			if c.Urgency == u {
				of = append(of, c)
			}
		}
		if len(of) == 0 {
			continue
		}
		fmt.Fprintf(b, "### %s (%d)\n\n", urgencyTitles[u], len(of))
		for i, c := range of {
			if i == maxEntries {
				fmt.Fprintf(b, "- … and %d more, in the JSON report.\n", len(of)-i)
				break
			}
			fmt.Fprintf(b, "- **%s**", escapeBlockStart(md(c.Title)))
			var about []string
			if c.Name != "" && !strings.Contains(c.Title, c.Name) {
				about = append(about, md(c.Name))
			}
			if c.Reach != "" {
				about = append(about, reachWords[c.Reach]+viaWords[c.Via])
			}
			if len(about) > 0 {
				b.WriteString(" (" + strings.Join(about, "; ") + ")")
			}
			var changes []string
			for _, ch := range c.Changes {
				switch {
				case ch.To == "" && ch.Needs == "":
					changes = append(changes, md(ch.Name+" "+ch.From)+", no fix yet")
				case ch.To == "":
					changes = append(changes, md(ch.Name+" "+ch.From)+", fixed in "+md(ch.Needs))
				case ch.Needs != "":
					changes = append(changes, md(ch.Name+" "+ch.From)+" → "+md(ch.To)+" (fixed in "+md(ch.Needs)+")")
				default:
					changes = append(changes, md(ch.Name+" "+ch.From)+" → "+md(ch.To))
				}
			}
			switch {
			case c.MoreChanges > 0 && len(changes) == 0:
				changes = append(changes, plural(c.MoreChanges, "package affected", "packages affected"))
			case c.MoreChanges > 0:
				changes = append(changes, fmt.Sprintf("and %d more", c.MoreChanges))
			}
			if len(changes) > 0 {
				b.WriteString(": " + strings.Join(changes, "; "))
			}
			b.WriteString("\n")
			if c.Kind == audit.ActionImage {
				b.WriteString("  - " + md(updateLine(c.Update)) + "\n")
			}
			if c.Waiting != nil && (c.Urgency == UrgencyWaiting || c.Waiting.Overdue) {
				b.WriteString("  - " + waitingLine(c) + "\n")
			}
			also, step := "Also", "Step"
			if c.Urgency == UrgencyWaiting {
				also, step = "Meanwhile", "If no fix comes, step"
			}
			for _, a := range c.Also {
				b.WriteString("  - " + also + ": " + escapeBlockStart(md(a)) + "\n")
			}
			for n, s := range c.Steps {
				fmt.Fprintf(b, "  - %s %d: %s", step, n+1, md(s.Text))
				if s.Command != "" {
					b.WriteString(": " + codeSpan(s.Command))
				}
				b.WriteString("\n")
			}
			switch {
			case !c.Reviewed:
				b.WriteString("  - Not reviewed: these are the default steps.\n")
			case c.Upstream.State == review.UpstreamNone:
				b.WriteString("  - Upstream has no fixed release yet" + upstreamNote(c.Upstream) + "\n")
			case c.Upstream.Note != "" || c.Upstream.Source != "":
				b.WriteString("  - Upstream" + upstreamNote(c.Upstream) + "\n")
			}
		}
		b.WriteString("\n")
	}
}

func upstreamNote(u review.Upstream) string {
	s := ""
	if u.Note != "" {
		s += ": " + md(u.Note)
	}
	if u.Source != "" && !strings.ContainsFunc(u.Source, unsafeURLRune) {
		s += " (" + u.Source + ")"
	}
	return s + "."
}
