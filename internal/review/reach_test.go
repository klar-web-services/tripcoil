package review

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/config"
	"github.com/klar-web-services/tripcoil/internal/facts"
)

func reachEntry(over map[string]any) map[string]any {
	e := map[string]any{"item": "proc:aaaa", "from": "tailnet", "via": "direct", "evidence": []string{"facts/firewall.txt: tcp dport 3000 drop on eth0"}}
	for k, v := range over {
		if v == "DELETE" {
			delete(e, k)
		} else {
			e[k] = v
		}
	}
	return e
}

func withReach(reach ...map[string]any) []byte {
	data, _ := json.Marshal(map[string]any{"summary": "s", "findings": []any{entry(nil)}, "coverageNotes": []string{}, "actions": []any{}, "reach": reach})
	return data
}

func TestValidateReach(t *testing.T) {
	aud, inv := fixtureAudit()
	r, warns, err := Validate(withReach(reachEntry(nil), reachEntry(map[string]any{"item": "proc:bbbb", "from": "unknown", "via": nil,
		"evidence": []string{"  the tunnel's configuration\tis not readable\n", "", "two", "three", "four"}})), nil, aud, inv)
	if err != nil || len(warns) != 0 {
		t.Fatalf("%v %+v", err, warns)
	}
	want := []ReachEntry{
		{Item: "proc:aaaa", From: "tailnet", Via: "direct", Evidence: []string{"facts/firewall.txt: tcp dport 3000 drop on eth0"}},
		{Item: "proc:bbbb", From: "unknown", Evidence: []string{"the tunnel's configuration is not readable", "two", "three"}},
	}
	if !reflect.DeepEqual(r.Reach, want) {
		t.Errorf("reach:\n got %+v\nwant %+v", r.Reach, want)
	}

	long := strings.Repeat("é", 150)
	r, _, err = Validate(withReach(reachEntry(map[string]any{"evidence": []string{long}})), nil, aud, inv)
	if err != nil || len(r.Reach[0].Evidence[0]) > MaxEvidenceLine || !strings.HasSuffix(r.Reach[0].Evidence[0], "…") {
		t.Errorf("a long evidence line is cut: %v %+v", err, r.Reach)
	}
}

func TestValidateDropsReach(t *testing.T) {
	aud, inv := fixtureAudit()
	for name, tc := range map[string]struct {
		entry map[string]any
		why   string
	}{
		"an unknown item":     {reachEntry(map[string]any{"item": "proc:gone"}), "inventory.json has no such item"},
		"a wrong from":        {reachEntry(map[string]any{"from": "everywhere"}), `from "everywhere" is not one of`},
		"a wrong via":         {reachEntry(map[string]any{"via": "magic"}), `via "magic" is not one of`},
		"no evidence":         {reachEntry(map[string]any{"evidence": []string{" ", "\n"}}), "it has no evidence"},
		"evidence not a list": {reachEntry(map[string]any{"evidence": "the firewall"}), "reach[0]"},
		"a missing key":       {reachEntry(map[string]any{"via": "DELETE"}), `lacks "via"`},
		"an unknown key":      {reachEntry(map[string]any{"port": 3000}), `unknown key "port"`},
	} {
		r, warns, err := Validate(withReach(tc.entry), nil, aud, inv)
		if err != nil {
			t.Fatalf("%s: a broken reach entry must not fail the review: %v", name, err)
		}
		if len(r.Reach) != 0 || len(warns) != 1 || warns[0].Code != "REVIEW_ENTRIES_DROPPED" || !strings.Contains(warns[0].Message, tc.why) {
			t.Errorf("%s: reach %+v, warnings %+v", name, r.Reach, warns)
		}
	}
	r, warns, err := Validate(withReach(reachEntry(nil), reachEntry(map[string]any{"from": "internet"})), nil, aud, inv)
	if err != nil || len(r.Reach) != 1 || r.Reach[0].From != "tailnet" || len(warns) != 1 || !strings.Contains(warns[0].Message, "it addresses an item twice") {
		t.Errorf("the first entry of an item counts: %v %+v %+v", err, r.Reach, warns)
	}
}

// A script that forgets the two new keys must not cost its entries, in the result or in the file.
func TestValidateVectorAndReachOfAnEntry(t *testing.T) {
	aud, inv := fixtureAudit()
	for name, tc := range map[string]struct {
		over          map[string]any
		vector, reach string
	}{
		"both set":          {map[string]any{"vector": "inbound", "reach": "tailnet"}, "inbound", "tailnet"},
		"both null":         {map[string]any{"vector": nil, "reach": nil}, "", ""},
		"both missing":      {nil, "", ""},
		"unknown values":    {map[string]any{"vector": "remote", "reach": "internet"}, "", ""},
		"content, no reach": {map[string]any{"vector": "content", "reach": nil}, "content", ""},
	} {
		for _, where := range []string{"result", "file"} {
			data, _ := json.Marshal(map[string]any{"summary": "s", "findings": []any{entry(tc.over)}, "coverageNotes": []string{}, "actions": []any{}, "reach": []any{}})
			var file []byte
			if where == "file" {
				file, _ = json.Marshal(entry(tc.over))
				data, _ = json.Marshal(map[string]any{"summary": "s", "findings": []any{}, "coverageNotes": []string{}, "actions": []any{}, "reach": []any{}})
			}
			r, warns, err := Validate(data, file, aud, inv)
			if err != nil || len(warns) != 0 || len(r.Findings) != 1 || r.Findings[0].Vector != tc.vector || r.Findings[0].Reach != tc.reach {
				t.Errorf("%s in the %s: %v %+v %+v", name, where, err, warns, r)
			}
		}
	}
}

func TestCarryReach(t *testing.T) {
	aud, inv := fixtureAudit()
	prev := &Review{Summary: "s", Findings: []Entry{{FindingID: "f:0000000000000001", Verdict: Confirmed}},
		Reach: []ReachEntry{{Item: "proc:aaaa", From: "tailnet", Evidence: []string{"e"}}, {Item: "proc:gone", From: "internet", Evidence: []string{"e"}}}}
	r := Carry(prev, aud, inv)
	if len(r.Reach) != 1 || r.Reach[0].Item != "proc:aaaa" {
		t.Errorf("reach %+v", r.Reach)
	}
	if r := Carry(&Review{Summary: "s"}, aud, inv); r.Reach == nil {
		t.Error("a review from before prompt 5 carries a null list")
	}
}

// reachCase is one finding on proc:aaaa (and proc:bbbb when two), judged exploitable and "now".
type reachCase struct {
	vector, own  string // the entry's vector and its own reach
	bare         bool   // the entry has no evidence
	added        bool   // a finding the review added, on proc:aaaa
	a, b         string // what the reviewer wrote for the two items; "" for no entry
	two, kernel  bool
	noFact       bool
	lan          string
	exploit, pri string // what must come out
	rule         string // the reach it was lowered for; "" when it must stay untouched
}

func (tc reachCase) run() (*Review, int) {
	aud, _ := fixtureAudit()
	aud.Actions = []audit.Action{{ID: "a:1", Kind: audit.ActionImage}, {ID: "a:k", Kind: audit.ActionKernel}}
	aud.Findings[0].Action, aud.Findings[0].Items = "a:1", []string{"proc:aaaa"}
	if tc.two {
		aud.Findings[0].Items = []string{"proc:aaaa", "proc:bbbb"}
	}
	if tc.kernel {
		aud.Findings[0].Action = "a:k"
	}
	rev := &Review{Findings: []Entry{{FindingID: "f:0000000000000001", Verdict: Confirmed, Exploitability: Exploitable, Priority: "now",
		Vector: tc.vector, Reach: tc.own, Evidence: []string{"dokploy.yml: ipAllowList 100.64.0.0/10"}}}}
	if tc.bare {
		rev.Findings[0].Evidence = nil
	}
	if tc.added {
		rev.Findings[0].FindingID, rev.Findings[0].Verdict, rev.Findings[0].Item = "added:1", Added, "proc:aaaa"
	}
	if tc.kernel {
		aud.Actions[1].Items = []string{"proc:aaaa"}
	}
	for item, from := range map[string]string{"proc:aaaa": tc.a, "proc:bbbb": tc.b} {
		if from != "" {
			rev.Reach = append(rev.Reach, ReachEntry{Item: item, From: from, Via: facts.ViaDirect, Evidence: []string{"e"}})
		}
	}
	def := &facts.Reach{Items: []facts.ItemReach{{Item: "proc:aaaa", Default: facts.ReachLocalhost}, {Item: "proc:bbbb", Default: facts.ReachLocalhost}}}
	if tc.noFact {
		def = nil
	}
	lan := tc.lan
	if lan == "" {
		lan = config.LANLower
	}
	return rev, ApplyReach(rev, aud, def, lan)
}

func TestApplyReach(t *testing.T) {
	for name, tc := range map[string]reachCase{
		// The rule's rows.
		"internet":          {vector: "inbound", a: "internet", exploit: Exploitable, pri: "now"},
		"lan":               {vector: "inbound", a: "lan", exploit: Conditional, pri: "scheduled", rule: "lan"},
		"lan, trusted":      {vector: "inbound", a: "lan", lan: config.LANTrusted, exploit: NotExploitable, pri: "none", rule: "lan"},
		"lan, untrusted":    {vector: "inbound", a: "lan", lan: config.LANUntrusted, exploit: Exploitable, pri: "now"},
		"tailnet":           {vector: "inbound", a: "tailnet", exploit: NotExploitable, pri: "none", rule: "tailnet"},
		"localhost":         {vector: "inbound", a: "localhost", exploit: NotExploitable, pri: "none", rule: "localhost"},
		"none":              {vector: "inbound", a: "none", exploit: NotExploitable, pri: "none", rule: "none"},
		"the widest of two": {vector: "inbound", two: true, a: "tailnet", b: "lan", exploit: Conditional, pri: "scheduled", rule: "lan"},
		"two, one public":   {vector: "inbound", two: true, a: "tailnet", b: "internet", exploit: Exploitable, pri: "now"},
		// A finding's own reach: narrower than its item's, with evidence.
		"behind an allow-list":   {vector: "inbound", own: "tailnet", a: "internet", exploit: NotExploitable, pri: "none", rule: "tailnet"},
		"own reach is not wider": {vector: "inbound", own: "lan", a: "tailnet", exploit: NotExploitable, pri: "none", rule: "tailnet"},
		"own reach, no evidence": {vector: "inbound", own: "tailnet", a: "internet", bare: true, exploit: Exploitable, pri: "now"},
		"an added finding":       {vector: "inbound", added: true, a: "tailnet", exploit: NotExploitable, pri: "none", rule: "tailnet"},
		// Never on missing information.
		"a default only":          {vector: "inbound", exploit: Exploitable, pri: "now"},
		"unknown":                 {vector: "inbound", a: "unknown", exploit: Exploitable, pri: "now"},
		"one of two not settled":  {vector: "inbound", two: true, a: "tailnet", exploit: Exploitable, pri: "now"},
		"own reach, item unknown": {vector: "inbound", own: "tailnet", a: "unknown", exploit: Exploitable, pri: "now"},
		"no reach fact":           {vector: "inbound", a: "tailnet", noFact: true, exploit: Exploitable, pri: "now"},
		"the kernel":              {vector: "inbound", a: "tailnet", kernel: true, exploit: Exploitable, pri: "now"},
		"added, on the kernel":    {vector: "inbound", added: true, a: "tailnet", kernel: true, exploit: Exploitable, pri: "now"},
		// Only an inbound finding depends on who can connect.
		"content":   {vector: "content", a: "localhost", exploit: Exploitable, pri: "now"},
		"local":     {vector: "local", a: "localhost", exploit: Exploitable, pri: "now"},
		"no vector": {a: "localhost", exploit: Exploitable, pri: "now"},
	} {
		rev, n := tc.run()
		e := rev.Findings[0]
		if e.Exploitability != tc.exploit || e.Priority != tc.pri {
			t.Errorf("%s: %s, %s; want %s, %s", name, e.Exploitability, e.Priority, tc.exploit, tc.pri)
		}
		switch {
		case tc.rule == "" && (e.Adjusted != nil || n != 0):
			t.Errorf("%s: must stay untouched: %+v, %d changed", name, e.Adjusted, n)
		case tc.rule != "" && (n != 1 || e.Adjusted == nil || *e.Adjusted != Adjusted{Exploitability: Exploitable, Priority: "now", Rule: tc.rule}):
			t.Errorf("%s: adjusted %+v, %d changed", name, e.Adjusted, n)
		}
	}
}

func TestApplyReachLeavesTheRestAlone(t *testing.T) {
	aud, _ := fixtureAudit()
	aud.Findings[0].Items, aud.Findings[1].Items, aud.Findings[2].Items = []string{"proc:aaaa"}, []string{"proc:aaaa"}, []string{"proc:aaaa"}
	rev := &Review{Reach: []ReachEntry{{Item: "proc:aaaa", From: "lan", Evidence: []string{"e"}}}, Findings: []Entry{
		{FindingID: "f:0000000000000001", Verdict: Confirmed, Exploitability: NotExploitable, Priority: "none", Vector: VectorInbound},
		{FindingID: "f:0000000000000002", Verdict: FalsePositive},
		{FindingID: "f:0000000000000003", Verdict: Confirmed, Exploitability: Conditional, Priority: "scheduled", Vector: VectorInbound},
		{FindingID: "added:1", Verdict: Added, Item: "proc:aaaa", Exploitability: Conditional, Priority: "soon", Vector: VectorInbound},
	}}
	def := &facts.Reach{Items: []facts.ItemReach{{Item: "proc:aaaa", Default: facts.ReachLAN}}}
	if n := ApplyReach(rev, aud, def, config.LANLower); n != 1 {
		t.Errorf("%d changed, want the added finding only", n)
	}
	for _, e := range rev.Findings[:3] {
		if e.Adjusted != nil {
			t.Errorf("%s: what the rule would not change is not marked: %+v", e.FindingID, e.Adjusted)
		}
	}
	if e := rev.Findings[3]; e.Priority != "scheduled" || e.Adjusted == nil || e.Adjusted.Priority != "soon" {
		t.Errorf("an added finding goes by its item: %+v", e)
	}
	if ApplyReach(nil, aud, def, config.LANLower) != 0 {
		t.Error("no review, nothing to do")
	}

	// The kernel item is never lowered, also for a finding the review added and when the audit has
	// no kernel action.
	onKernel := &Review{Reach: []ReachEntry{{Item: "kernel", From: "tailnet", Evidence: []string{"e"}}}, Findings: []Entry{
		{FindingID: "added:1", Verdict: Added, Item: "kernel", Exploitability: Exploitable, Priority: "now", Vector: VectorInbound}}}
	if n := ApplyReach(onKernel, aud, def, config.LANLower); n != 0 || onKernel.Findings[0].Exploitability != Exploitable {
		t.Errorf("an added finding on the kernel was lowered: %+v", onKernel.Findings[0])
	}
}

// Applying the rule again starts from what the reviewer said: after a carry-forward, and when the
// owner changes exposure.lan or the reviewer's entry is no longer there.
func TestApplyReachAgain(t *testing.T) {
	tc := reachCase{vector: "inbound", a: "lan"}
	rev, _ := tc.run()
	aud, inv := fixtureAudit()
	aud.Findings[0].Items = []string{"proc:aaaa"}
	def := &facts.Reach{Items: []facts.ItemReach{{Item: "proc:aaaa", Default: facts.ReachLAN}}}
	want := Adjusted{Exploitability: Exploitable, Priority: "now", Rule: "lan"}
	for i := 0; i < 2; i++ {
		rev = Carry(rev, aud, inv)
		if n := ApplyReach(rev, aud, def, config.LANLower); n != 1 || rev.Findings[0].Exploitability != Conditional || rev.Findings[0].Priority != "scheduled" || *rev.Findings[0].Adjusted != want {
			t.Fatalf("pass %d: %d changed, %+v", i, n, rev.Findings[0])
		}
	}
	if ApplyReach(rev, aud, def, config.LANTrusted); rev.Findings[0].Exploitability != NotExploitable || *rev.Findings[0].Adjusted != want {
		t.Errorf("trusted: %+v", rev.Findings[0])
	}
	if n := ApplyReach(rev, aud, def, config.LANUntrusted); n != 0 || rev.Findings[0].Exploitability != Exploitable || rev.Findings[0].Priority != "now" || rev.Findings[0].Adjusted != nil {
		t.Errorf("untrusted gives the reviewer's values back: %+v", rev.Findings[0])
	}
	ApplyReach(rev, aud, def, config.LANLower)
	if n := ApplyReach(rev, aud, nil, config.LANLower); n != 0 || rev.Findings[0].Exploitability != Exploitable || rev.Findings[0].Adjusted != nil {
		t.Errorf("without the fact the reviewer's values come back: %+v", rev.Findings[0])
	}
}

// Where the owner stated the public ports, the reviewer may narrow an item's reach, not widen it
// through the machine's own ports.
func TestEstablishedWithAStatement(t *testing.T) {
	def := &facts.Reach{Items: []facts.ItemReach{
		{Item: "a", Default: facts.ReachLAN, Stated: true}, {Item: "b", Default: facts.ReachLAN, Stated: true},
		{Item: "c", Default: facts.ReachLAN, Stated: true}, {Item: "d", Default: facts.ReachLAN, Stated: true},
		{Item: "e", Default: facts.ReachLAN}, {Item: "f", Default: facts.ReachLAN},
		{Item: "g", Default: facts.ReachLAN, Stated: true, Unsure: "caddy runs here"}, {Item: "h", Default: facts.ReachLAN, Stated: true, Unsure: "caddy runs here"},
	}}
	rev := &Review{Reach: []ReachEntry{
		{Item: "a", From: "internet", Via: facts.ViaDirect}, {Item: "b", From: "internet", Via: facts.ViaForward},
		{Item: "c", From: "internet", Via: facts.ViaTunnel}, {Item: "d", From: "tailnet", Via: facts.ViaDirect},
		{Item: "e", From: "internet", Via: facts.ViaForward}, {Item: "f", From: "unknown"},
		{Item: "g", From: "internet", Via: facts.ViaDirect}, {Item: "h", From: "tailnet", Via: facts.ViaDirect},
	}}
	got := map[string]string{}
	for item, e := range Established(rev, def) {
		got[item] = e.From + " " + e.Via
	}
	// What the statement holds back is the item's own reach again, not the forward the reviewer assumed.
	// "g" would be held back too, but a proxy may publish it: holding it back would call it narrow on
	// no evidence, so it is not established at all. "h" is the reviewer's own narrowing and stands.
	want := map[string]string{"a": "lan direct", "b": "lan direct", "c": "internet tunnel", "d": "tailnet direct", "e": "internet forward", "h": "tailnet direct"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("\n got %v\nwant %v", got, want)
	}
	if len(Established(rev, nil)) != 0 || len(Established(nil, def)) != 0 {
		t.Error("without the fact or the review nothing is established")
	}
}

func TestPromptExplainsReach(t *testing.T) {
	for _, want := range []string{"Establish who can reach each item", "`facts/reach.json`", "`addresses.json`", "When more than one applies, or in doubt, `content`",
		"A protection that is already in place is no measure", "leave `reach` empty", "A proxy or tunnel still widens it", "`routers` lists a program that is not `complete`",
		"Do not write a `from` narrower than the reach of a program that routes to the item", "`routes.json` (what the proxies and tunnels that run here route to",
		"resolve only to private or tailnet addresses are evidence that there is no forward", "`resolved`"} {
		if !strings.Contains(Prompt, want) {
			t.Errorf("the prompt lacks %q", want)
		}
	}
}

// The route facts name who may call a target, and the summary says of a service what they show.
func TestPromptExplainsRouteLimitsAndTheSummary(t *testing.T) {
	for _, want := range []string{"a target also has `routes`", "`allow`", "none means every caller", "`redirect`", "100.64.0.0/10 and fd7a:115c:a1e0::/48",
		"A target without `routes` says nothing about callers",
		"7. Write the `summary`", "is not public", "Never mention a false positive, not even a critical or known-exploited one"} {
		if !strings.Contains(Prompt, want) {
			t.Errorf("the prompt lacks %q", want)
		}
	}
}

// Whether data from a source the owner chose is an attack is settled once, not anew by every review.
func TestPromptSettlesContentFromChosenSources(t *testing.T) {
	for _, want := range []string{"takes data from anyone in normal use", "only from sources the owner chose", "needs one of those sources to turn hostile", "that is `conditional`"} {
		if !strings.Contains(Prompt, want) {
			t.Errorf("the prompt lacks %q", want)
		}
	}
}
