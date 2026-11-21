package report

import (
	"reflect"
	"strings"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/facts"
	"github.com/klar-web-services/tripcoil/internal/review"
)

// reachInput is cardInput with the reach facts and a review that settled them: nginx is public, the
// shop is behind a firewall rule, the api is on the LAN, the worker was not looked at, and the
// container's routing could not be read. The api's added finding needs a connection, so the rule
// lowered it.
func reachInput() Input {
	in := cardInput()
	in.Reach = &facts.Reach{Items: []facts.ItemReach{
		{Item: "proc:nginx", Default: facts.ReachInternet, Via: facts.ViaDirect, Sockets: []facts.ReachSocket{{Proto: "tcp", Address: "0.0.0.0", Port: 443, Reach: facts.ReachInternet}}},
		{Item: "proc:shop", Default: facts.ReachInternet, Via: facts.ViaDirect, Sockets: []facts.ReachSocket{{Proto: "tcp", Address: "0.0.0.0", Port: 8443, Reach: facts.ReachInternet}}},
		{Item: "proc:api", Default: facts.ReachLAN, Via: facts.ViaDirect, Stated: true, Sockets: []facts.ReachSocket{{Proto: "tcp", Address: "0.0.0.0", Port: 8080, Reach: facts.ReachLAN}}},
		{Item: "proc:worker", Default: facts.ReachLocalhost, Via: facts.ViaDirect, Sockets: []facts.ReachSocket{{Proto: "tcp", Address: "127.0.0.1", Port: 9000, Reach: facts.ReachLocalhost}}},
	}, Routers: []facts.Router{{Item: "proc:nginx", Program: "nginx", Kind: facts.ViaProxy, Reach: facts.ReachInternet}}}
	in.Review.Reach = []review.ReachEntry{
		{Item: "proc:nginx", From: facts.ReachInternet, Via: facts.ViaDirect, Evidence: []string{"facts/firewall.txt: tcp dport 443 accept", "facts/addresses.json: eth0 203.0.113.5 is global"}},
		{Item: "proc:shop", From: facts.ReachTailnet, Via: facts.ViaDirect, Evidence: []string{"facts/firewall.txt: tcp dport 8443 drop on eth0"}},
		{Item: "proc:api", From: facts.ReachInternet, Via: facts.ViaForward, Evidence: []string{"the api's certificate names api.example.org"}},
		{Item: "container:shop-web-1", From: facts.ReachUnknown, Evidence: []string{"/etc/nginx/conf.d is readable by root only"}},
	}
	for i := range in.Review.Findings {
		e := &in.Review.Findings[i]
		switch e.FindingID {
		case "f:0000000000000001", "added:1":
			e.Vector = review.VectorInbound
		case "f:0000000000000002":
			e.Vector = review.VectorLocal
		}
	}
	review.ApplyReach(in.Review, in.Audit, in.Reach, "lower")
	return in
}

func TestReaches(t *testing.T) {
	var got []string
	for _, l := range Reaches(reachInput()) {
		got = append(got, l.Item+" "+l.From+" "+l.Via+" "+l.Source+": "+l.Evidence)
	}
	want := []string{
		"nginx internet direct review: facts/firewall.txt: tcp dport 443 accept",
		"shop-web-1 unknown  review: /etc/nginx/conf.d is readable by root only",
		// The owner stated the public ports and 8080 is not among them: the reviewer cannot widen it.
		"api lan direct config: exposure.internetPorts does not list its ports; the reviewer said internet",
		"node tailnet direct review: facts/firewall.txt: tcp dport 8443 drop on eth0",
		"python3.11 localhost direct default: tcp 127.0.0.1 port 9000",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("\n got %s\nwant %s", strings.Join(got, "\n     "), strings.Join(want, "\n     "))
	}

	// Without a review the defaults are all there is; an item nothing reaches is left out.
	in := reachInput()
	in.Review, in.Run.Reviewed, in.NoReview = nil, false, "review.agent is none"
	in.Reach.Items = append(in.Reach.Items, facts.ItemReach{Item: "kernel", Default: facts.ReachNone})
	lines := Reaches(in)
	if len(lines) != 4 || lines[0].Item != "nginx" || lines[0].Source != ReachFromDefault || lines[2].Item != "api" || lines[2].Source != ReachFromConfig {
		t.Errorf("audit only: %+v", lines)
	}
	// A default that is in doubt is not established, whatever the owner stated about its ports.
	in.Reach.Items[2].Unsure = "nginx runs here"
	if l := Reaches(in)[2]; l.Item != "api" || l.From != facts.ReachUnknown || l.Source != ReachFromDefault {
		t.Errorf("a stated default in doubt: %+v", l)
	}
	in.Reach = nil
	if len(Reaches(in)) != 0 {
		t.Error("no fact, no lines")
	}
	// A review with entries but no fact: nothing is established, and nothing was held back by the owner.
	lost := reachInput()
	lost.Reach = nil
	for _, l := range Reaches(lost) {
		if l.From != facts.ReachUnknown || l.Source != ReachFromReview {
			t.Errorf("without the fact: %+v", l)
		}
	}
	many := reachInput()
	for i := 0; i < 300; i++ {
		many.Reach.Items = append(many.Reach.Items, facts.ItemReach{Item: "proc:x" + strings.Repeat("y", i), Default: facts.ReachLAN})
	}
	if lines := Reaches(many); len(lines) != MaxReachLines || lines[0].Item != "nginx" {
		t.Errorf("%d lines, first %+v", len(lines), lines[0])
	}
}

func TestCardsCarryTheirReach(t *testing.T) {
	got := map[string]string{}
	for _, c := range Cards(reachInput()) {
		got[c.Kind+" "+c.Urgency] = strings.TrimSpace(c.Reach + " " + c.Via)
	}
	// The system's packages are used by nginx, the shop and the worker: public through nginx. The
	// api's finding was lowered for the LAN, so its card is routine. The kernel has no reach, and the
	// image's container is not established.
	want := map[string]string{"packages now": "internet direct", "finding routine": "lan direct", "kernel soon": "", "image unassessed": "unknown"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("\n got %v\nwant %v", got, want)
	}
	for _, c := range Cards(cardInput()) {
		if c.Reach != "" || c.Via != "" {
			t.Errorf("without the reach fact a card has no reach: %+v", c)
		}
	}
	in := reachInput()
	in.Review, in.Run.Reviewed, in.NoReview = nil, false, "review.agent is none"
	for _, c := range Cards(in) {
		if c.Reach != "" {
			t.Errorf("without a review no reach is established: %+v", c)
		}
	}
}

func TestCardReach(t *testing.T) {
	est := map[string]review.ReachEntry{"a": {From: facts.ReachTailnet, Via: facts.ViaDirect}, "b": {From: facts.ReachLAN, Via: facts.ViaProxy}, "c": {From: facts.ReachInternet, Via: facts.ViaTunnel}}
	for name, tc := range map[string]struct {
		items     []string
		from, via string
	}{
		"the widest":                 {[]string{"a", "b"}, facts.ReachLAN, facts.ViaProxy},
		"one not established":        {[]string{"a", "x"}, facts.ReachUnknown, ""},
		"the internet beats unknown": {[]string{"x", "c", "a"}, facts.ReachInternet, facts.ViaTunnel},
		"no items":                   {nil, facts.ReachUnknown, ""},
	} {
		if from, via := cardReach(tc.items, est, nil, nil); from != tc.from || via != tc.via {
			t.Errorf("%s: %s %s", name, from, via)
		}
	}
	// An item that listens nowhere ("y") does not make a card's reach unknown, unless a proxy or tunnel
	// runs that could publish it. An item with sockets that the reviewer left out ("x") always does.
	quiet := &facts.Reach{Items: []facts.ItemReach{{Item: "x", Default: facts.ReachLAN}}}
	if from, via := cardReach([]string{"a", "y"}, est, quiet, nil); from != facts.ReachTailnet || via != facts.ViaDirect {
		t.Errorf("an item without sockets: %s %s", from, via)
	}
	if from, _ := cardReach([]string{"a", "x"}, est, quiet, nil); from != facts.ReachUnknown {
		t.Errorf("an item with sockets and no entry: %s", from)
	}
	// The reviewer wrote an entry for "y" that established nothing: the card must not call it unreachable.
	if from, _ := cardReach([]string{"a", "y"}, est, quiet, map[string]bool{"y": true}); from != facts.ReachUnknown {
		t.Errorf("an item the reviewer could not settle: %s", from)
	}
	quiet.Routers = []facts.Router{{Item: "p", Program: "caddy", Reach: facts.ReachLAN}}
	if from, _ := cardReach([]string{"a", "y"}, est, quiet, nil); from != facts.ReachUnknown {
		t.Errorf("an item without sockets beside a proxy: %s", from)
	}
}

func TestRenderReviewedWithReach(t *testing.T) {
	md := Render(reachInput())
	golden(t, "reviewed-reach", md)
	for _, want := range []string{
		"- **Update libssl3** (System packages; reachable from the internet): ",
		"## Who can reach what\n\n- nginx: reachable from the internet (the reviewer): facts/firewall.txt: tcp dport 443 accept\n",
		"- api: reachable from the LAN (the owner's statement): exposure.internetPorts does not list its ports; the reviewer said internet\n",
		"- python3.11: reachable from this machine only (Tripcoil's default, not reviewed): tcp 127.0.0.1 port 9000\n",
		"  - Lowered by Tripcoil: reachable from the LAN; the reviewer said exploitable, now\n",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("the report lacks %q", want)
		}
	}
	if strings.Contains(Render(cardInput()), "Who can reach what") {
		t.Error("a report without the reach fact has no such section")
	}
}

func TestJSONCarriesReach(t *testing.T) {
	out := JSON(reachInput())
	if len(out.Reach) != 5 || out.Reach[0].Item != "nginx" {
		t.Fatalf("reach %+v", out.Reach)
	}
	var added review.Entry
	for _, e := range out.Added {
		added = e
	}
	if added.Vector != review.VectorInbound || added.Adjusted == nil || added.Adjusted.Rule != facts.ReachLAN || added.Exploitability != review.Conditional {
		t.Errorf("the added finding carries its vector and what the rule did: %+v", added)
	}
	if out := JSON(cardInput()); out.Reach == nil || len(out.Reach) != 0 {
		t.Errorf("a run without the fact has an empty list: %+v", out.Reach)
	}
}
