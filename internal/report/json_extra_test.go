package report

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestJSONNamesHostAndFreshness(t *testing.T) {
	r := record(map[string]string{"inventory": "ok", "audit": "ok", "review": "ok"})
	in := Input{Run: r, Inventory: hostInventory(), Audit: hostAudit(), Review: hostReview()}
	out := JSON(in)
	if out.Host == nil || out.Host.Hostname == "" || out.Freshness == nil || out.Freshness.Grype == "" {
		t.Fatalf("host %+v freshness %+v", out.Host, out.Freshness)
	}
	for _, f := range out.Findings {
		if _, ok := out.Names.Origins[f.Origin]; !ok {
			t.Errorf("origin %s of %s has no name", f.Origin, f.ID)
		}
		for _, id := range f.Items {
			if out.Names.Items[id] == "" {
				t.Errorf("item %s of %s has no name", id, f.ID)
			}
		}
	}
	if out.Verdict.Code == "" || out.Verdict.Line != "" {
		t.Errorf("without a stored verdict: %+v", out.Verdict)
	}
	v := VerdictOf(in, Render(in))
	r.Verdict = &v
	if got := JSON(in).Verdict; got.Line != v.Line || got.Code != v.Code {
		t.Errorf("stored verdict not used: %+v", got)
	}
}

func TestPayloadTrimsFindingsButNotTheAudit(t *testing.T) {
	aud := hostAudit()
	aud.Findings[0].Vulnerability.Description = "long advisory text"
	aud.Findings[0].Package.CPEs = []string{"cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"}
	aud.Findings[0].Raw = "raw/abc.grype.json"
	r := record(map[string]string{"inventory": "ok", "audit": "ok"})
	data, _ := json.Marshal(Payload(Input{Run: r, Inventory: hostInventory(), Audit: aud}))
	if s := string(data); strings.Contains(s, "long advisory text") || strings.Contains(s, "cpe:2.3") || strings.Contains(s, "raw/abc") {
		t.Errorf("payload not trimmed: %s", s[:200])
	}
	if aud.Findings[0].Vulnerability.Description == "" || len(aud.Findings[0].Package.CPEs) != 1 {
		t.Error("Payload changed the audit")
	}
	data, _ = json.Marshal(JSON(Input{Run: r, Inventory: hostInventory(), Audit: aud}))
	if !strings.Contains(string(data), "long advisory text") {
		t.Error("JSON lost the description")
	}
}
