package report

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestJSON(t *testing.T) {
	r := record(map[string]string{"inventory": "ok", "audit": "ok", "review": "ok"})
	data, err := json.Marshal(JSON(Input{Run: r, Inventory: hostInventory(), Audit: hostAudit(), Review: hostReview()}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Run      map[string]any   `json:"run"`
		Summary  string           `json:"summary"`
		Findings []map[string]any `json:"findings"`
		Added    []map[string]any `json:"added"`
		Coverage []map[string]any `json:"coverage"`
		Errors   []any            `json:"errors"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Run["runId"] != "20261114T061500Z-3fa2" || !strings.HasPrefix(got.Summary, "nginx's TLS") || len(got.Findings) != 7 || len(got.Added) != 1 || len(got.Coverage) != 4 || got.Errors == nil {
		t.Fatalf("%s", data)
	}
	byID := map[string]map[string]any{}
	for _, f := range got.Findings {
		byID[f["id"].(string)] = f
	}
	if rv := byID["f:0000000000000001"]["review"].(map[string]any); rv["exploitability"] != "exploitable" || byID["f:0000000000000001"]["remediation"] == "" {
		t.Errorf("%v", byID["f:0000000000000001"])
	}
	if rv := byID["f:0000000000000006"]["review"].(map[string]any); rv["verdict"] != "not_reviewed" {
		t.Errorf("%v", rv)
	}

	data, _ = json.Marshal(JSON(Input{Run: r, Inventory: hostInventory(), Audit: hostAudit()}))
	if !strings.Contains(string(data), `"summary":null`) || !strings.Contains(string(data), `"review":null`) || !strings.Contains(string(data), `"added":[]`) {
		t.Errorf("audit-only: %s", data[:300])
	}
}
