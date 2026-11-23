package report

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/review"
)

var updateZosia = flag.Bool("update-zosia", false, "rewrite testdata/zosia/*.json, the report fixtures Zosia's tests read")

// TestZosiaFixtures keeps payloads in the shape Zosia receives, from this package's own test
// host: a reviewed run, an audit-only run, and a reviewed run whose one card waits for a fix. Zosia
// copies them into its tests/fixtures/.
func TestZosiaFixtures(t *testing.T) {
	ok := map[string]string{"inventory": "ok", "audit": "ok", "review": "ok"}
	reach := reachInput()
	reviewed := Input{Run: record(ok), Inventory: hostInventory(), Audit: reach.Audit, Review: reach.Review, Reach: reach.Reach}
	auditOnly := Input{Run: record(map[string]string{"inventory": "ok", "audit": "ok"}), Inventory: hostInventory(), Audit: cardAudit(),
		Reach: reach.Reach, NoReview: "review.agent is none"}
	for name, in := range map[string]Input{"payload-reviewed.json": reviewed, "payload-audit-only.json": auditOnly, "payload-waiting.json": waitingInput(review.Conditional)} {
		v := VerdictOf(in, Render(in))
		in.Run.Verdict = &v
		data, err := json.MarshalIndent(Payload(in), "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join("testdata", "zosia", name)
		if *updateZosia {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%v (run with -update-zosia)", err)
		}
		if string(want) != string(data)+"\n" {
			t.Errorf("%s is out of date; run go test ./internal/report/ -run TestZosiaFixtures -update-zosia and copy it to Zosia", path)
		}
	}
}
