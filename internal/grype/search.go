package grype

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
)

// searchBatch is how many IDs one `grype db search vuln` call looks up.
const searchBatch = 1000

// SearchVulnerabilities looks vulnerabilities up in the database by ID and returns their NVD
// records: severity, CVSS, EPSS and KEV. An ID the database does not hold is missing from the
// result.
func (r *Runner) SearchVulnerabilities(ctx context.Context, ids []string) (map[string]Vulnerability, error) {
	out := map[string]Vulnerability{}
	for start := 0; start < len(ids); start += searchBatch {
		batch := ids[start:min(start+searchBatch, len(ids))]
		args := append([]string{"db", "search", "vuln"}, batch...)
		args = append(args, "--provider", "nvd", "--limit", "0", "-o", "json")
		var buf bytes.Buffer
		if err := r.run(ctx, args, &buf); err != nil {
			return nil, err
		}
		found, err := parseSearch(buf.Bytes())
		if err != nil {
			return nil, err
		}
		for id, v := range found {
			out[id] = v
		}
	}
	return out, nil
}

type searchRecord struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Refs        []struct {
		URL string `json:"url"`
	} `json:"refs"`
	Severities []struct {
		Scheme string `json:"scheme"`
		Rank   int    `json:"rank"`
		Value  struct {
			Vector  string `json:"vector"`
			Metrics struct {
				BaseScore float64 `json:"baseScore"`
			} `json:"metrics"`
		} `json:"value"`
	} `json:"severities"`
	KnownExploited []json.RawMessage `json:"known_exploited"`
	EPSS           []struct {
		EPSS float64 `json:"epss"`
	} `json:"epss"`
}

// parseSearch reads `grype db search vuln -o json` output.
func parseSearch(data []byte) (map[string]Vulnerability, error) {
	var recs []searchRecord
	if err := json.Unmarshal(data, &recs); err != nil {
		return nil, fmt.Errorf("unexpected output from grype db search: %w", err)
	}
	out := map[string]Vulnerability{}
	for _, r := range recs {
		if r.ID == "" {
			return nil, fmt.Errorf("unexpected output from grype db search: a record has no ID")
		}
		v := Vulnerability{ID: r.ID, Namespace: "nvd", Severity: r.Severity, Description: r.Description, KnownExploited: len(r.KnownExploited) > 0}
		for _, ref := range r.Refs {
			v.URLs = append(v.URLs, ref.URL)
		}
		sort.SliceStable(r.Severities, func(i, j int) bool { return r.Severities[i].Rank < r.Severities[j].Rank })
		for _, s := range r.Severities {
			if s.Scheme == "CVSS" {
				v.CVSS = append(v.CVSS, CVSS{Score: s.Value.Metrics.BaseScore, Vector: s.Value.Vector})
			}
		}
		for _, e := range r.EPSS {
			v.EPSS = max(v.EPSS, e.EPSS)
		}
		out[r.ID] = v
	}
	return out, nil
}
