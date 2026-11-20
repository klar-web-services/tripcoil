package run

// Verdict is the report's verdict line with its code and the counts behind it, kept in run.json so
// `tripcoil report --json` and Zosia never rebuild them.
type Verdict struct {
	Code   string         `json:"code"`
	Line   string         `json:"line"`
	Counts map[string]int `json:"counts"`
}
