package run

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
)

// idPattern matches run folder names; runs/ also holds the latest links and dot entries (.probe-*,
// .tmp-*), which retention never touches.
var idPattern = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{4}$`)

// Prune deletes run folders beyond the newest keep (spec section 11.4). It keeps the runs that
// latest and latest-reviewed point to and the run each kept run carries its review from. A
// folder without a readable run.json counts by its name like any other. It returns the removed IDs.
func Prune(stateDir string, keep int) ([]string, error) {
	runs := filepath.Join(stateDir, "runs")
	es, err := os.ReadDir(runs)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range es {
		if e.IsDir() && idPattern.MatchString(e.Name()) { // a link is never a folder here
			ids = append(ids, e.Name())
		}
	}
	slices.Sort(ids)
	slices.Reverse(ids) // newest first: an ID starts with its UTC start time
	kept := map[string]bool{}
	for _, name := range []string{"latest", "latest-reviewed"} {
		if target, err := os.Readlink(filepath.Join(runs, name)); err == nil {
			kept[target] = true
		}
	}
	for i, id := range ids {
		if i >= keep && !kept[id] {
			continue
		}
		kept[id] = true
		if r, err := ReadRecord(filepath.Join(runs, id)); err == nil && r.CarriedFrom != "" {
			kept[r.CarriedFrom] = true
		}
	}
	var removed []string
	var errs []error
	for _, id := range ids {
		if kept[id] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(runs, id)); err != nil {
			errs = append(errs, err)
			continue
		}
		removed = append(removed, id)
	}
	return removed, errors.Join(errs...)
}
