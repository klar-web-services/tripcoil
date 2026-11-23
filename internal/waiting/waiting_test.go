package waiting

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/klar-web-services/tripcoil/internal/audit"
)

var now = time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)

func days(n int) time.Time { return now.Add(-time.Duration(n) * 24 * time.Hour) }

func TestKeyOfAnImageSurvivesAPull(t *testing.T) {
	before := audit.Action{ID: "a:111111111111", Kind: audit.ActionImage, Target: "ghcr.io/flaresolverr/flaresolverr:latest"}
	after := audit.Action{ID: "a:222222222222", Kind: audit.ActionImage, Target: "ghcr.io/flaresolverr/flaresolverr:latest"}
	other := audit.Action{ID: "a:333333333333", Kind: audit.ActionImage, Target: "ghcr.io/flaresolverr/flaresolverr:v3"}
	bin := audit.Action{ID: "a:111111111111", Kind: audit.ActionBinary, Target: "/usr/local/bin/caddy"}
	k := audit.WaitingKey(before)
	if len(k) != 14 || k[:2] != "w:" || k != audit.WaitingKey(after) || k == audit.WaitingKey(other) || k == audit.WaitingKey(bin) {
		t.Errorf("keys %s %s %s %s", k, audit.WaitingKey(after), audit.WaitingKey(other), audit.WaitingKey(bin))
	}
	// Anything else is named by its action.
	if audit.WaitingKey(bin) == audit.WaitingKey(audit.Action{ID: "a:444444444444", Kind: audit.ActionBinary, Target: "/usr/local/bin/caddy"}) {
		t.Error("two binaries share a key")
	}
}

func TestMarkSetsTheClockOfActionsThatWaited(t *testing.T) {
	fresh := audit.Action{ID: "a:000000000001", Kind: audit.ActionBinary}
	recent := audit.Action{ID: "a:000000000002", Kind: audit.ActionBinary}
	old := audit.Action{ID: "a:000000000003", Kind: audit.ActionBinary}
	kept := audit.Action{ID: "a:000000000004", Kind: audit.ActionBinary}
	aud := &audit.Audit{Actions: []audit.Action{fresh, recent, old, kept}}
	st := State{audit.WaitingKey(recent): days(3), audit.WaitingKey(old): days(30), audit.WaitingKey(kept): days(45), "w:ffffffffffff": days(1)}
	until := now.Add(20 * 24 * time.Hour)
	Mark(aud, st, map[string]time.Time{audit.WaitingKey(kept): until, audit.WaitingKey(recent): until}, now)
	a := aud.Actions
	if a[0].Waiting != nil {
		t.Errorf("an action that never waited: %+v", a[0].Waiting)
	}
	if w := a[1].Waiting; w == nil || w.Key != audit.WaitingKey(recent) || !w.Since.Equal(days(3)) || w.Days != 3 || w.Overdue || w.Until != nil {
		t.Errorf("three days: %+v", w)
	}
	if w := a[2].Waiting; w == nil || w.Days != 30 || !w.Overdue || w.Until != nil {
		t.Errorf("thirty days: %+v", w)
	}
	// Only an overdue action can be kept waiting.
	if w := a[3].Waiting; w == nil || !w.Overdue || w.Until == nil || !w.Until.Equal(until) {
		t.Errorf("kept: %+v", w)
	}
	if got := Overdue(aud); len(got) != 2 || got[0] > got[1] {
		t.Errorf("overdue keys %v", got)
	}
}

func TestStateFile(t *testing.T) {
	dir := t.TempDir()
	if st, err := Read(dir); err != nil || len(st) != 0 {
		t.Fatalf("no file: %v %v", st, err)
	}
	st := State{"w:2ffdd1b1d089": days(3)}
	if err := Write(dir, st); err != nil {
		t.Fatal(err)
	}
	got, err := Read(dir)
	if err != nil || len(got) != 1 || !got["w:2ffdd1b1d089"].Equal(days(3)) {
		t.Fatalf("%v %v", got, err)
	}
	if info, err := os.Stat(filepath.Join(dir, File)); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the file's mode: %v %v", info, err)
	}
	// A damaged file starts over, and says so; a key that is none is dropped.
	if err := os.WriteFile(filepath.Join(dir, File), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := Read(dir); err == nil || len(got) != 0 {
		t.Errorf("a damaged file: %v %v", got, err)
	}
	if err := os.WriteFile(filepath.Join(dir, File), []byte(`{"w:2ffdd1b1d089":"2026-11-20T10:00:00Z","../x":"2026-11-20T10:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := Read(dir); err != nil || len(got) != 1 {
		t.Errorf("a key that is none: %v %v", got, err)
	}
}

func TestUpdate(t *testing.T) {
	st := State{"w:000000000001": days(10), "w:000000000002": days(10), "w:000000000003": days(10)}
	Update(st, []Card{
		{Key: "w:000000000001", Waits: true, NoFix: true},
		{Key: "w:000000000002", NoFix: false},
		{Key: "w:000000000004", Waits: true, NoFix: true},
		{Key: "w:000000000005", NoFix: true},
	}, now)
	// A card that still waits keeps its clock; one with a fixed release, and one that is gone, lose it;
	// a card that waits for the first time starts now; one with no fix that never waited has no clock.
	if len(st) != 2 || !st["w:000000000001"].Equal(days(10)) || !st["w:000000000004"].Equal(now) {
		t.Errorf("%v", st)
	}
	// A card that is a to-do again while no fix exists keeps its clock.
	st = State{"w:000000000001": days(40)}
	Update(st, []Card{{Key: "w:000000000001", NoFix: true}}, now)
	if len(st) != 1 || !st["w:000000000001"].Equal(days(40)) {
		t.Errorf("an overdue card: %v", st)
	}
}
