package problem

import "testing"

func TestSplitAndHasErrors(t *testing.T) {
	ps := []Problem{
		New(Error, DockerUnavailable, "inventory", "docker at %s does not answer", "/var/run/docker.sock"),
		New(Notice, DockerAbsent, "inventory", "no docker"),
		New(Warning, "SOMETHING", "inventory", "worth knowing"),
		New(Gap, AppDirNotFound, "inventory", "not audited"),
	}
	errs, warns, notices := Split(ps)
	if len(errs) != 1 || errs[0].Message != "docker at /var/run/docker.sock does not answer" {
		t.Fatalf("errors %+v", errs)
	}
	if len(warns) != 1 || len(notices) != 1 {
		t.Fatalf("warnings %+v notices %+v", warns, notices)
	}
	if !HasErrors(ps) || HasErrors(ps[1:]) {
		t.Fatal("HasErrors is wrong")
	}
	e, w, n := Split(nil)
	if e == nil || w == nil || n == nil {
		t.Fatal("Split must return empty slices, not nil, so JSON shows []")
	}
}
