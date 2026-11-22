package audit

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/osrel"
)

func actionFinding(r remediation, origin, pkg, version, typ, risk string, fixes ...string) Finding {
	f := Finding{ID: fmt.Sprintf("f:%s:%s:%s:%v", origin, pkg, version, fixes), Origin: origin, Risk: risk,
		Package: Package{Name: pkg, Version: version, Type: typ}, Fix: Fix{State: "not-fixed", Versions: []string{}}, Items: r.itemIDs(origin)}
	if len(fixes) > 0 {
		f.Fix = Fix{State: "fixed", Versions: fixes}
	}
	return f
}

func actionByKind(t *testing.T, actions []Action, kind string) Action {
	t.Helper()
	i := slices.IndexFunc(actions, func(a Action) bool { return a.Kind == kind })
	if i < 0 {
		t.Fatalf("no %s action in %+v", kind, actions)
	}
	return actions[i]
}

func TestActions(t *testing.T) {
	r := newRemediation(osrel.Debian, remediationInventory())
	cna := Finding{ID: "f:cna", Origin: "kernel-upstream:6.1.119", Source: "kernel-cna", Risk: RiskMedium,
		Package: Package{Name: "linux", Version: "6.1.119"}, Fix: Fix{State: "fixed", Versions: []string{"6.1.120"}}, Items: []string{"kernel"}}
	kev := actionFinding(r, imageID, "chromium", "148.0-1", "deb", RiskCritical, "153.0-1")
	kev.Vulnerability.KnownExploited = true
	findings := []Finding{
		actionFinding(r, kernelID, "linux-image-6.1.0-28-amd64", "6.1.119-1", "deb", RiskHigh, "6.1.123-1"),
		cna,
		actionFinding(r, libsslID, "libssl3", "3.0.15-1~deb12u1", "deb", RiskHigh, "3.0.16-1~deb12u1"),
		actionFinding(r, libsslID, "libssl3", "3.0.15-1~deb12u1", "deb", RiskMedium, "3.0.17-1~deb12u1", "3.0.2-0"),
		actionFinding(r, libsslID, "libssl3", "3.0.15-1~deb12u1", "deb", RiskLow),
		actionFinding(r, imageID, "libssl3", "3.0.11-1~deb12u2", "deb", RiskHigh, "3.0.16-1~deb12u1"),
		kev,
		actionFinding(r, imageID, "zlib1g", "1.2.13", "deb", RiskCritical),
		actionFinding(r, "appdir:/srv/shop", "minimist", "1.2.5", "npm", RiskHigh, "1.2.6"),
		actionFinding(r, apiID, "golang.org/x/net", "v0.1.0", "go-module", RiskMedium, "v0.17.0"),
	}
	upgrades := []Upgrade{{Origin: "appdir:/srv/shop", Path: "/srv/shop", Package: "minimist", Type: "npm", Installed: []string{"1.2.5"}, Version: "1.2.8", Findings: 1}}
	actions := r.actions(findings, upgrades)
	if len(actions) != 5 {
		t.Fatalf("%d actions, want 5: %+v", len(actions), actions)
	}
	for _, f := range findings {
		if !slices.ContainsFunc(actions, func(a Action) bool { return a.ID == f.Action }) {
			t.Errorf("finding %s has the action %q, which does not exist", f.ID, f.Action)
		}
	}
	if findings[0].Action != findings[1].Action || findings[0].Action != ActionID(ActionKernel, ActionKernel) {
		t.Errorf("kernel findings have the actions %q and %q", findings[0].Action, findings[1].Action)
	}

	kernel := actionByKind(t, actions, ActionKernel)
	wantKernel := Action{ID: "a:18d4158d999f", Kind: ActionKernel, Name: "Linux kernel", Items: []string{"kernel"},
		Changes: []Change{{Name: "linux-image-6.1.0-28-amd64", From: "6.1.119-1", To: "6.1.123-1", Clears: 1}, {Name: "linux", From: "6.1.119", To: "6.1.120", Clears: 1}},
		Steps:   []Step{{Text: "Upgrade the kernel", Command: "apt-get update && apt-get dist-upgrade"}, {Text: "Reboot"}},
		Counts:  ActionCounts{Findings: 2, High: 1, Medium: 1}}
	if !reflect.DeepEqual(kernel, wantKernel) {
		t.Errorf("kernel:\n got %+v\nwant %+v", kernel, wantKernel)
	}

	pkgs := actionByKind(t, actions, ActionPackages)
	if pkgs.Name != "System packages" || pkgs.ID != ActionID(ActionPackages, ActionPackages) {
		t.Errorf("packages: %+v", pkgs)
	}
	if want := []Change{{Name: "libssl3", From: "3.0.15-1~deb12u1", To: "3.0.17-1~deb12u1", Clears: 2, Unfixed: 1}}; !reflect.DeepEqual(pkgs.Changes, want) {
		t.Errorf("packages changes: %+v", pkgs.Changes)
	}
	if want := []Step{{Text: "Upgrade the packages", Command: "apt-get update && apt-get install --only-upgrade libssl3"},
		{Text: "Restart nginx.service, php8.2-fpm.service, shop.service", Command: "systemctl restart nginx.service php8.2-fpm.service shop.service"},
		{Text: "Restart api"}}; !reflect.DeepEqual(pkgs.Steps, want) {
		t.Errorf("packages steps: %+v", pkgs.Steps)
	}
	if want := []string{"proc:api", "proc:nginx", "proc:php", "proc:shop"}; !slices.Equal(pkgs.Items, want) {
		t.Errorf("packages items: %v", pkgs.Items)
	}

	image := actionByKind(t, actions, ActionImage)
	if image.Name != "shop" || image.Target != "ghcr.io/acme/shop:2026.11.3" || image.ID != ActionID(ActionImage, imageID) {
		t.Errorf("image: %+v", image)
	}
	// The exploited one first, then by tier; the one without a fix last.
	if want := []Change{{Name: "chromium", From: "148.0-1", To: "153.0-1", Clears: 1}, {Name: "libssl3", From: "3.0.11-1~deb12u2", To: "3.0.16-1~deb12u1", Clears: 1},
		{Name: "zlib1g", From: "1.2.13", Unfixed: 1}}; !reflect.DeepEqual(image.Changes, want) {
		t.Errorf("image changes: %+v", image.Changes)
	}
	if want := []Step{{Text: "Pull or rebuild ghcr.io/acme/shop:2026.11.3"}, {Text: "Recreate the container cache"},
		{Text: "Recreate shop-web-1", Command: "docker compose -p shop --project-directory /srv/shop -f /srv/shop/compose.yml up -d --force-recreate --no-deps web"}}; !reflect.DeepEqual(image.Steps, want) {
		t.Errorf("image steps: %+v", image.Steps)
	}
	if image.Counts != (ActionCounts{Findings: 3, Critical: 2, High: 1, KnownExploited: 1}) {
		t.Errorf("image counts: %+v", image.Counts)
	}

	app := actionByKind(t, actions, ActionAppDir)
	if app.Name != "/srv/shop" || app.Target != "/srv/shop" {
		t.Errorf("app directory: %+v", app)
	}
	if want := []Change{{Name: "minimist", From: "1.2.5", To: "1.2.8", Clears: 1}}; !reflect.DeepEqual(app.Changes, want) {
		t.Errorf("app directory changes take the verified upgrade line: %+v", app.Changes)
	}
	if want := []Step{{Text: "Upgrade the packages below in /srv/shop"}, {Text: "Restart shop.service", Command: "systemctl restart shop.service"}}; !reflect.DeepEqual(app.Steps, want) {
		t.Errorf("app directory steps: %+v", app.Steps)
	}

	bin := actionByKind(t, actions, ActionBinary)
	if bin.Name != "/opt/api/api" || bin.Target != "/opt/api/api" || !reflect.DeepEqual(bin.Steps, []Step{{Text: "Replace or rebuild /opt/api/api"}, {Text: "Restart api"}}) {
		t.Errorf("binary: %+v", bin)
	}
}

func TestActionNames(t *testing.T) {
	inv := remediationInventory()
	inv.Items = slices.DeleteFunc(inv.Items, func(it inventory.Item) bool { return it.Name == "cache" })
	r := newRemediation(osrel.Debian, inv)
	a := r.actions([]Finding{actionFinding(r, imageID, "libssl3", "3.0.11", "deb", RiskHigh, "3.0.16")}, nil)
	if a[0].Name != "shop-web-1" {
		t.Errorf("an image with one container is named %q, want the container's name", a[0].Name)
	}
	for ref, want := range map[string]string{"ghcr.io/acme/shop:2026.11.3": "shop", "redis": "redis", "registry:5000/a/b@sha256:abc": "b", "sha256:1111": "sha256"} {
		if got := imageShortName(ref); got != want {
			t.Errorf("imageShortName(%q) = %q, want %q", ref, got, want)
		}
	}
}

func TestActionLimits(t *testing.T) {
	r := newRemediation(osrel.Debian, remediationInventory())
	var findings []Finding
	for i := range 120 {
		findings = append(findings, actionFinding(r, libsslID, fmt.Sprintf("libexample-package-%03d", i), "1.0", "deb", RiskLow, "1.1"))
	}
	a := r.actions(findings, nil)[0]
	if len(a.Changes) != 50 || a.MoreChanges != 70 {
		t.Errorf("%d changes and %d more, want 50 and 70", len(a.Changes), a.MoreChanges)
	}
	// Naming 120 packages is longer than a command may be: the whole-system upgrade instead.
	if a.Steps[0].Command != "apt-get update && apt-get dist-upgrade" {
		t.Errorf("command %q", a.Steps[0].Command)
	}

	inv := remediationInventory()
	for i := range 30 {
		inv.Items = append(inv.Items, inventory.Item{ID: fmt.Sprintf("container:w%02d", i), Kind: inventory.KindContainer, Name: fmt.Sprintf("w%02d", i), Origins: []string{imageID}})
	}
	r = newRemediation(osrel.Debian, inv)
	a = r.actions([]Finding{actionFinding(r, imageID, "libssl3", "3.0.11", "deb", RiskHigh, "3.0.16")}, nil)[0]
	if len(a.Items) != MaxItems || a.MoreItems != 12 {
		t.Errorf("%d items and %d more", len(a.Items), a.MoreItems)
	}
	if len(a.Steps) != MaxSteps || a.Steps[MaxSteps-1].Text != "Recreate the other 22 containers" {
		t.Errorf("%d steps, the last %+v", len(a.Steps), a.Steps[len(a.Steps)-1])
	}
}

func TestPackagesStepByFamily(t *testing.T) {
	for family, want := range map[osrel.Family]string{osrel.Arch: "pacman -Syu", osrel.Alpine: "apk upgrade -U libssl3", osrel.Unknown: ""} {
		r := newRemediation(family, remediationInventory())
		a := r.actions([]Finding{actionFinding(r, libsslID, "libssl3", "3.0.15", "deb", RiskHigh, "3.0.16")}, nil)[0]
		if a.Steps[0] != (Step{Text: "Upgrade the packages", Command: want}) {
			t.Errorf("%q: %+v", family, a.Steps[0])
		}
	}
}

func TestCut(t *testing.T) {
	for _, c := range []struct {
		in   string
		n    int
		want string
	}{
		{"short", 10, "short"},
		{"exactly 10", 10, "exactly 10"},
		{"more than ten bytes", 10, "more th…"},
		{"ääääää", 10, "äää…"}, // never in the middle of a character
	} {
		if got := Cut(c.in, c.n); got != c.want || len(got) > c.n {
			t.Errorf("Cut(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
	if s := Cut(strings.Repeat("x", 1000), MaxStepText); len(s) != MaxStepText {
		t.Errorf("%d bytes", len(s))
	}
}
