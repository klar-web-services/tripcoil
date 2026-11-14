package audit

import (
	"slices"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/osrel"
)

const (
	libsslID = "pkg:deb/debian/libssl3@3.0.15-1~deb12u1?arch=amd64&distro=debian-12"
	kernelID = "pkg:deb/debian/linux-image-6.1.0-28-amd64@6.1.119-1?arch=amd64&distro=debian-12"
	apiID    = "binary:9f2c41d0"
	imageID  = "image:sha256:1111"
)

func remediationInventory() *inventory.Inventory {
	return &inventory.Inventory{
		Items: []inventory.Item{
			{ID: "kernel", Kind: inventory.KindKernel, RunningVersion: "6.1.119-1", Origins: []string{kernelID}},
			{ID: "proc:nginx", Kind: inventory.KindProcess, Name: "nginx", Units: []string{"nginx.service"}, Origins: []string{libsslID}},
			{ID: "proc:php", Kind: inventory.KindProcess, Name: "php-fpm8.2", Units: []string{"php8.2-fpm.service"}, Origins: []string{libsslID}},
			{ID: "proc:shop", Kind: inventory.KindProcess, Name: "node", Units: []string{"shop.service"}, Origins: []string{libsslID, "appdir:/srv/shop"}},
			{ID: "proc:api", Kind: inventory.KindProcess, Name: "api", Units: []string{"user@1000.service"}, Origins: []string{apiID, libsslID}},
			{ID: "container:shop-web-1", Kind: inventory.KindContainer, Name: "shop-web-1", Compose: &inventory.Compose{Project: "shop", Service: "web"}, Origins: []string{imageID}},
			{ID: "container:cache", Kind: inventory.KindContainer, Name: "cache", Origins: []string{imageID}},
		},
		Origins: []inventory.Origin{
			{ID: libsslID, Kind: inventory.OriginPackage, Name: "libssl3", Version: "3.0.15-1~deb12u1", RunningOlderCopy: true},
			{ID: kernelID, Kind: inventory.OriginPackage, Name: "linux-image-6.1.0-28-amd64", Version: "6.1.119-1"},
			{ID: apiID, Kind: inventory.OriginBinary, Paths: []string{"/opt/api/api"}},
			{ID: "appdir:/srv/shop", Kind: inventory.OriginAppDir, Path: "/srv/shop"},
			{ID: imageID, Kind: inventory.OriginImage, ImageID: "sha256:1111", Ref: "ghcr.io/acme/shop:2026.11.3"},
		},
	}
}

func TestRemediation(t *testing.T) {
	r := newRemediation(osrel.Debian, remediationInventory())
	f := func(origin, pkg, version, state string, fixes ...string) Finding {
		return Finding{Origin: origin, Package: Package{Name: pkg, Version: version}, Fix: Fix{State: state, Versions: fixes}}
	}
	cases := []struct {
		name string
		f    Finding
		want string
	}{
		{"package, with its units, and a running older copy", f(libsslID, "libssl3", "3.0.15-1~deb12u1", "fixed", "3.0.16-1~deb12u1"),
			"Upgrade libssl3 to 3.0.16-1~deb12u1 (apt-get install --only-upgrade libssl3), then restart nginx.service, php8.2-fpm.service, shop.service, api. The running copy is older than the installed package, so a restart may already clear it."},
		{"no fix known", f(libsslID, "libssl3", "3.0.15-1~deb12u1", "not-fixed"), "No fix is known for libssl3 3.0.15-1~deb12u1 yet."},
		{"fixed without a version is no fix", f(libsslID, "libssl3", "3.0.15-1~deb12u1", "fixed"), "No fix is known for libssl3 3.0.15-1~deb12u1 yet."},
		{"wont-fix", f(libsslID, "libssl3", "3.0.15-1~deb12u1", "wont-fix"), "No fix will be released for libssl3 3.0.15-1~deb12u1 (wont-fix)."},
		{"kernel package", f(kernelID, "linux-image-6.1.0-28-amd64", "6.1.119-1", "fixed", "6.1.123-1"),
			"Upgrade the kernel to 6.1.123-1 or later (apt-get dist-upgrade), then reboot."},
		{"kernel without a fix", f(kernelID, "linux-image-6.1.0-28-amd64", "6.1.119-1", "not-fixed"), "No fixed kernel version is known yet."},
		{"binary", f(apiID, "golang.org/x/net", "v0.1.0", "fixed", "v0.17.0"), "Replace or rebuild /opt/api/api with golang.org/x/net v0.17.0 or later, then restart api."},
		{"app directory, several fix versions", f("appdir:/srv/shop", "minimist", "1.2.5", "fixed", "0.2.4", "1.2.6"), "Upgrade minimist in /srv/shop to 0.2.4 or 1.2.6, then restart shop.service."},
		{"image, with and without Compose", f(imageID, "libssl3", "3.0.11-1~deb12u2", "fixed", "3.0.16-1~deb12u1"),
			"Rebuild ghcr.io/acme/shop:2026.11.3 or pull a newer image with libssl3 3.0.16-1~deb12u1 or later, then recreate the container cache, shop-web-1 (docker compose -p shop up -d --force-recreate web)."},
	}
	for _, c := range cases {
		if got := r.line(c.f); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
	}
	if ids := r.itemIDs(imageID); !slices.Equal(ids, []string{"container:shop-web-1", "container:cache"}) {
		t.Errorf("items %v", ids)
	}
}

func TestRemediationKernelUpstreamAndArch(t *testing.T) {
	up := inventory.KernelUpstreamOriginID("7.3.3")
	inv := &inventory.Inventory{
		Items:   []inventory.Item{{ID: "kernel", Kind: inventory.KindKernel, RunningVersion: "7.3.3-1", Origins: []string{up}}, {ID: "proc:sshd", Kind: inventory.KindProcess, Name: "sshd", Units: []string{"sshd.service"}, Origins: []string{"pkg:alpm/cachyos/openssl@3.6.0-1?arch=x86_64&distro=cachyos"}}},
		Origins: []inventory.Origin{{ID: up, Kind: inventory.OriginKernelUpstream, UpstreamVersion: "7.3.3"}, {ID: "pkg:alpm/cachyos/openssl@3.6.0-1?arch=x86_64&distro=cachyos", Kind: inventory.OriginPackage, Name: "openssl"}},
	}
	r := newRemediation(osrel.Arch, inv)
	if got, want := r.line(Finding{Origin: up, Fix: Fix{State: "fixed", Versions: []string{"7.3.5"}}}), "Upgrade the kernel to Linux 7.3.5 or later (pacman -Syu), then reboot."; got != want {
		t.Errorf("got %s\nwant %s", got, want)
	}
	if got, want := r.line(Finding{Origin: "pkg:alpm/cachyos/openssl@3.6.0-1?arch=x86_64&distro=cachyos", Package: Package{Name: "openssl"}, Fix: Fix{State: "fixed", Versions: []string{"3.6.1-1"}}}), "Upgrade openssl to 3.6.1-1 (pacman -Syu), then restart sshd.service."; got != want {
		t.Errorf("got %s\nwant %s", got, want)
	}
	// A custom kernel without a package is not upgraded with the package tool.
	inv.Items[0].RunningVersion = ""
	r = newRemediation(osrel.Arch, inv)
	if got, want := r.line(Finding{Origin: up, Fix: Fix{State: "fixed", Versions: []string{"7.3.5"}}}), "Upgrade the kernel to Linux 7.3.5 or later, then reboot."; got != want {
		t.Errorf("got %s\nwant %s", got, want)
	}
}

func TestRemediationNamesAtMostFive(t *testing.T) {
	inv := &inventory.Inventory{Origins: []inventory.Origin{{ID: libsslID, Kind: inventory.OriginPackage}}}
	for _, u := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		inv.Items = append(inv.Items, inventory.Item{ID: "proc:" + u, Kind: inventory.KindProcess, Name: u, Units: []string{u + ".service"}, Origins: []string{libsslID}})
	}
	got := newRemediation(osrel.Debian, inv).line(Finding{Origin: libsslID, Package: Package{Name: "libssl3"}, Fix: Fix{State: "fixed", Versions: []string{"2"}}})
	if want := "Upgrade libssl3 to 2 (apt-get install --only-upgrade libssl3), then restart a.service, b.service, c.service, d.service, e.service and 2 more."; got != want {
		t.Errorf("got %s\nwant %s", got, want)
	}
}
