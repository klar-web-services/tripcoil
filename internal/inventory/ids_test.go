package inventory

import (
	"strings"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/pkgtool"
)

func TestPackageOriginID(t *testing.T) {
	cases := []struct {
		d    Distro
		p    pkgtool.Package
		want string
	}{
		{Distro{ID: "debian", VersionID: "12"}, pkgtool.Package{Name: "libssl3", Version: "3.0.15-1~deb12u1", Arch: "amd64", Type: "deb"},
			"pkg:deb/debian/libssl3@3.0.15-1~deb12u1?arch=amd64&distro=debian-12"},
		{Distro{ID: "rocky", VersionID: "9.4"}, pkgtool.Package{Name: "bind-libs", Version: "9.16.23-18.el9", Epoch: "32", Arch: "x86_64", Type: "rpm"},
			"pkg:rpm/rocky/bind-libs@32:9.16.23-18.el9?arch=x86_64&distro=rocky-9.4"},
		{Distro{ID: "cachyos"}, pkgtool.Package{Name: "glibc", Version: "2.44+r50-1", Type: "alpm"},
			"pkg:alpm/cachyos/glibc@2.44+r50-1?distro=cachyos"},
	}
	for _, tc := range cases {
		if got := PackageOriginID(tc.d, tc.p); got != tc.want {
			t.Errorf("got %q, want %q", got, tc.want)
		}
	}
}

func TestItemIDs(t *testing.T) {
	a := ProcessItemID("/usr/bin/node", "/srv/shop")
	if a != ProcessItemID("/usr/bin/node", "/srv/shop") {
		t.Fatal("not stable")
	}
	if a == ProcessItemID("/usr/bin/node", "/srv/blog") || a == ProcessItemID("/usr/bin/node", "") {
		t.Fatal("different app directories must give different items")
	}
	if !strings.HasPrefix(a, "proc:") || len(a) != len("proc:")+12 {
		t.Fatalf("format %q", a)
	}
	if ContainerItemID("shop-web-1") != "container:shop-web-1" || KernelItemID != "kernel" {
		t.Fatal("container or kernel ID")
	}
	if BinaryOriginID("ab12") != "binary:ab12" || AppDirOriginID("/srv/shop") != "appdir:/srv/shop" ||
		ImageOriginID("sha256:ff") != "image:sha256:ff" || KernelUpstreamOriginID("7.3.3") != "kernel-upstream:7.3.3" {
		t.Fatal("origin IDs")
	}
	if u := UnresolvedOriginID("/snap/x"); !strings.HasPrefix(u, "unresolved:") || u == UnresolvedOriginID("/snap/y") {
		t.Fatalf("unresolved ID %q", u)
	}
}
