package inventory

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/osrel"
	"github.com/klar-web-services/tripcoil/internal/pkgtool"
	"github.com/klar-web-services/tripcoil/internal/problem"
)

const debianProcVersion = "Linux version 6.1.0-28-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0, " +
	"GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.1.119-1 (2024-11-22)"

func kernelRoot(t *testing.T, rel, procVersion, signature string, modDirs ...string) string {
	content := map[string]string{
		"proc/sys/kernel/osrelease": rel + "\n",
		"proc/version":              procVersion + "\n",
		"proc/modules":              "wireguard 118784 0 - Live 0x0000000000000000\nnf_tables 389120 3 nft_ct, Live 0x0000000000000000\n",
	}
	if signature != "" {
		content["proc/version_signature"] = signature + "\n"
	}
	for _, d := range modDirs {
		content[d+"/modules.builtin"] = "kernel/fs/ext4/ext4.ko\n"
	}
	return files(t, content)
}

func deb(name, version string) pkgtool.Package {
	return pkgtool.Package{Name: name, Version: version, Arch: "amd64", Type: "deb"}
}

func TestKernel(t *testing.T) {
	debianRel := osrel.Release{ID: "debian", VersionID: "12"}
	debianImage := deb("linux-image-6.1.0-28-amd64", "6.1.119-1")
	debianBuiltin := "/usr/lib/modules/6.1.0-28-amd64/modules.builtin"
	rockyRel := osrel.Release{ID: "rocky", VersionID: "9.4", IDLike: []string{"rhel", "centos", "fedora"}}
	rockyCore := func(v string) pkgtool.Package {
		return pkgtool.Package{Name: "kernel-core", Version: v, Arch: "x86_64", Type: "rpm"}
	}
	cases := []struct {
		name            string
		release         osrel.Release
		root            func(t *testing.T) string
		tool            *fakeTool // nil: no package tool
		running         string
		upstream        string
		pendingContains string // "" means not pending
		origin          string // expected origin ID; "unresolved" checks the kind only
	}{
		{
			name: "debian current", release: debianRel,
			root: func(t *testing.T) string {
				return kernelRoot(t, "6.1.0-28-amd64", debianProcVersion, "", "usr/lib/modules/6.1.0-28-amd64")
			},
			tool: &fakeTool{typ: "deb", owners: map[string]pkgtool.Package{debianBuiltin: debianImage},
				installed: map[string][]pkgtool.Package{"linux-image-*": {debianImage, deb("linux-image-amd64", "6.1.119-1")}}},
			running: "6.1.119-1", upstream: "6.1.119",
			origin: PackageOriginID(Distro{ID: "debian", VersionID: "12"}, debianImage),
		},
		{
			name: "debian 13 with a newer kernel installed", release: osrel.Release{ID: "debian", VersionID: "13"},
			root: func(t *testing.T) string {
				return kernelRoot(t, "6.12.43+deb13-amd64", "Linux version 6.12.43+deb13-amd64 (debian-kernel@lists.debian.org) "+
					"(x86_64-linux-gnu-gcc-14 (Debian 14.2.0-19) 14.2.0, GNU ld (GNU Binutils for Debian) 2.44) "+
					"#1 SMP PREEMPT_DYNAMIC Debian 6.12.43-1 (2025-08-27)", "", "usr/lib/modules/6.12.43+deb13-amd64")
			},
			tool: &fakeTool{typ: "deb",
				owners: map[string]pkgtool.Package{"/usr/lib/modules/6.12.43+deb13-amd64/modules.builtin": deb("linux-image-6.12.43+deb13-amd64", "6.12.43-1")},
				installed: map[string][]pkgtool.Package{"linux-image-*": {
					deb("linux-image-6.12.43+deb13-amd64", "6.12.43-1"), deb("linux-image-6.12.57+deb13-amd64", "6.12.57-1"),
					deb("linux-image-6.12.57+deb13-cloud-amd64", "6.12.57-1"), deb("linux-image-amd64", "6.12.57-1"),
				}}},
			running: "6.12.43-1", upstream: "6.12.43", pendingContains: "linux-image-6.12.57+deb13-amd64 6.12.57-1",
			origin: PackageOriginID(Distro{ID: "debian", VersionID: "13"}, deb("linux-image-6.12.43+deb13-amd64", "6.12.43-1")),
		},
		{
			name: "amazon linux 2023", release: osrel.Release{ID: "amzn", VersionID: "2023", IDLike: []string{"fedora"}},
			root: func(t *testing.T) string {
				return kernelRoot(t, "6.12.40-63.114.amzn2023.x86_64", "Linux version 6.12.40-63.114.amzn2023.x86_64", "",
					"usr/lib/modules/6.12.40-63.114.amzn2023.x86_64")
			},
			tool: &fakeTool{typ: "rpm", owners: map[string]pkgtool.Package{
				"/usr/lib/modules/6.12.40-63.114.amzn2023.x86_64/modules.builtin": {Name: "kernel6.12", Version: "6.12.40-63.114.amzn2023", Arch: "x86_64", Type: "rpm"}}},
			running: "6.12.40-63.114.amzn2023", upstream: "6.12.40",
			origin: PackageOriginID(Distro{ID: "amzn", VersionID: "2023"}, pkgtool.Package{Name: "kernel6.12", Version: "6.12.40-63.114.amzn2023", Arch: "x86_64", Type: "rpm"}),
		},
		{
			name: "debian upgraded in place", release: debianRel,
			root: func(t *testing.T) string {
				return kernelRoot(t, "6.1.0-28-amd64", debianProcVersion, "", "usr/lib/modules/6.1.0-28-amd64")
			},
			tool:    &fakeTool{typ: "deb", owners: map[string]pkgtool.Package{debianBuiltin: deb("linux-image-6.1.0-28-amd64", "6.1.123-1")}},
			running: "6.1.119-1", upstream: "6.1.119", pendingContains: "now at 6.1.123-1",
			origin: PackageOriginID(Distro{ID: "debian", VersionID: "12"}, deb("linux-image-6.1.0-28-amd64", "6.1.123-1")),
		},
		{
			name: "debian newer kernel of the same flavor", release: debianRel,
			root: func(t *testing.T) string {
				return kernelRoot(t, "6.1.0-28-amd64", debianProcVersion, "", "usr/lib/modules/6.1.0-28-amd64")
			},
			tool: &fakeTool{typ: "deb", owners: map[string]pkgtool.Package{debianBuiltin: debianImage},
				installed: map[string][]pkgtool.Package{"linux-image-*": {
					debianImage, deb("linux-image-6.1.0-31-amd64", "6.1.128-1"), deb("linux-image-6.1.0-31-cloud-amd64", "6.1.128-1"), deb("linux-image-amd64", "6.1.128-1"),
				}}},
			running: "6.1.119-1", upstream: "6.1.119", pendingContains: "linux-image-6.1.0-31-amd64 6.1.128-1",
			origin: PackageOriginID(Distro{ID: "debian", VersionID: "12"}, debianImage),
		},
		{
			name: "ubuntu", release: osrel.Release{ID: "ubuntu", VersionID: "22.04", IDLike: []string{"debian"}},
			root: func(t *testing.T) string {
				return kernelRoot(t, "5.15.0-91-generic", "Linux version 5.15.0-91-generic (buildd@lcy02) #101-Ubuntu SMP",
					"Ubuntu 5.15.0-91.101-generic 5.15.131", "usr/lib/modules/5.15.0-91-generic")
			},
			tool: &fakeTool{typ: "deb", owners: map[string]pkgtool.Package{
				"/usr/lib/modules/5.15.0-91-generic/modules.builtin": deb("linux-modules-5.15.0-91-generic", "5.15.0-91.101")}},
			running: "5.15.0-91.101", upstream: "5.15.131",
			origin: PackageOriginID(Distro{ID: "ubuntu", VersionID: "22.04"}, deb("linux-modules-5.15.0-91-generic", "5.15.0-91.101")),
		},
		{
			name: "ubuntu with a newer kernel installed", release: osrel.Release{ID: "ubuntu", VersionID: "22.04", IDLike: []string{"debian"}},
			root: func(t *testing.T) string {
				return kernelRoot(t, "5.15.0-91-generic", "Linux version 5.15.0-91-generic (buildd@lcy02) #101-Ubuntu SMP",
					"Ubuntu 5.15.0-91.101-generic 5.15.131", "usr/lib/modules/5.15.0-91-generic")
			},
			tool: &fakeTool{typ: "deb",
				owners: map[string]pkgtool.Package{"/usr/lib/modules/5.15.0-91-generic/modules.builtin": deb("linux-modules-5.15.0-91-generic", "5.15.0-91.101")},
				installed: map[string][]pkgtool.Package{"linux-modules-*": {
					deb("linux-modules-5.15.0-91-generic", "5.15.0-91.101"), deb("linux-modules-5.15.0-94-generic", "5.15.0-94.104"), deb("linux-modules-5.15.0-94-lowlatency", "5.15.0-94.104"),
				}}},
			running: "5.15.0-91.101", upstream: "5.15.131", pendingContains: "linux-modules-5.15.0-94-generic 5.15.0-94.104",
			origin: PackageOriginID(Distro{ID: "ubuntu", VersionID: "22.04"}, deb("linux-modules-5.15.0-91-generic", "5.15.0-91.101")),
		},
		{
			name: "ubuntu upgraded in place", release: osrel.Release{ID: "ubuntu", VersionID: "22.04", IDLike: []string{"debian"}},
			root: func(t *testing.T) string {
				return kernelRoot(t, "5.15.0-91-generic", "Linux version 5.15.0-91-generic (buildd@lcy02) #101-Ubuntu SMP",
					"Ubuntu 5.15.0-91.101-generic 5.15.131", "usr/lib/modules/5.15.0-91-generic")
			},
			tool: &fakeTool{typ: "deb",
				owners:    map[string]pkgtool.Package{"/usr/lib/modules/5.15.0-91-generic/modules.builtin": deb("linux-modules-5.15.0-91-generic", "5.15.0-91.102")},
				installed: map[string][]pkgtool.Package{"linux-modules-*": {deb("linux-modules-5.15.0-91-generic", "5.15.0-91.102")}}},
			running: "5.15.0-91.101", upstream: "5.15.131", pendingContains: "now at 5.15.0-91.102",
			origin: PackageOriginID(Distro{ID: "ubuntu", VersionID: "22.04"}, deb("linux-modules-5.15.0-91-generic", "5.15.0-91.102")),
		},
		{
			name: "rocky with a newer kernel installed", release: rockyRel,
			root: func(t *testing.T) string {
				return kernelRoot(t, "5.14.0-427.13.1.el9_4.x86_64", "Linux version 5.14.0-427.13.1.el9_4.x86_64", "",
					"usr/lib/modules/5.14.0-427.13.1.el9_4.x86_64")
			},
			tool: &fakeTool{typ: "rpm",
				owners:    map[string]pkgtool.Package{"/usr/lib/modules/5.14.0-427.13.1.el9_4.x86_64/modules.builtin": rockyCore("5.14.0-427.13.1.el9_4")},
				installed: map[string][]pkgtool.Package{"kernel-core": {rockyCore("5.14.0-427.13.1.el9_4"), rockyCore("5.14.0-503.11.1.el9_5")}}},
			running: "5.14.0-427.13.1.el9_4", upstream: "5.14.0", pendingContains: "kernel-core 5.14.0-503.11.1.el9_5",
			origin: PackageOriginID(Distro{ID: "rocky", VersionID: "9.4"}, rockyCore("5.14.0-427.13.1.el9_4")),
		},
		{
			name: "rocky without a newer kernel", release: rockyRel,
			root: func(t *testing.T) string {
				return kernelRoot(t, "5.14.0-427.13.1.el9_4.x86_64", "Linux version 5.14.0-427.13.1.el9_4.x86_64", "",
					"usr/lib/modules/5.14.0-427.13.1.el9_4.x86_64", "usr/lib/modules/5.14.0-362.24.1.el9_3.x86_64")
			},
			tool: &fakeTool{typ: "rpm",
				owners:    map[string]pkgtool.Package{"/usr/lib/modules/5.14.0-427.13.1.el9_4.x86_64/modules.builtin": rockyCore("5.14.0-427.13.1.el9_4")},
				installed: map[string][]pkgtool.Package{"kernel-core": {rockyCore("5.14.0-362.24.1.el9_3"), rockyCore("5.14.0-427.13.1.el9_4")}}},
			running: "5.14.0-427.13.1.el9_4", upstream: "5.14.0",
			origin: PackageOriginID(Distro{ID: "rocky", VersionID: "9.4"}, rockyCore("5.14.0-427.13.1.el9_4")),
		},
		{
			name: "arch after an upgrade", release: osrel.Release{ID: "arch"},
			root:    func(t *testing.T) string { return kernelRoot(t, "6.11.5-arch1-1", "Linux version 6.11.5-arch1-1", "") },
			tool:    &fakeTool{typ: "alpm"},
			running: "6.11.5-arch1-1", upstream: "6.11.5", pendingContains: "is gone",
			origin: KernelUpstreamOriginID("6.11.5"),
		},
		{
			name: "cachyos", release: osrel.Release{ID: "cachyos", IDLike: []string{"arch"}},
			root: func(t *testing.T) string {
				return kernelRoot(t, "7.3.3-1-cachyos", "Linux version 7.3.3-1-cachyos", "", "usr/lib/modules/7.3.3-1-cachyos")
			},
			tool: &fakeTool{typ: "alpm", owners: map[string]pkgtool.Package{
				"/usr/lib/modules/7.3.3-1-cachyos/modules.builtin": {Name: "linux-cachyos", Version: "7.3.3-1", Type: "alpm"}}},
			running: "7.3.3-1", upstream: "7.3.3",
			origin: KernelUpstreamOriginID("7.3.3"),
		},
		{
			name: "arch mainline release candidate", release: osrel.Release{ID: "arch"},
			root: func(t *testing.T) string {
				return kernelRoot(t, "7.4.0-rc1-1-mainline", "Linux version 7.4.0-rc1-1-mainline", "", "usr/lib/modules/7.4.0-rc1-1-mainline")
			},
			tool: &fakeTool{typ: "alpm", owners: map[string]pkgtool.Package{
				"/usr/lib/modules/7.4.0-rc1-1-mainline/modules.builtin": {Name: "linux-mainline", Version: "7.4rc1-1", Type: "alpm"}}},
			running: "7.4rc1-1", upstream: "7.4.0-rc1",
			origin: KernelUpstreamOriginID("7.4.0-rc1"),
		},
		{
			name: "release candidate built from git", release: osrel.Release{ID: "arch"},
			root: func(t *testing.T) string {
				return kernelRoot(t, "7.4.0-rc2-00123-gabcdef012345", "Linux version 7.4.0-rc2-00123-gabcdef012345", "", "usr/lib/modules/7.4.0-rc2-00123-gabcdef012345")
			},
			running: "7.4.0-rc2-00123-gabcdef012345", upstream: "7.4.0-rc2",
			origin: KernelUpstreamOriginID("7.4.0-rc2"),
		},
		{
			name: "alpine", release: osrel.Release{ID: "alpine", VersionID: "3.21.0"},
			root: func(t *testing.T) string {
				return kernelRoot(t, "6.6.58-0-lts", "Linux version 6.6.58-0-lts", "", "lib/modules/6.6.58-0-lts")
			},
			tool: &fakeTool{typ: "apk", owners: map[string]pkgtool.Package{
				"/lib/modules/6.6.58-0-lts/modules.builtin": {Name: "linux-lts", Version: "6.6.58-r0", Type: "apk"}}},
			running: "6.6.58-r0", upstream: "6.6.58",
			origin: KernelUpstreamOriginID("6.6.58"),
		},
		{
			name: "alpine after an upgrade", release: osrel.Release{ID: "alpine", VersionID: "3.21.0"},
			root: func(t *testing.T) string {
				return kernelRoot(t, "6.6.58-0-lts", "Linux version 6.6.58-0-lts", "", "lib/modules/6.6.62-0-lts")
			},
			tool: &fakeTool{typ: "apk", owners: map[string]pkgtool.Package{
				"/lib/modules/6.6.62-0-lts/modules.builtin": {Name: "linux-lts", Version: "6.6.62-r0", Type: "apk"}}},
			running: "6.6.58-0-lts", upstream: "6.6.58", pendingContains: "/lib/modules/6.6.58-0-lts is gone",
			origin: KernelUpstreamOriginID("6.6.58"),
		},
		{
			name: "debian backports kernel", release: debianRel,
			root: func(t *testing.T) string {
				return kernelRoot(t, "6.12.12+bpo-amd64", "Linux version 6.12.12+bpo-amd64 (debian-kernel@lists.debian.org) (x86_64-linux-gnu-gcc-12 (Debian 12.2.0-14) 12.2.0, "+
					"GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.12.12-1~bpo12+1 (2025-02-23)", "", "usr/lib/modules/6.12.12+bpo-amd64")
			},
			tool: &fakeTool{typ: "deb", owners: map[string]pkgtool.Package{
				"/usr/lib/modules/6.12.12+bpo-amd64/modules.builtin": deb("linux-image-6.12.12+bpo-amd64", "6.12.12-1~bpo12+1")}},
			running: "6.12.12-1~bpo12+1", upstream: "6.12.12",
			origin: PackageOriginID(Distro{ID: "debian", VersionID: "12"}, deb("linux-image-6.12.12+bpo-amd64", "6.12.12-1~bpo12+1")),
		},
		{
			name: "debian experimental release candidate", release: osrel.Release{ID: "debian"},
			root: func(t *testing.T) string {
				return kernelRoot(t, "6.13-rc7-amd64", "Linux version 6.13-rc7-amd64 (debian-kernel@lists.debian.org) (x86_64-linux-gnu-gcc-14 (Debian 14.2.0-12) 14.2.0, "+
					"GNU ld (GNU Binutils for Debian) 2.43.50.20250108) #1 SMP PREEMPT_DYNAMIC Debian 6.13~rc7-1~exp1 (2025-01-14)", "", "usr/lib/modules/6.13-rc7-amd64")
			},
			tool: &fakeTool{typ: "deb", owners: map[string]pkgtool.Package{
				"/usr/lib/modules/6.13-rc7-amd64/modules.builtin": deb("linux-image-6.13-rc7-amd64", "6.13~rc7-1~exp1")}},
			running: "6.13~rc7-1~exp1", upstream: "6.13-rc7",
			origin: KernelUpstreamOriginID("6.13-rc7"),
		},
		{
			name: "debian with a custom kernel", release: debianRel,
			root: func(t *testing.T) string {
				return kernelRoot(t, "6.12.0-custom", "Linux version 6.12.0-custom (me@build) (gcc (Debian 12.2.0-14) 12.2.0, "+
					"GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Sat Nov  9 10:00:00 CET 2026", "", "usr/lib/modules/6.12.0-custom")
			},
			tool:    &fakeTool{typ: "deb"},
			running: "6.12.0-custom", upstream: "6.12.0",
			origin: KernelUpstreamOriginID("6.12.0"),
		},
		{
			name: "proxmox kernel on debian", release: debianRel,
			root: func(t *testing.T) string {
				return kernelRoot(t, "6.8.12-4-pve", "Linux version 6.8.12-4-pve (build@proxmox) (gcc (Debian 12.2.0-14) 12.2.0, "+
					"GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC PMX 6.8.12-4 (2024-11-06T15:04Z)", "", "usr/lib/modules/6.8.12-4-pve")
			},
			tool: &fakeTool{typ: "deb", owners: map[string]pkgtool.Package{
				"/usr/lib/modules/6.8.12-4-pve/modules.builtin": deb("proxmox-kernel-6.8.12-4-pve-signed", "6.8.12-4")}},
			running: "6.8.12-4", upstream: "6.8.12",
			origin: KernelUpstreamOriginID("6.8.12"), // Debian's advisories do not cover Proxmox kernels
		},
		{
			name: "proxmox kernel with a newer one installed", release: debianRel,
			root: func(t *testing.T) string {
				return kernelRoot(t, "6.8.12-4-pve", "Linux version 6.8.12-4-pve (build@proxmox) (gcc (Debian 12.2.0-14) 12.2.0, "+
					"GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC PMX 6.8.12-4 (2024-11-06T15:04Z)", "", "usr/lib/modules/6.8.12-4-pve")
			},
			tool: &fakeTool{typ: "deb",
				owners: map[string]pkgtool.Package{"/usr/lib/modules/6.8.12-4-pve/modules.builtin": deb("proxmox-kernel-6.8.12-4-pve-signed", "6.8.12-4")},
				installed: map[string][]pkgtool.Package{"proxmox-kernel-*": {
					deb("proxmox-kernel-6.8.12-4-pve-signed", "6.8.12-4"), deb("proxmox-kernel-6.8.12-5-pve-signed", "6.8.12-5"), deb("proxmox-kernel-6.8", "6.8.12-5"),
				}}},
			running: "6.8.12-4", upstream: "6.8.12", pendingContains: "proxmox-kernel-6.8.12-5-pve-signed 6.8.12-5",
			origin: KernelUpstreamOriginID("6.8.12"),
		},
		{
			name: "raspberry pi kernel with an epoch", release: debianRel,
			root: func(t *testing.T) string {
				return kernelRoot(t, "6.6.51+rpt-rpi-v8", "Linux version 6.6.51+rpt-rpi-v8 (serge@raspberrypi.com) (aarch64-linux-gnu-gcc-12 (Debian 12.2.0-14) 12.2.0, "+
					"GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT Debian 1:6.6.51-1+rpt3 (2024-10-08)", "", "usr/lib/modules/6.6.51+rpt-rpi-v8")
			},
			tool: &fakeTool{typ: "deb", owners: map[string]pkgtool.Package{
				"/usr/lib/modules/6.6.51+rpt-rpi-v8/modules.builtin": deb("linux-image-6.6.51+rpt-rpi-v8", "1:6.6.51-1+rpt3")}},
			running: "1:6.6.51-1+rpt3", upstream: "6.6.51",
			origin: KernelUpstreamOriginID("6.6.51"),
		},
		{
			name: "raspberry pi kernel with a newer one installed", release: debianRel,
			root: func(t *testing.T) string {
				return kernelRoot(t, "6.6.51+rpt-rpi-v8", "Linux version 6.6.51+rpt-rpi-v8 (serge@raspberrypi.com) (aarch64-linux-gnu-gcc-12 (Debian 12.2.0-14) 12.2.0, "+
					"GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT Debian 1:6.6.51-1+rpt3 (2024-10-08)", "", "usr/lib/modules/6.6.51+rpt-rpi-v8")
			},
			tool: &fakeTool{typ: "deb",
				owners: map[string]pkgtool.Package{"/usr/lib/modules/6.6.51+rpt-rpi-v8/modules.builtin": deb("linux-image-6.6.51+rpt-rpi-v8", "1:6.6.51-1+rpt3")},
				installed: map[string][]pkgtool.Package{"linux-image-*": {
					deb("linux-image-6.6.51+rpt-rpi-v8", "1:6.6.51-1+rpt3"), deb("linux-image-6.6.62+rpt-rpi-v8", "1:6.6.62-1+rpt1"),
					deb("linux-image-6.6.62+rpt-rpi-2712", "1:6.6.62-1+rpt1"), deb("linux-image-rpi-v8", "1:6.6.62-1+rpt1"),
				}}},
			running: "1:6.6.51-1+rpt3", upstream: "6.6.51", pendingContains: "linux-image-6.6.62+rpt-rpi-v8 1:6.6.62-1+rpt1",
			origin: KernelUpstreamOriginID("6.6.51"),
		},
		{
			name: "liquorix kernel on debian", release: osrel.Release{ID: "debian", VersionID: "13"},
			root: func(t *testing.T) string {
				return kernelRoot(t, "7.0.9-1-liquorix-amd64", "Linux version 7.0.9-1-liquorix-amd64 (steven@liquorix.net) (gcc (Debian 14.2.0-19) 14.2.0, "+
					"GNU ld (GNU Binutils for Debian) 2.44) #1 ZEN SMP PREEMPT_DYNAMIC liquorix 7.0-9.1~trixie (2026-05-20)", "", "usr/lib/modules/7.0.9-1-liquorix-amd64")
			},
			tool: &fakeTool{typ: "deb", owners: map[string]pkgtool.Package{
				"/usr/lib/modules/7.0.9-1-liquorix-amd64/modules.builtin": deb("linux-image-7.0.9-1-liquorix-amd64", "7.0-9.1~trixie")}},
			running: "7.0-9.1~trixie", upstream: "7.0.9",
			origin: KernelUpstreamOriginID("7.0.9"),
		},
		{
			name: "ubuntu mainline kernel", release: osrel.Release{ID: "ubuntu", VersionID: "24.04", IDLike: []string{"debian"}},
			root: func(t *testing.T) string {
				return kernelRoot(t, "6.12.5-061205-generic", "Linux version 6.12.5-061205-generic (kernel@kathleen) #202412141234 SMP PREEMPT_DYNAMIC", "",
					"usr/lib/modules/6.12.5-061205-generic")
			},
			tool: &fakeTool{typ: "deb", owners: map[string]pkgtool.Package{
				"/usr/lib/modules/6.12.5-061205-generic/modules.builtin": deb("linux-modules-6.12.5-061205-generic", "6.12.5-061205.202412141234")}},
			running: "6.12.5-061205.202412141234", upstream: "6.12.5",
			origin: KernelUpstreamOriginID("6.12.5"),
		},
		{
			name: "ubuntu mainline kernel of an x.y.0 release", release: osrel.Release{ID: "ubuntu", VersionID: "24.04", IDLike: []string{"debian"}},
			root: func(t *testing.T) string {
				return kernelRoot(t, "6.12.0-061200-generic", "Linux version 6.12.0-061200-generic (kernel@kathleen) #202411172217 SMP PREEMPT_DYNAMIC", "",
					"usr/lib/modules/6.12.0-061200-generic")
			},
			tool: &fakeTool{typ: "deb", owners: map[string]pkgtool.Package{
				"/usr/lib/modules/6.12.0-061200-generic/modules.builtin": deb("linux-modules-6.12.0-061200-generic", "6.12.0-061200.202411172217")}},
			running: "6.12.0-061200.202411172217", upstream: "6.12.0",
			origin: KernelUpstreamOriginID("6.12.0"),
		},
		{
			name: "elrepo kernel on rocky", release: rockyRel,
			root: func(t *testing.T) string {
				return kernelRoot(t, "6.12.9-1.el9.elrepo.x86_64", "Linux version 6.12.9-1.el9.elrepo.x86_64", "", "usr/lib/modules/6.12.9-1.el9.elrepo.x86_64")
			},
			tool: &fakeTool{typ: "rpm", owners: map[string]pkgtool.Package{
				"/usr/lib/modules/6.12.9-1.el9.elrepo.x86_64/modules.builtin": {Name: "kernel-ml-core", Version: "6.12.9-1.el9.elrepo", Arch: "x86_64", Type: "rpm"}}},
			running: "6.12.9-1.el9.elrepo", upstream: "6.12.9",
			origin: KernelUpstreamOriginID("6.12.9"),
		},
		{
			name: "debian without a package tool", release: debianRel,
			root: func(t *testing.T) string {
				return kernelRoot(t, "6.1.0-28-amd64", debianProcVersion, "", "usr/lib/modules/6.1.0-28-amd64")
			},
			running: "6.1.119-1", upstream: "6.1.119",
			origin: "unresolved",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fam := tc.release.Family()
			k := kernelCollector{root: tc.root(t), release: tc.release, distro: Distro{ID: tc.release.ID, VersionID: tc.release.VersionID, Family: string(fam)}}
			if tc.tool != nil {
				k.resolver = &pkgtool.Resolver{Tool: *tc.tool}
			}
			it, o, problems := k.collect(context.Background())
			if it.ID != KernelItemID || it.Kind != KindKernel || it.RunningVersion != tc.running || it.UpstreamVersion != tc.upstream {
				t.Fatalf("item %+v", it)
			}
			if len(problems) != 0 {
				t.Fatalf("problems %+v", problems)
			}
			if !slices.Equal(it.Modules, []string{"nf_tables", "wireguard"}) {
				t.Fatalf("modules %v", it.Modules)
			}
			if tc.pendingContains == "" {
				if *it.RebootPending || len(it.RebootReasons) > 0 {
					t.Fatalf("unexpected reboot reasons %v", it.RebootReasons)
				}
			} else if !*it.RebootPending || !strings.Contains(strings.Join(it.RebootReasons, "; "), tc.pendingContains) {
				t.Fatalf("reboot reasons %v, want one containing %q", it.RebootReasons, tc.pendingContains)
			}
			for _, other := range []string{"cloud", "lowlatency", "rpi-2712"} {
				if strings.Contains(strings.Join(it.RebootReasons, "; "), other) {
					t.Fatal("another flavor must not count")
				}
			}
			if tc.origin == "unresolved" {
				if o.Kind != OriginUnresolved {
					t.Fatalf("origin %+v", o)
				}
			} else if o.ID != tc.origin {
				t.Fatalf("origin %q, want %q", o.ID, tc.origin)
			}
			if !slices.Equal(it.Origins, []string{o.ID}) {
				t.Fatalf("item origins %v", it.Origins)
			}
		})
	}
}

func TestDistroKernel(t *testing.T) {
	for name, want := range map[string]bool{
		"linux-image-6.1.0-28-amd64": true, "linux-image-6.1.0-0.deb11.17-amd64": true, "linux-image-6.12.43+deb13-amd64": true,
		"linux-image-6.12.12+bpo-cloud-amd64": true, "linux-modules-5.15.0-91-generic": true, "linux-image-unsigned-6.8.0-49-generic": true,
		"linux-image-7.0.9-1-liquorix-amd64": false, "linux-modules-6.12.5-061205-generic": false, "linux-image-6.6.51+rpt-rpi-v8": false,
		"proxmox-kernel-6.8.12-4-pve-signed": false, "linux-image-amd64": false,
	} {
		if got := distroKernel(deb(name, "1"), true); got != want {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
		if distroKernel(deb(name, "1"), false) {
			t.Errorf("%s without the distribution's build marker must not count", name)
		}
	}
}

type failingInstalled struct{ fakeTool }

func (failingInstalled) Installed(context.Context, string) ([]pkgtool.Package, error) {
	return nil, errors.New("dpkg-query: error: cannot read status file")
}

type failingCompare struct{ fakeTool }

func (failingCompare) Compare(context.Context, string, string) (int, error) {
	return 0, errors.New("signal: killed")
}

func TestKernelPackageToolFailures(t *testing.T) {
	debianRel := osrel.Release{ID: "debian", VersionID: "12"}
	debianImage := deb("linux-image-6.1.0-28-amd64", "6.1.119-1")
	debianRoot := func(t *testing.T) string {
		return kernelRoot(t, "6.1.0-28-amd64", debianProcVersion, "", "usr/lib/modules/6.1.0-28-amd64")
	}
	rockyRel := osrel.Release{ID: "rocky", VersionID: "9.4", IDLike: []string{"rhel", "centos", "fedora"}}
	rockyCore := func(v string) pkgtool.Package {
		return pkgtool.Package{Name: "kernel-core", Version: v, Arch: "x86_64", Type: "rpm"}
	}
	rockyRoot := func(t *testing.T) string {
		return kernelRoot(t, "5.14.0-427.13.1.el9_4.x86_64", "Linux version 5.14.0-427.13.1.el9_4.x86_64", "",
			"usr/lib/modules/5.14.0-427.13.1.el9_4.x86_64")
	}
	rockyBuiltin := "/usr/lib/modules/5.14.0-427.13.1.el9_4.x86_64/modules.builtin"
	cases := []struct {
		name    string
		release osrel.Release
		root    func(t *testing.T) string
		tool    pkgtool.Tool
		origin  string // expected origin ID; "unresolved" checks the kind and reason
		message string // part of the PACKAGE_TOOL_FAILED error's message
	}{
		{
			name: "rocky ownership", release: rockyRel, root: rockyRoot,
			tool:   fakeTool{typ: "rpm", ownersErr: errors.New("error: cannot open Packages database")},
			origin: "unresolved", message: "kernel's package",
		},
		{
			name: "debian ownership", release: debianRel, root: debianRoot,
			tool:   fakeTool{typ: "deb", ownersErr: errors.New("dpkg-query: error: cannot read status file")},
			origin: "unresolved", message: "kernel's package",
		},
		{
			name: "cachyos ownership", release: osrel.Release{ID: "cachyos", IDLike: []string{"arch"}},
			root: func(t *testing.T) string {
				return kernelRoot(t, "7.3.3-1-cachyos", "Linux version 7.3.3-1-cachyos", "", "usr/lib/modules/7.3.3-1-cachyos")
			},
			tool:   fakeTool{typ: "alpm", ownersErr: errors.New("error: could not open database")},
			origin: KernelUpstreamOriginID("7.3.3"), message: "kernel's package", // matched by upstream version anyway
		},
		{
			name: "debian installed kernels", release: debianRel, root: debianRoot,
			tool:   failingInstalled{fakeTool{typ: "deb", owners: map[string]pkgtool.Package{"/usr/lib/modules/6.1.0-28-amd64/modules.builtin": debianImage}}},
			origin: PackageOriginID(Distro{ID: "debian", VersionID: "12"}, debianImage), message: "list the installed kernels",
		},
		{
			name: "rocky version comparison", release: rockyRel, root: rockyRoot,
			tool: failingCompare{fakeTool{typ: "rpm", owners: map[string]pkgtool.Package{rockyBuiltin: rockyCore("5.14.0-427.13.1.el9_4")},
				installed: map[string][]pkgtool.Package{"kernel-core": {
					rockyCore("5.14.0-427.13.1.el9_4"), rockyCore("5.14.0-503.11.1.el9_5"), rockyCore("5.14.0-503.14.1.el9_5"),
				}}}},
			origin: PackageOriginID(Distro{ID: "rocky", VersionID: "9.4"}, rockyCore("5.14.0-427.13.1.el9_4")), message: "compare kernel versions",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k := kernelCollector{root: tc.root(t), release: tc.release, resolver: &pkgtool.Resolver{Tool: tc.tool},
				distro: Distro{ID: tc.release.ID, VersionID: tc.release.VersionID, Family: string(tc.release.Family())}}
			it, o, problems := k.collect(context.Background())
			if len(problems) != 1 || problems[0].Code != problem.PackageToolFailed || problems[0].Kind != problem.Error ||
				problems[0].Stage != "inventory" || !strings.Contains(problems[0].Message, tc.message) {
				t.Fatalf("problems %+v, want one PACKAGE_TOOL_FAILED error about %q", problems, tc.message)
			}
			if *it.RebootPending || len(it.RebootReasons) > 0 {
				t.Fatalf("unexpected reboot reasons %v", it.RebootReasons)
			}
			if tc.origin == "unresolved" {
				if o.Kind != OriginUnresolved || !strings.Contains(o.Reason, "package ownership") {
					t.Fatalf("origin %+v", o)
				}
			} else if o.ID != tc.origin {
				t.Fatalf("origin %q, want %q", o.ID, tc.origin)
			}
		})
	}
}
