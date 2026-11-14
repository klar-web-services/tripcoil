package osrel

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFamilies(t *testing.T) {
	cases := []struct {
		name, osRelease string
		family          Family
		pkgType         string
		backports       bool
	}{
		{"debian", "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nVERSION_ID=\"12\"\nID=debian\n", Debian, "deb", true},
		{"ubuntu", "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\n", Ubuntu, "deb", true},
		{"mint", "ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n", Ubuntu, "deb", true},
		{"rocky", "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.4\"\n", RHEL, "rpm", true},
		{"alma", "ID=\"almalinux\"\nID_LIKE=\"rhel centos fedora\"\n", RHEL, "rpm", true},
		{"oracle", "ID=\"ol\"\nID_LIKE=\"fedora\"\n", RHEL, "rpm", true},
		{"amazon", "ID=\"amzn\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"2023\"\n", Amazon, "rpm", true},
		{"fedora", "ID=fedora\nVERSION_ID=41\n", Fedora, "rpm", false},
		{"leap", "ID=\"opensuse-leap\"\nID_LIKE=\"suse opensuse\"\n", SUSE, "rpm", true},
		{"sles", "ID=\"sles\"\nID_LIKE=\"suse\"\n", SUSE, "rpm", true},
		{"alpine", "ID=alpine\nVERSION_ID=3.21.0\n", Alpine, "apk", false},
		{"arch", "ID=arch\nBUILD_ID=rolling\n", Arch, "alpm", false},
		{"cachyos", "NAME=\"CachyOS Linux\"\nPRETTY_NAME=\"CachyOS\"\nID=cachyos\nID_LIKE=arch\nBUILD_ID=rolling\n", Arch, "alpm", false},
		{"gentoo", "ID=gentoo\n", Unknown, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Parse([]byte(tc.osRelease))
			if f := r.Family(); f != tc.family {
				t.Fatalf("family %q, want %q", f, tc.family)
			}
			if pt := r.Family().PackageType(); pt != tc.pkgType {
				t.Fatalf("package type %q, want %q", pt, tc.pkgType)
			}
			if b := r.Family().BackportsKernelFixes(); b != tc.backports {
				t.Fatalf("backports %v, want %v", b, tc.backports)
			}
		})
	}
}

func TestParseFields(t *testing.T) {
	r := Parse([]byte("# comment\nID=\"Rocky\"\nVERSION_ID='9.4'\nID_LIKE=\"rhel centos\"\nPRETTY_NAME=\"Rocky Linux 9.4 (Blue Onyx)\"\n"))
	if r.ID != "rocky" || r.VersionID != "9.4" || len(r.IDLike) != 2 || r.PrettyName != "Rocky Linux 9.4 (Blue Onyx)" {
		t.Fatalf("%+v", r)
	}
}

func TestReadFallsBackToUsrLib(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr/lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr/lib/os-release"), []byte("ID=arch\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := Read(root)
	if err != nil || r.ID != "arch" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := Read(t.TempDir()); err == nil {
		t.Fatal("no os-release must be an error")
	}
}
