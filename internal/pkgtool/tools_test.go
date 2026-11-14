package pkgtool

import (
	"context"
	"maps"
	"strings"
	"testing"
)

var ctx = context.Background()

// fakeRunner answers commands from a table; an unexpected command fails the test.
type fakeRunner struct {
	t    *testing.T
	resp map[string]Result
}

func (f *fakeRunner) run(_ context.Context, name string, args ...string) (Result, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	r, ok := f.resp[key]
	if !ok {
		f.t.Fatalf("unexpected command: %s", key)
	}
	return r, nil
}

func out(s string) Result { return Result{Stdout: []byte(s)} }

func TestDpkgOwners(t *testing.T) {
	f := &fakeRunner{t: t, resp: map[string]Result{
		"dpkg-query -S /usr/bin/dpkg /usr/lib/x86_64-linux-gnu/libc.so.6 /bin/sh": {
			Stdout: []byte("dpkg: /usr/bin/dpkg\ndiversion by dash from: /bin/sh\ndiversion by dash to: /bin/sh.distrib\n" +
				"local diversion from: /usr/bin/dpkg\nlocal diversion to: /usr/bin/dpkg.real\ndash: /bin/sh\n"),
			Stderr:   []byte("dpkg-query: no path found matching pattern /usr/lib/x86_64-linux-gnu/libc.so.6\n"),
			ExitCode: 1,
		},
		"dpkg-query -W -f " + dpkgFormat + " dash dpkg": out("ii \tdash\tdash\tamd64\t0.5.12-2\nii \tdpkg\tdpkg\tamd64\t1.21.23\n"),
	}}
	got, err := dpkg{f.run}.Owners(ctx, []string{"/usr/bin/dpkg", "/usr/lib/x86_64-linux-gnu/libc.so.6", "/bin/sh"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Package{
		"/usr/bin/dpkg": {Name: "dpkg", Version: "1.21.23", Arch: "amd64", Type: "deb"},
		"/bin/sh":       {Name: "dash", Version: "0.5.12-2", Arch: "amd64", Type: "deb"},
	}
	if !maps.Equal(got, want) {
		t.Fatalf("got %+v", got)
	}
}

func TestDpkgInstalledAndCompare(t *testing.T) {
	f := &fakeRunner{t: t, resp: map[string]Result{
		"dpkg-query -W -f " + dpkgFormat + " linux-image-*": out("ii \tlinux-image-6.1.0-28-amd64\tlinux-image-6.1.0-28-amd64\tamd64\t6.1.119-1\n" +
			"rc \tlinux-image-6.1.0-25-amd64\tlinux-image-6.1.0-25-amd64\tamd64\t6.1.106-3\n" +
			"ii \tlinux-image-amd64\tlinux-image-amd64\tamd64\t6.1.119-1\n"),
		"dpkg-query -W -f " + dpkgFormat + " nothing-*":  {Stderr: []byte("dpkg-query: no packages found matching nothing-*\n"), ExitCode: 1},
		"dpkg --compare-versions 6.1.119-1 lt 6.1.123-1": {},
		"dpkg --compare-versions 6.1.123-1 lt 6.1.119-1": {ExitCode: 1},
		"dpkg --compare-versions 6.1.123-1 eq 6.1.119-1": {ExitCode: 1},
		"dpkg --compare-versions 1.0 lt 1.0":             {ExitCode: 1},
		"dpkg --compare-versions 1.0 eq 1.0":             {},
	}}
	d := dpkg{f.run}
	pkgs, err := d.Installed(ctx, "linux-image-*")
	if err != nil || len(pkgs) != 2 || pkgs[0].Name != "linux-image-6.1.0-28-amd64" || pkgs[1].Name != "linux-image-amd64" {
		t.Fatalf("%+v %v", pkgs, err)
	}
	if pkgs, err := d.Installed(ctx, "nothing-*"); err != nil || len(pkgs) != 0 {
		t.Fatalf("no match: %+v %v", pkgs, err)
	}
	for _, tc := range []struct {
		a, b string
		want int
	}{{"6.1.119-1", "6.1.123-1", -1}, {"6.1.123-1", "6.1.119-1", 1}, {"1.0", "1.0", 0}} {
		if c, err := d.Compare(ctx, tc.a, tc.b); err != nil || c != tc.want {
			t.Errorf("Compare(%s, %s) = %d %v", tc.a, tc.b, c, err)
		}
	}
	if _, err := d.Compare(ctx, "1.0; rm -rf /", "1.0"); err == nil {
		t.Fatal("unexpected characters must be refused")
	}
}

func TestDpkgPackageStates(t *testing.T) {
	f := &fakeRunner{t: t, resp: map[string]Result{
		"dpkg-query -W -f " + dpkgFormat + " linux-image-*": out("hi \tlinux-image-6.1.0-28-amd64\tlinux-image-6.1.0-28-amd64\tamd64\t6.1.119-1\n" +
			"iW \tlinux-image-6.1.0-29-amd64\tlinux-image-6.1.0-29-amd64\tamd64\t6.1.123-1\n" +
			"rc \tlinux-image-6.1.0-25-amd64\tlinux-image-6.1.0-25-amd64\tamd64\t6.1.106-3\n"),
		"dpkg-query -S /usr/bin/kubelet /usr/sbin/update-initramfs /etc/php/8.1/mods-available/pdo.ini": out("kubelet: /usr/bin/kubelet\n" +
			"initramfs-tools: /usr/sbin/update-initramfs\nphp8.1-common: /etc/php/8.1/mods-available/pdo.ini\n"),
		"dpkg-query -W -f " + dpkgFormat + " initramfs-tools kubelet php8.1-common": out("hi \tkubelet\tkubelet\tamd64\t1.31.2-1.1\n" +
			"it \tinitramfs-tools\tinitramfs-tools\tall\t0.142\nrc \tphp8.1-common\tphp8.1-common\tamd64\t8.1.31-1\n"),
		"dpkg-query -S /etc/php": out("php8.1-common, php8.2-common: /etc/php\n"),
		"dpkg-query -W -f " + dpkgFormat + " php8.1-common php8.2-common": out("rc \tphp8.1-common\tphp8.1-common\tamd64\t8.1.31-1\n" +
			"ii \tphp8.2-common\tphp8.2-common\tamd64\t8.2.26-1\n"),
	}}
	d := dpkg{f.run}
	pkgs, err := d.Installed(ctx, "linux-image-*")
	if err != nil || len(pkgs) != 2 || pkgs[0].Name != "linux-image-6.1.0-28-amd64" || pkgs[1].Name != "linux-image-6.1.0-29-amd64" {
		t.Errorf("Installed: %+v %v", pkgs, err)
	}
	got, err := d.Owners(ctx, []string{"/usr/bin/kubelet", "/usr/sbin/update-initramfs", "/etc/php/8.1/mods-available/pdo.ini"})
	want := map[string]Package{
		"/usr/bin/kubelet":           {Name: "kubelet", Version: "1.31.2-1.1", Arch: "amd64", Type: "deb"},
		"/usr/sbin/update-initramfs": {Name: "initramfs-tools", Version: "0.142", Arch: "all", Type: "deb"},
	}
	if err != nil || !maps.Equal(got, want) {
		t.Errorf("Owners: %+v %v", got, err)
	}
	got, err = d.Owners(ctx, []string{"/etc/php"})
	want = map[string]Package{"/etc/php": {Name: "php8.2-common", Version: "8.2.26-1", Arch: "amd64", Type: "deb"}}
	if err != nil || !maps.Equal(got, want) {
		t.Errorf("Owners with two listed owners: %+v %v", got, err)
	}
}

func TestRPM(t *testing.T) {
	f := &fakeRunner{t: t, resp: map[string]Result{
		"rpm -qf --qf " + rpmFormat + " /usr/bin/rpm":                                            out("rpm\t0\t4.16.1.3\t40.el9\tx86_64\n"),
		"rpm -qf --qf " + rpmFormat + " /usr/lib64/libc.so.6":                                    out("glibc\t0\t2.34\t266.el9_8\tx86_64\nglibc\t0\t2.34\t266.el9_8\ti686\n"),
		"rpm -qf --qf " + rpmFormat + " /usr/lib64/libbind9.so":                                  out("bind-libs\t32\t9.16.23\t18.el9\tx86_64\n"),
		"rpm -qf --qf " + rpmFormat + " /etc/hostname":                                           {Stdout: []byte("file /etc/hostname is not owned by any package\n"), ExitCode: 1},
		"rpm -q --qf " + rpmFormat + " kernel-core":                                              out("kernel-core\t0\t5.14.0\t427.13.1.el9_4\tx86_64\nkernel-core\t0\t5.14.0\t503.11.1.el9_5\tx86_64\n"),
		"rpm -q --qf " + rpmFormat + " kernel-rt":                                                {Stdout: []byte("package kernel-rt is not installed\n"), ExitCode: 1},
		`rpm --eval %{lua: print(rpm.vercmp("5.14.0-427.13.1.el9_4", "5.14.0-503.11.1.el9_5"))}`: out("-1\n"),
		"rpm -q --qf " + rpmFormat + " rpm":                                                      out("rpm\t0\t4.16.1.3\t40.el9\tx86_64\n"),
	}}
	r := rpm{f.run}
	got, err := r.Owners(ctx, []string{"/usr/bin/rpm", "/usr/lib64/libc.so.6", "/usr/lib64/libbind9.so", "/etc/hostname"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Package{
		"/usr/bin/rpm":           {Name: "rpm", Version: "4.16.1.3-40.el9", Arch: "x86_64", Type: "rpm"},
		"/usr/lib64/libc.so.6":   {Name: "glibc", Version: "2.34-266.el9_8", Arch: "x86_64", Type: "rpm"},
		"/usr/lib64/libbind9.so": {Name: "bind-libs", Version: "9.16.23-18.el9", Epoch: "32", Arch: "x86_64", Type: "rpm"},
	}
	if !maps.Equal(got, want) {
		t.Fatalf("got %+v", got)
	}
	if pkgs, err := r.Installed(ctx, "kernel-core"); err != nil || len(pkgs) != 2 || pkgs[1].Version != "5.14.0-503.11.1.el9_5" {
		t.Fatalf("%+v %v", pkgs, err)
	}
	if pkgs, err := r.Installed(ctx, "kernel-rt"); err != nil || len(pkgs) != 0 {
		t.Fatalf("%+v %v", pkgs, err)
	}
	if c, err := r.Compare(ctx, "5.14.0-427.13.1.el9_4", "5.14.0-503.11.1.el9_5"); err != nil || c != -1 {
		t.Fatalf("%d %v", c, err)
	}
	if err := r.Check(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestApk(t *testing.T) {
	f := &fakeRunner{t: t, resp: map[string]Result{
		"apk info --who-owns /bin/busybox /lib/ld-musl-x86_64.so.1 /usr/lib/libz.so.1 /usr/bin/nonexistent /etc/hostname": {
			Stdout: []byte("/bin/busybox is owned by busybox-1.37.0-r14\n/lib/ld-musl-x86_64.so.1 is owned by musl-1.2.5-r12\n" +
				"/usr/lib/libz.so.1 is owned by zlib-1.3.2-r1\n/etc/hostname is owned by alpine-baselayout-data-3.6.8-r1\n"),
			Stderr:   []byte("ERROR: /usr/bin/nonexistent: Could not find owner package\n"),
			ExitCode: 1,
		},
		"apk version -t 6.6.58-r0 6.6.63-r0": out("<\n"),
		"apk version -t 1.2.3-r1 1.2.3-r1":   out("=\n"),
		"apk info -e apk-tools":              out("apk-tools\n"),
	}}
	a := apk{f.run}
	got, err := a.Owners(ctx, []string{"/bin/busybox", "/lib/ld-musl-x86_64.so.1", "/usr/lib/libz.so.1", "/usr/bin/nonexistent", "/etc/hostname"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Package{
		"/bin/busybox":             {Name: "busybox", Version: "1.37.0-r14", Type: "apk"},
		"/lib/ld-musl-x86_64.so.1": {Name: "musl", Version: "1.2.5-r12", Type: "apk"},
		"/usr/lib/libz.so.1":       {Name: "zlib", Version: "1.3.2-r1", Type: "apk"},
		"/etc/hostname":            {Name: "alpine-baselayout-data", Version: "3.6.8-r1", Type: "apk"},
	}
	if !maps.Equal(got, want) {
		t.Fatalf("got %+v", got)
	}
	if c, err := a.Compare(ctx, "6.6.58-r0", "6.6.63-r0"); err != nil || c != -1 {
		t.Fatalf("%d %v", c, err)
	}
	if c, err := a.Compare(ctx, "1.2.3-r1", "1.2.3-r1"); err != nil || c != 0 {
		t.Fatalf("%d %v", c, err)
	}
	if err := a.Check(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestApkIgnoresUnrequestedPaths(t *testing.T) {
	f := &fakeRunner{t: t, resp: map[string]Result{
		"apk info --who-owns /usr/bin/vi /usr/local/bin/tool": {
			Stdout:   []byte("/usr/bin/vi symlink target is owned by busybox-1.37.0-r14\n/usr/sbin/nginx is owned by nginx-99.0-r0\n"),
			Stderr:   []byte("ERROR: /usr/local/bin/tool: Could not find owner package\n"),
			ExitCode: 1,
		},
	}}
	got, err := apk{f.run}.Owners(ctx, []string{"/usr/bin/vi", "/usr/local/bin/tool"})
	if err != nil || len(got) != 0 {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestPacman(t *testing.T) {
	f := &fakeRunner{t: t, resp: map[string]Result{
		"pacman -Qo /usr/bin/pacman /lib/libc.so.6 /usr/bin/nonexistent": {
			Stdout:   []byte("/usr/bin/pacman is owned by pacman 7.1.0.r9.g54d9411-3\n/usr/lib/libc.so.6 is owned by glibc 2.44+r50+g1848099f063e-1\n"),
			Stderr:   []byte("warning: database file for 'core' does not exist (use '-Sy' to download)\nerror: No package owns /usr/bin/nonexistent\n"),
			ExitCode: 1,
		},
		"vercmp 6.11.5.arch1-1 6.11.6.arch1-1": out("-1\n"),
		"vercmp 2 1":                           out("1\n"),
		"pacman -Q pacman":                     out("pacman 7.1.0.r9.g54d9411-3\n"),
	}}
	realpath := func(p string) (string, error) {
		if p == "/lib/libc.so.6" {
			return "/usr/lib/libc.so.6", nil
		}
		return p, nil
	}
	p := pacman{run: f.run, realpath: realpath}
	got, err := p.Owners(ctx, []string{"/usr/bin/pacman", "/lib/libc.so.6", "/usr/bin/nonexistent"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Package{
		"/usr/bin/pacman": {Name: "pacman", Version: "7.1.0.r9.g54d9411-3", Type: "alpm"},
		"/lib/libc.so.6":  {Name: "glibc", Version: "2.44+r50+g1848099f063e-1", Type: "alpm"},
	}
	if !maps.Equal(got, want) {
		t.Fatalf("got %+v", got)
	}
	if c, err := p.Compare(ctx, "6.11.5.arch1-1", "6.11.6.arch1-1"); err != nil || c != -1 {
		t.Fatalf("%d %v", c, err)
	}
	if c, err := p.Compare(ctx, "2", "1"); err != nil || c != 1 {
		t.Fatalf("%d %v", c, err)
	}
	if err := p.Check(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestToolFailures(t *testing.T) {
	rpmdb := "error: rpmdb: BDB0113 Thread/process 2207/140061577549888 failed: BDB1507 Thread died in Berkeley DB library\n" +
		"error: db5 error(-30973) from dbenv->failchk: BDB0087 DB_RUNRECOVERY: Fatal error, run database recovery\n"
	for _, tc := range []struct {
		name, typ, cmd string
		res            Result
		installed      string // when set, Installed(installed) is called instead of Owners
	}{
		{"dpkg -S killed", "deb", "dpkg-query -S /usr/sbin/sshd", Result{ExitCode: -1}, ""},
		{"dpkg -W killed", "deb", "dpkg-query -W -f " + dpkgFormat + " linux-image-*", Result{ExitCode: -1}, "linux-image-*"},
		{"rpm db error", "rpm", "rpm -qf --qf " + rpmFormat + " /usr/sbin/sshd", Result{Stderr: []byte(rpmdb), ExitCode: 1}, ""},
		{"rpm db error and not owned", "rpm", "rpm -qf --qf " + rpmFormat + " /usr/sbin/sshd",
			Result{Stdout: []byte("file /usr/sbin/sshd is not owned by any package\n"), Stderr: []byte(rpmdb), ExitCode: 1}, ""},
		{"rpm -q db error", "rpm", "rpm -q --qf " + rpmFormat + " kernel-core", Result{Stderr: []byte(rpmdb), ExitCode: 1}, "kernel-core"},
		{"apk db error", "apk", "apk info --who-owns /usr/sbin/sshd",
			Result{Stderr: []byte("ERROR: Failed to open apk database: Permission denied\n"), ExitCode: 1}, ""},
		{"apk killed", "apk", "apk info --who-owns /usr/sbin/sshd", Result{ExitCode: -1}, ""},
		{"pacman unreadable files list", "alpm", "pacman -Qo /usr/sbin/sshd", Result{Stderr: []byte(
			"error: could not open file /var/lib/pacman/local/openssh-9.9p2-1/files: No such file or directory\n" +
				"error: No package owns /usr/sbin/sshd\n"), ExitCode: 1}, ""},
		{"pacman killed", "alpm", "pacman -Qo /usr/sbin/sshd", Result{ExitCode: -1}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeRunner{t: t, resp: map[string]Result{tc.cmd: tc.res}}
			tool := New(tc.typ, f.run)
			var err error
			if tc.installed != "" {
				_, err = tool.Installed(ctx, tc.installed)
			} else {
				_, err = tool.Owners(ctx, []string{"/usr/sbin/sshd"})
			}
			if err == nil {
				t.Fatal("a tool failure must be an error")
			}
		})
	}
}

func TestMissingFileIsUnowned(t *testing.T) {
	for _, tc := range []struct {
		typ, path, cmd string
		res            Result
	}{
		{"rpm", "/usr/lib64/libgone.so.1", "rpm -qf --qf " + rpmFormat + " /usr/lib64/libgone.so.1",
			Result{Stderr: []byte("error: file /usr/lib64/libgone.so.1: No such file or directory\n"), ExitCode: 1}},
		{"alpm", "/usr/lib/libgone.so.1", "pacman -Qo /usr/lib/libgone.so.1",
			Result{Stderr: []byte("error: failed to read file '/usr/lib/libgone.so.1': No such file or directory\n"), ExitCode: 1}},
	} {
		f := &fakeRunner{t: t, resp: map[string]Result{tc.cmd: tc.res}}
		if got, err := New(tc.typ, f.run).Owners(ctx, []string{tc.path}); err != nil || len(got) != 0 {
			t.Errorf("%s: %+v %v", tc.typ, got, err)
		}
	}
}

func TestNew(t *testing.T) {
	for _, pt := range []string{"deb", "rpm", "apk", "alpm"} {
		if tool := New(pt, Exec); tool == nil || tool.Type() != pt {
			t.Errorf("New(%q) = %v", pt, tool)
		}
	}
	if New("", Exec) != nil {
		t.Error("an unknown package type has no tool")
	}
}
