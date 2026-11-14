package pkgtool

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestDetectAliases(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"usr/lib", "usr/bin", "sbin"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("usr/lib", filepath.Join(root, "lib")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin", filepath.Join(root, "bin")); err != nil {
		t.Fatal(err)
	}
	got := DetectAliases(root)
	want := []Alias{{Canonical: "/usr/bin/", Alt: "/bin/"}, {Canonical: "/usr/lib/", Alt: "/lib/"}}
	if !slices.Equal(got, want) {
		t.Fatalf("got %+v", got)
	}
}

func TestResolverNeverAsksAboutNewlinePaths(t *testing.T) {
	f := &fakeRunner{t: t, resp: map[string]Result{
		"dpkg-query -S /usr/bin/dpkg":              out("dpkg: /usr/bin/dpkg\n"),
		"dpkg-query -W -f " + dpkgFormat + " dpkg": out("ii \tdpkg\tdpkg\tamd64\t1.21.23\n"),
	}}
	r := Resolver{Tool: dpkg{f.run}, Aliases: []Alias{{Canonical: "/usr/bin/", Alt: "/bin/"}}}
	forged := "/usr/bin/a\nnginx-core: /usr/sbin/nginx"
	got, err := r.Owners(ctx, []string{"/usr/bin/dpkg", forged})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Package{"/usr/bin/dpkg": {Name: "dpkg", Version: "1.21.23", Arch: "amd64", Type: "deb"}}
	if !maps.Equal(got, want) {
		t.Fatalf("got %+v", got)
	}
	if r.Owned(ctx, forged) {
		t.Fatal("a path with a newline is never owned")
	}
}

func TestResolverTriesAliases(t *testing.T) {
	f := &fakeRunner{t: t, resp: map[string]Result{
		"dpkg-query -S /usr/bin/dpkg /usr/lib/x86_64-linux-gnu/libc.so.6 /usr/bin/nonexistent": {
			Stdout: []byte("dpkg: /usr/bin/dpkg\n"),
			Stderr: []byte("dpkg-query: no path found matching pattern /usr/lib/x86_64-linux-gnu/libc.so.6\n" +
				"dpkg-query: no path found matching pattern /usr/bin/nonexistent\n"),
			ExitCode: 1,
		},
		"dpkg-query -W -f " + dpkgFormat + " dpkg": out("ii \tdpkg\tdpkg\tamd64\t1.21.23\n"),
		"dpkg-query -S /lib/x86_64-linux-gnu/libc.so.6 /bin/nonexistent": {
			Stdout:   []byte("libc6:amd64: /lib/x86_64-linux-gnu/libc.so.6\n"),
			Stderr:   []byte("dpkg-query: no path found matching pattern /bin/nonexistent\n"),
			ExitCode: 1,
		},
		"dpkg-query -W -f " + dpkgFormat + " libc6:amd64": out("ii \tlibc6:amd64\tlibc6\tamd64\t2.36-9+deb12u14\n"),
	}}
	r := Resolver{Tool: dpkg{f.run}, Aliases: []Alias{{Canonical: "/usr/bin/", Alt: "/bin/"}, {Canonical: "/usr/lib/", Alt: "/lib/"}}}
	got, err := r.Owners(ctx, []string{"/usr/bin/dpkg", "/usr/lib/x86_64-linux-gnu/libc.so.6", "/usr/bin/nonexistent"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Package{
		"/usr/bin/dpkg":                       {Name: "dpkg", Version: "1.21.23", Arch: "amd64", Type: "deb"},
		"/usr/lib/x86_64-linux-gnu/libc.so.6": {Name: "libc6", Version: "2.36-9+deb12u14", Arch: "amd64", Type: "deb"},
	}
	if !maps.Equal(got, want) {
		t.Fatalf("got %+v", got)
	}
}
