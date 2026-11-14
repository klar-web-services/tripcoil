// Package osrel reads /etc/os-release and maps the distribution to the family Tripcoil handles it as.
package osrel

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Release is the part of os-release Tripcoil uses.
type Release struct {
	ID         string   `json:"id"`
	VersionID  string   `json:"versionId,omitempty"`
	IDLike     []string `json:"idLike,omitempty"`
	PrettyName string   `json:"prettyName,omitempty"`
}

// Read reads root/etc/os-release, or root/usr/lib/os-release when the first is missing.
func Read(root string) (Release, error) {
	for _, p := range []string{"etc/os-release", "usr/lib/os-release"} {
		data, err := os.ReadFile(filepath.Join(root, p))
		if err == nil {
			return Parse(data), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return Release{}, err
		}
	}
	return Release{}, fmt.Errorf("no os-release file below %s", root)
}

// Parse reads os-release content.
func Parse(data []byte) Release {
	var r Release
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = unquote(v)
		switch k {
		case "ID":
			r.ID = strings.ToLower(v)
		case "VERSION_ID":
			r.VersionID = v
		case "ID_LIKE":
			r.IDLike = strings.Fields(strings.ToLower(v))
		case "PRETTY_NAME":
			r.PrettyName = v
		}
	}
	return r
}

func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		v = v[1 : len(v)-1]
	}
	return strings.NewReplacer(`\"`, `"`, `\\`, `\`, `\$`, `$`, "\\`", "`").Replace(v)
}

// Family is how Tripcoil treats a distribution.
type Family string

const (
	Debian  Family = "debian"
	Ubuntu  Family = "ubuntu"
	RHEL    Family = "rhel"
	Fedora  Family = "fedora"
	Amazon  Family = "amazon"
	SUSE    Family = "suse"
	Alpine  Family = "alpine"
	Arch    Family = "arch"
	Unknown Family = ""
)

// Family maps the release to a family, by ID first and then ID_LIKE.
func (r Release) Family() Family {
	is := func(ids ...string) bool {
		for _, id := range ids {
			if r.ID == id || slices.Contains(r.IDLike, id) {
				return true
			}
		}
		return false
	}
	switch {
	case is("ubuntu"):
		return Ubuntu
	case is("debian"):
		return Debian
	case r.ID == "amzn":
		return Amazon
	case is("rhel", "centos", "rocky", "almalinux") || r.ID == "ol":
		return RHEL
	case is("fedora"):
		return Fedora
	case strings.HasPrefix(r.ID, "opensuse") || is("sles", "suse"):
		return SUSE
	case is("alpine"):
		return Alpine
	case is("arch"):
		return Arch
	}
	return Unknown
}

// PackageType is the package format, named as Grype names it: deb, rpm, apk or alpm.
func (f Family) PackageType() string {
	switch f {
	case Debian, Ubuntu:
		return "deb"
	case RHEL, Fedora, Amazon, SUSE:
		return "rpm"
	case Alpine:
		return "apk"
	case Arch:
		return "alpm"
	}
	return ""
}

// BackportsKernelFixes reports whether the distribution backports fixes into its kernels, so the
// kernel is matched through its package and the distribution's advisories (spec section 6.3).
func (f Family) BackportsKernelFixes() bool {
	switch f {
	case Debian, Ubuntu, RHEL, Amazon, SUSE:
		return true
	}
	return false
}
