package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/klar-web-services/tripcoil/internal/pkgtool"
)

// KernelItemID is the ID of the one kernel item.
const KernelItemID = "kernel"

func shortHash(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:])[:12]
}

// ProcessItemID identifies a host process item by executable and app directory, stable across runs.
func ProcessItemID(exe, appDir string) string { return "proc:" + shortHash("process", exe, appDir) }

// ContainerItemID identifies a container item by name.
func ContainerItemID(name string) string { return "container:" + name }

// PackageOriginID is a package URL with the distribution as namespace and qualifiers.
func PackageOriginID(d Distro, p pkgtool.Package) string {
	v := p.Version
	if p.Epoch != "" {
		v = p.Epoch + ":" + v
	}
	q := url.Values{}
	if p.Arch != "" {
		q.Set("arch", p.Arch)
	}
	distro := d.ID
	if d.VersionID != "" {
		distro += "-" + d.VersionID
	}
	q.Set("distro", distro)
	return fmt.Sprintf("pkg:%s/%s/%s@%s?%s", p.Type, url.PathEscape(d.ID), url.PathEscape(p.Name), url.PathEscape(v), q.Encode())
}

// BinaryOriginID identifies an unpackaged file by content.
func BinaryOriginID(sha string) string { return "binary:" + sha }

// AppDirOriginID identifies an app directory or jar by path.
func AppDirOriginID(path string) string { return "appdir:" + path }

// ImageOriginID identifies a container image by ID.
func ImageOriginID(imageID string) string { return "image:" + imageID }

// KernelUpstreamOriginID identifies a kernel matched by its upstream version.
func KernelUpstreamOriginID(version string) string { return "kernel-upstream:" + version }

// UnresolvedOriginID identifies something whose origin could not be resolved.
func UnresolvedOriginID(subject string) string {
	return "unresolved:" + shortHash("unresolved", subject)
}
