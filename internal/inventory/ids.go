package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/klar-web-services/tripcoil/internal/pkgtool"
)

const KernelItemID = "kernel"

func shortHash(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:])[:12]
}

func ProcessItemID(exe, appDir string) string { return "proc:" + shortHash("process", exe, appDir) }

func ContainerItemID(name string) string { return "container:" + name }

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

func BinaryOriginID(sha string) string { return "binary:" + sha }

func AppDirOriginID(path string) string { return "appdir:" + path }

func ImageOriginID(imageID string) string { return "image:" + imageID }

func KernelUpstreamOriginID(version string) string { return "kernel-upstream:" + version }

func UnresolvedOriginID(subject string) string {
	return "unresolved:" + shortHash("unresolved", subject)
}
