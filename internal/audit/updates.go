package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/klar-web-services/tripcoil/internal/grype"
	"github.com/klar-web-services/tripcoil/internal/inventory"
)

// What is known about the image a tag points to now.
const (
	// UpdateScanned: the tag points to another image than the one that runs, and that image was scanned.
	UpdateScanned = "scanned"
	// UpdateCurrent: the tag still points to the image that runs, so pulling changes nothing.
	UpdateCurrent = "current"
	// UpdateWaiting: the tag points to another image, which this run did not scan.
	UpdateWaiting = "waiting"
	// UpdateFailed: the tag points to another image, which could not be scanned.
	UpdateFailed = "failed"
	// UpdateUnknown: whether the tag moved could not be found out.
	UpdateUnknown = "unknown"

	AfterCleared = "cleared"
	AfterRemains = "remains"
)

// maxNewImages is how many newer images one run downloads. The others wait for the next run; an
// image that was scanned once is not downloaded again.
var maxNewImages = 3

// Update says what pulling an image's tag would bring: of the action's findings, how many the
// newer image no longer has and how many it still has. Only State and Reason are set when the
// newer image was not scanned.
type Update struct {
	State string `json:"state"`
	// Ref is the newer image, as repository@digest.
	Ref              string `json:"ref,omitempty"`
	Reason           string `json:"reason,omitempty"`
	Clears           int    `json:"clears"`
	Remains          int    `json:"remains"`
	RemainsExploited int    `json:"remainsExploited"`
}

// newer is what a newer image holds.
type newer struct {
	versions map[string][]string // package name → its versions
	vulns    map[string]bool     // vulnerability ID, NUL, package name
}

var hexDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// repository is the repository of a tagged image reference: "ghcr.io/acme/shop" of
// "ghcr.io/acme/shop:1.2". A reference by digest, or without a tag, has none.
func repository(ref string) (string, bool) {
	i := strings.LastIndex(ref, ":")
	if i <= 0 || strings.Contains(ref, "@") || strings.Contains(ref[i:], "/") {
		return "", false
	}
	return ref[:i], true
}

// reason is an error as one short line.
func reason(what string, err error) string {
	return Cut(what+": "+strings.Join(strings.Fields(err.Error()), " "), MaxNote)
}

// update finds out whether an image's tag points to a newer image, and what that image holds.
func (au *auditor) update(ctx context.Context, o inventory.Origin) (*Update, *newer) {
	repo, ok := repository(o.Ref)
	if !ok {
		return &Update{State: UpdateUnknown, Reason: "the image is not referred to by a tag"}, nil
	}
	running, err := au.d.Images.RepoDigests(ctx, o.ImageID)
	switch {
	case err != nil:
		return &Update{State: UpdateUnknown, Reason: reason("Docker could not be asked about the image", err)}, nil
	case len(running) == 0:
		return &Update{State: UpdateUnknown, Reason: "the image was built or loaded on this machine, not pulled"}, nil
	}
	digest, err := au.d.Images.TagDigest(ctx, o.Ref)
	switch {
	case err != nil:
		return &Update{State: UpdateUnknown, Reason: reason("the registry could not be asked where the tag points", err)}, nil
	case !hexDigest.MatchString(digest):
		return &Update{State: UpdateUnknown, Reason: "the registry named no usable digest"}, nil
	case slices.Contains(running, digest):
		return &Update{State: UpdateCurrent}, nil
	}
	up := &Update{State: UpdateScanned, Ref: repo + "@" + digest}
	key := "newer-" + strings.TrimPrefix(digest, "sha256:")
	if err := os.MkdirAll(au.scanDir(), 0o700); err != nil {
		return &Update{State: UpdateFailed, Ref: up.Ref, Reason: reason("the newer image could not be scanned", err)}, nil
	}
	raw := filepath.Join(au.scanDir(), key+".json")
	defer os.Remove(raw)
	var rep *grype.Report
	var data []byte
	if sbom, ok := au.cache.get(key); ok {
		if data, _, err = readCached(sbom); err == nil {
			rep, err = au.d.Grype.Match(ctx, sbom, raw, false)
		}
		if err != nil {
			au.cache.remove(key)
		}
	}
	if rep == nil {
		if au.newImages >= maxNewImages {
			return &Update{State: UpdateWaiting, Ref: up.Ref, Reason: fmt.Sprintf("one run downloads at most %d newer images; this one waits for the next run", maxNewImages)}, nil
		}
		au.newImages++
		tmp := filepath.Join(au.scanDir(), key+".cdx.json")
		defer os.Remove(tmp)
		// The registry: source reads the image from its registry into Grype's own temporary folder.
		// Docker's images and tags stay as they are.
		if rep, err = au.d.Grype.Scan(ctx, "registry:"+up.Ref, raw, tmp); err == nil {
			data, err = grype.ReadSBOM(tmp, maxSBOMSize)
		}
		if err == nil {
			data, err = grype.StripSBOM(data)
		}
		if err != nil {
			return &Update{State: UpdateFailed, Ref: up.Ref, Reason: reason("the newer image could not be scanned", err)}, nil
		}
		_ = au.cache.put(key, data)
	}
	pkgs, err := grype.SBOMPackages(data)
	if err != nil {
		return &Update{State: UpdateFailed, Ref: up.Ref, Reason: reason("the newer image's package list could not be read", err)}, nil
	}
	nw := &newer{versions: map[string][]string{}, vulns: map[string]bool{}}
	for _, p := range pkgs {
		if !slices.Contains(nw.versions[p.Name], p.Version) {
			nw.versions[p.Name] = append(nw.versions[p.Name], p.Version)
		}
	}
	for _, m := range rep.Matches {
		nw.vulns[vulnerability(m.Vulnerability, m.Related).ID+"\x00"+m.Artifact.Name] = true
	}
	return up, nw
}

// setUpdates gives each image action what pulling its tag would bring, each of its changes the
// version the newer image has, and each of its findings whether the newer image still has it.
func (au *auditor) setUpdates(ctx context.Context) {
	if !au.d.NewImages || au.d.Images == nil {
		return
	}
	a := au.a
	byID := map[string]int{}
	for i, act := range a.Actions {
		if act.Kind == ActionImage {
			byID[act.ID] = i
		}
	}
	for _, o := range au.inv.Origins {
		i, ok := byID[ActionID(ActionImage, o.ID)]
		if !ok || o.Kind != inventory.OriginImage || ctx.Err() != nil {
			continue
		}
		up, nw := au.update(ctx, o)
		act := &a.Actions[i]
		act.Update = up
		if nw == nil {
			continue
		}
		// A change reaches its fix when none of its package's fixable findings is left.
		short := map[string]bool{}
		for k := range a.Findings {
			f := &a.Findings[k]
			if f.Action != act.ID {
				continue
			}
			if !nw.vulns[f.Vulnerability.ID+"\x00"+f.Package.Name] {
				f.AfterUpdate = AfterCleared
				up.Clears++
				continue
			}
			f.AfterUpdate = AfterRemains
			up.Remains++
			if f.Vulnerability.KnownExploited {
				up.RemainsExploited++
			}
			if f.Fix.State == "fixed" {
				short[f.Package.Name+"\x00"+f.Package.Version] = true
			}
		}
		for k := range act.Changes {
			c := &act.Changes[k]
			switch versions := nw.versions[c.Name]; len(versions) {
			case 0:
				c.Gone = true
			case 1:
				c.Gets = versions[0]
				c.Reaches = c.To != "" && !short[c.Name+"\x00"+c.From]
			}
		}
	}
}
