package audit

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/osrel"
)

const maxNamed = 5

type remediation struct {
	family  osrel.Family
	version string
	init    string
	origins map[string]inventory.Origin
	users   map[string][]inventory.Item
	kernel  map[string]bool
}

func newRemediation(family osrel.Family, inv *inventory.Inventory) remediation {
	r := remediation{family: family, version: inv.Host.Distro.VersionID, init: inv.Host.Init, origins: map[string]inventory.Origin{}, users: map[string][]inventory.Item{}, kernel: map[string]bool{}}
	for _, o := range inv.Origins {
		r.origins[o.ID] = o
	}
	for _, it := range inv.Items {
		for _, id := range it.Origins {
			r.users[id] = append(r.users[id], it)
			if it.Kind == inventory.KindKernel {
				r.kernel[id] = true
			}
		}
	}
	return r
}

func (r remediation) itemIDs(origin string) []string {
	ids := []string{}
	for _, it := range r.users[origin] {
		ids = append(ids, it.ID)
	}
	return ids
}

func (r remediation) line(f Finding) string {
	o := r.origins[f.Origin]
	fixed := f.Fix.State == "fixed" && len(f.Fix.Versions) > 0
	switch {
	case r.kernel[f.Origin]:
		to := strings.Join(f.Fix.Versions, " or ")
		if f.Fix.State == "wont-fix" {
			return "No fix will be released for this kernel (wont-fix)."
		}
		if !fixed {
			return "No fixed kernel version is known yet."
		}
		cmd := ""
		if c := r.systemUpgrade(); c != "" && (o.Kind == inventory.OriginPackage || r.kernelPackaged()) {
			cmd = " (" + c + ")"
		}
		if o.Kind == inventory.OriginKernelUpstream {
			return fmt.Sprintf("Upgrade the kernel to Linux %s or later%s, then reboot.", to, cmd)
		}
		return fmt.Sprintf("Upgrade the kernel to %s or later%s, then reboot.", to, cmd)
	case !fixed:
		return noFix(f)
	}
	fix, above := fixVersion(f)
	orLater := fix
	if !above {
		orLater += " or later"
	}
	switch o.Kind {
	case inventory.OriginPackage:
		line := fmt.Sprintf("Upgrade %s to %s", f.Package.Name, fix)
		if c := r.packageUpgrade(f.Package.Name); c != "" {
			line += " (" + c + ")"
		}
		line += r.restart(f.Origin) + "."
		if o.RunningOlderCopy {
			line += " Some of its processes still run an older copy from before the last upgrade; restart them either way."
		}
		return line
	case inventory.OriginBinary:
		return fmt.Sprintf("Replace or rebuild %s with %s %s%s.", named(o.Paths, "the binary"), f.Package.Name, orLater, r.restart(f.Origin))
	case inventory.OriginAppDir:
		return fmt.Sprintf("Upgrade %s in %s to %s%s.", f.Package.Name, o.Path, fix, r.restart(f.Origin))
	case inventory.OriginImage:
		return fmt.Sprintf("Rebuild %s or pull a newer image with %s %s, then recreate %s.", imageName(o), f.Package.Name, orLater, r.recreate(f.Origin))
	}
	return fmt.Sprintf("Upgrade %s to %s.", f.Package.Name, fix)
}

func fixVersion(f Finding) (string, bool) {
	installed, typ := f.Package.Version, f.Package.Type
	// Debian's fixed versions are its source packages', which have no epoch where the binary
	// package has one: bsdutils 1:2.38.1-5+b1 is fixed in util-linux 2.38.1-5+deb12u1.
	installedEpoch, _, ok := strings.Cut(installed, ":")
	adoptEpoch := typ == "deb" && ok && allDigits(installedEpoch)
	key := func(v string) string {
		if e, _, ok := strings.Cut(v, ":"); adoptEpoch && !(ok && allDigits(e)) {
			return installedEpoch + ":" + v
		}
		return v
	}
	var above []string
	for _, v := range f.Fix.Versions {
		if installed != "" && compareVersions(typ, key(v), installed) > 0 && !slices.Contains(above, v) {
			above = append(above, v)
		}
	}
	if len(above) == 0 {
		return strings.Join(f.Fix.Versions, " or "), false
	}
	slices.SortStableFunc(above, func(x, y string) int { return compareVersions(typ, key(x), key(y)) })
	fix := above[0] + " or later"
	if len(above) > 1 {
		fix += " (also fixed in " + andList(above[1:]) + ")"
	}
	return fix, true
}

func andList(s []string) string {
	if len(s) == 1 {
		return s[0]
	}
	return strings.Join(s[:len(s)-1], ", ") + " and " + s[len(s)-1]
}

func noFix(f Finding) string {
	if f.Fix.State == "wont-fix" {
		return fmt.Sprintf("No fix will be released for %s %s (wont-fix).", f.Package.Name, f.Package.Version)
	}
	return fmt.Sprintf("No fix is known for %s %s yet.", f.Package.Name, f.Package.Version)
}

// kernelPackaged reports whether the running kernel came from a package, so the distribution's
// tool upgrades it. The Inventory sets the running version to the release itself when no package
// owns the kernel, so a running version that differs from the release is a package's.
func (r remediation) kernelPackaged() bool {
	for id := range r.kernel {
		for _, it := range r.users[id] {
			if it.Kind == inventory.KindKernel && it.RunningVersion != it.Release {
				return true
			}
		}
	}
	return false
}

// restart names the systemd units of an origin's processes, or the processes without a unit. A
// user's own manager (user@1000.service) is never named: restarting it ends the user's session,
// so a process below it is named instead. systemd as PID 1 re-executes itself instead, and so do
// the users' managers, which run the same executable. Another init, such as busybox, is named.
func (r remediation) restart(origin string) string {
	var units, names []string
	for _, it := range r.users[origin] {
		if it.Kind != inventory.KindProcess {
			continue
		}
		own := slices.DeleteFunc(slices.Clone(it.Units), func(u string) bool { return strings.HasPrefix(u, "user@") })
		units = append(units, own...)
		pid1 := slices.ContainsFunc(it.Processes, func(p inventory.Process) bool { return p.PID == 1 })
		switch {
		case pid1 && (it.Name == "systemd" || r.init == "systemd"):
			how := "systemctl daemon-reexec"
			if len(it.Processes) > 1 {
				how += "; for each user manager: systemctl --user -M <user>@ daemon-reexec"
			}
			names = append(names, "systemd ("+how+")")
		case len(own) == 0:
			names = append(names, it.Name)
		}
	}
	slices.Sort(units)
	slices.Sort(names)
	all := append(slices.Compact(units), slices.Compact(names)...)
	if len(all) == 0 {
		return ""
	}
	return ", then restart " + list(all)
}

func (r remediation) recreate(origin string) string {
	var how []string
	for _, it := range r.users[origin] {
		if it.Kind != inventory.KindContainer {
			continue
		}
		if cmd := composeRecreate(it.Compose); cmd != "" {
			how = append(how, fmt.Sprintf("%s (%s)", it.Name, cmd))
		} else {
			how = append(how, it.Name)
		}
	}
	slices.Sort(how)
	switch len(how) {
	case 0:
		return "its containers"
	case 1:
		return "the container " + how[0]
	}
	return "the containers " + list(how)
}

var (
	composeProject = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	composeService = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)
	plainPath      = regexp.MustCompile(`^/[A-Za-z0-9._/+-]*$`)
)

// composeRecreate is the command that recreates a container's Compose service, or "". The Compose
// labels it is built from can come from the image, and an admin may run the command as root, so
// it is only written when every part follows the rules above. When the directory or a file breaks
// them, or there is no file, there is no command at all: without that part, the command would
// depend on where it is run, and Compose also searches the parent directories. Compose always
// records its files, so labels without them came from the image.
func composeRecreate(c *inventory.Compose) string {
	if c == nil || len(c.ConfigFiles) == 0 || !composeProject.MatchString(c.Project) || !composeService.MatchString(c.Service) {
		return ""
	}
	cmd := "docker compose -p " + c.Project
	if c.WorkingDir != "" {
		if !plainPath.MatchString(c.WorkingDir) {
			return ""
		}
		cmd += " --project-directory " + c.WorkingDir
	}
	for _, f := range c.ConfigFiles {
		if !plainPath.MatchString(f) {
			return ""
		}
		cmd += " -f " + f
	}
	return cmd + " up -d --force-recreate --no-deps " + c.Service
}

func list(names []string) string {
	if len(names) > maxNamed {
		return strings.Join(names[:maxNamed], ", ") + fmt.Sprintf(" and %d more", len(names)-maxNamed)
	}
	return strings.Join(names, ", ")
}

func named(paths []string, fallback string) string {
	switch len(paths) {
	case 0:
		return fallback
	case 1:
		return paths[0]
	}
	return fmt.Sprintf("%s (and %d more paths)", paths[0], len(paths)-1)
}

func imageName(o inventory.Origin) string {
	if o.Ref != "" {
		return o.Ref
	}
	return o.ImageID
}

// packageUpgrade is the command that upgrades one package. apt and apk do not refresh their package
// lists by themselves, so the command does (dnf, yum and zypper refresh expired metadata). On the
// RHEL family yum works from 7 to 10 (it is dnf from 8 on). Amazon Linux 2023 locks its release,
// so fixes from a newer one need --releasever=latest. Arch does not support partial upgrades, so
// there it is a whole-system upgrade.
func (r remediation) packageUpgrade(pkg string) string {
	switch r.family {
	case osrel.Debian, osrel.Ubuntu:
		return "apt-get update && apt-get install --only-upgrade " + pkg
	case osrel.RHEL:
		return "yum update " + pkg
	case osrel.Fedora:
		return "dnf upgrade " + pkg
	case osrel.Amazon:
		if r.version == "2023" {
			return "dnf upgrade --releasever=latest " + pkg
		}
		return "yum update " + pkg
	case osrel.SUSE:
		return "zypper update " + pkg
	case osrel.Alpine:
		return "apk upgrade -U " + pkg
	case osrel.Arch:
		return "pacman -Syu"
	}
	return ""
}

func (r remediation) systemUpgrade() string {
	switch r.family {
	case osrel.Debian, osrel.Ubuntu:
		return "apt-get update && apt-get dist-upgrade"
	case osrel.RHEL:
		return "yum update"
	case osrel.Fedora:
		return "dnf upgrade"
	case osrel.Amazon:
		if r.version == "2023" {
			return "dnf upgrade --releasever=latest"
		}
		return "yum update"
	case osrel.SUSE:
		return "zypper update"
	case osrel.Alpine:
		return "apk upgrade -U"
	case osrel.Arch:
		return "pacman -Syu"
	}
	return ""
}
