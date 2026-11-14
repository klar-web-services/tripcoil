package inventory

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/klar-web-services/tripcoil/internal/osrel"
	"github.com/klar-web-services/tripcoil/internal/pkgtool"
	"github.com/klar-web-services/tripcoil/internal/problem"
)

type kernelCollector struct {
	root     string
	release  osrel.Release
	resolver *pkgtool.Resolver // nil when the package tool is unavailable
	distro   Distro
}

var (
	// debianRunning finds the package version a Debian kernel prints at the end of /proc/version,
	// "... #1 SMP PREEMPT_DYNAMIC Debian 6.1.119-1 (2024-11-22)". Kernels Debian did not build
	// (custom, Proxmox) end differently; their "gcc (Debian 12.2.0-14)" must not match.
	debianRunning = regexp.MustCompile(`Debian (\S+) \(\d{4}-\d{2}-\d{2}\)\s*$`)
	// upstreamLead keeps a release candidate's -rcN: 7.4.0-rc1 in 7.4.0-rc1-1-mainline.
	upstreamLead = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)?(?:-rc\d+)?`)
	// fedoraRC finds a Fedora rawhide release candidate, 6.13-rc7 in 6.13.0-0.rc7.56.fc42.x86_64.
	// A merge-window snapshot is -0.rc0., which gives an -rc0 the kernel CNA matching rejects.
	fedoraRC = regexp.MustCompile(`^(\d+\.\d+)\.0-0\.(rc\d+)\.`)
	// rpmKernelName matches the distributions' own kernel packages, as listed from the real
	// repositories on 2026-11-14: RHEL family kernel, kernel-core, kernel-modules(-core),
	// kernel-debug(-core), kernel-rt(-core), kernel-uki-virt, Oracle's kernel-uek(-core); Amazon
	// Linux 2023 kernel6.12, kernel6.18; SUSE kernel-default(-base), kernel-azure, kernel-rt,
	// kernel-kvmsmall, kernel-64kb. Third-party ones such as ELRepo's kernel-ml do not match. A
	// distribution flavor missing here is matched by upstream version: noisier, never silent.
	rpmKernelName = regexp.MustCompile(`^kernel(\d+\.\d+)?(-(core|modules|modules-core|debug|debug-core|debug-modules|debug-modules-core|rt|rt-core|rt_debug|uki-virt|default|default-base|azure|kvmsmall|64kb|64k|64k-core|uek|uek-core))?$`)
	// debKernelName matches Debian's and Ubuntu's own kernel packages, <prefix>-<abi>-<flavor>.
	// ABIs: 6.1.0-28 (Debian 12), 6.12.117+deb13 (Debian 13), 6.12.95+deb12 and 6.1.0-0.deb11.17
	// (backports), 5.15.0-91 (Ubuntu, where linux-modules-* owns modules.builtin). A dash ABI
	// always has patch level 0, so Liquorix's 7.0.9-1 and Ubuntu mainline's 6.12.5-061205 do not
	// match. Metapackages such as linux-image-amd64 do not match.
	debKernelName = regexp.MustCompile(`^(linux-(?:image-unsigned|image|modules))-(\d+\.\d+\.0-\d+(?:\.deb\d+\.\d+)?|\d+\.\d+\.\d+(?:\+deb\d+|\+bpo))-(.+)$`)
	// debKernelFlavor splits any deb kernel package into <prefix>-<abi>-<flavor> to find installed
	// kernels of the same flavor: the distributions' own and also pve-kernel-5.15.131-2-pve,
	// proxmox-kernel-6.8.12-4-pve-signed, linux-image-6.6.51+rpt-rpi-v8 (Raspberry Pi) and Kali's
	// linux-image-6.11.2-amd64. Metapackages (linux-image-amd64, proxmox-kernel-6.8) do not match.
	debKernelFlavor = regexp.MustCompile(`^(.+?)-(\d+\.\d+\.\d+[^-]*(?:-\d+(?:\.[^-]+)?)?)-(.+)$`)
)

func (k kernelCollector) collect(ctx context.Context) (Item, Origin, []problem.Problem) {
	it := Item{ID: KernelItemID, Kind: KindKernel, Name: "kernel"}
	rel := readTrimmed(k.root, "proc/sys/kernel/osrelease")
	it.Release = rel
	it.Modules = readModules(k.root)
	family := k.release.Family()
	modDir, modDirExists := modulesDir(k.root, rel)
	var problems []problem.Problem
	pkg, err := k.kernelPackage(ctx, modDir, modDirExists)
	if err != nil {
		if !interrupted(ctx, err) {
			problems = append(problems, problem.New(problem.Error, problem.PackageToolFailed, "inventory",
				"the package tool failed, so the running kernel's package is unknown: %v", err))
		}
		// As without a package tool: a kernel matched through its package is unresolved.
		k.resolver = nil
	}
	var distroBuild bool
	it.RunningVersion, it.UpstreamVersion, distroBuild = runningVersions(family, rel,
		readTrimmed(k.root, "proc/version"), readTrimmed(k.root, "proc/version_signature"), pkg)
	var rebootProblems []problem.Problem
	it.RebootReasons, rebootProblems = k.rebootReasons(ctx, family, modDir, modDirExists, pkg, it.RunningVersion)
	problems = append(problems, rebootProblems...)
	pending := len(it.RebootReasons) > 0
	it.RebootPending = &pending
	o := k.origin(family, pkg, distroBuild, rel, it.UpstreamVersion)
	it.Origins = []string{o.ID}
	return it, o, problems
}

// kernelPackage is the package that owns modules.builtin in the running release's modules
// directory: one file, so one package even where several own parts of the directory.
func (k kernelCollector) kernelPackage(ctx context.Context, modDir string, exists bool) (*pkgtool.Package, error) {
	if k.resolver == nil || !exists {
		return nil, nil
	}
	builtin := modDir + "/modules.builtin"
	owners, err := k.resolver.Owners(ctx, []string{builtin})
	if err != nil {
		return nil, err
	}
	if p, ok := owners[builtin]; ok {
		return &p, nil
	}
	return nil, nil
}

// runningVersions also reports whether the running kernel carries the build marker of Debian's
// or Ubuntu's own kernels: the /proc/version trailer or /proc/version_signature.
func runningVersions(family osrel.Family, rel, procVersion, signature string, pkg *pkgtool.Package) (running, upstream string, distroBuild bool) {
	running, upstream = rel, upstreamLead.FindString(rel)
	if pkg != nil {
		running = pkg.Version
	}
	switch family {
	case osrel.Debian:
		if m := debianRunning.FindStringSubmatch(procVersion); m != nil {
			running = m[1]
			// Debian versions a release candidate as 6.13~rc7.
			upstream = upstreamLead.FindString(strings.Replace(withoutEpoch(running), "~rc", "-rc", 1))
			distroBuild = true
		}
	case osrel.Fedora:
		if m := fedoraRC.FindStringSubmatch(rel); m != nil {
			upstream = m[1] + "-" + m[2]
		}
	case osrel.Ubuntu:
		// "Ubuntu 5.15.0-91.101-generic 5.15.131": package version plus flavor, then upstream.
		if f := strings.Fields(signature); len(f) == 3 && f[0] == "Ubuntu" {
			running = strings.TrimSuffix(f[1], "-"+kernelFlavor(rel))
			upstream = f[2]
			distroBuild = true
		}
	}
	return running, upstream, distroBuild
}

// withoutEpoch drops a package epoch: "1:6.6.51-1+rpt3" becomes "6.6.51-1+rpt3".
func withoutEpoch(v string) string {
	if i := strings.Index(v, ":"); i > 0 {
		if _, err := strconv.Atoi(v[:i]); err == nil {
			return v[i+1:]
		}
	}
	return v
}

// distroKernel reports whether pkg is the distribution's own kernel package, which its
// advisories cover. A third-party kernel (Proxmox, ELRepo, Raspberry Pi, a bindeb-pkg build)
// is matched by upstream version instead, so it is never shown as clean by default. A deb kernel
// also needs the distribution's build marker, because mainline and third-party builds of an x.y.0
// release can carry the same names.
func distroKernel(pkg pkgtool.Package, distroBuild bool) bool {
	switch pkg.Type {
	case "deb":
		return distroBuild && debKernelName.MatchString(pkg.Name)
	case "rpm":
		return rpmKernelName.MatchString(pkg.Name)
	}
	return false
}

// kernelFlavor is what follows the ABI in a Debian or Ubuntu release: "amd64" in 6.1.0-28-amd64.
func kernelFlavor(rel string) string {
	if parts := strings.SplitN(rel, "-", 3); len(parts) == 3 {
		return parts[2]
	}
	return ""
}

func (k kernelCollector) rebootReasons(ctx context.Context, family osrel.Family, modDir string, modDirExists bool, pkg *pkgtool.Package, running string) ([]string, []problem.Problem) {
	var reasons []string
	if !modDirExists {
		reasons = append(reasons, fmt.Sprintf("the running kernel's modules directory %s is gone, so a newer kernel was installed", modDir))
	}
	if pkg == nil || k.resolver == nil {
		return reasons, nil
	}
	var problems []problem.Problem
	toolFailed := func(what string, err error) {
		if interrupted(ctx, err) {
			return
		}
		problems = append(problems, problem.New(problem.Error, problem.PackageToolFailed, "inventory",
			"the package tool could not %s, so whether a newer installed kernel needs a reboot is unknown: %v", what, err))
	}
	tool := k.resolver.Tool
	if (family == osrel.Debian || family == osrel.Ubuntu) && pkg.Version != running {
		reasons = append(reasons, fmt.Sprintf("kernel package %s is now at %s, but the running kernel is %s", pkg.Name, pkg.Version, running))
	}
	var siblings []pkgtool.Package
	switch tool.Type() {
	case "deb":
		m := debKernelFlavor.FindStringSubmatch(pkg.Name)
		if m == nil {
			break
		}
		all, err := tool.Installed(ctx, m[1]+"-*")
		if err != nil {
			toolFailed("list the installed kernels", err)
			break
		}
		for _, s := range all {
			if sm := debKernelFlavor.FindStringSubmatch(s.Name); sm != nil && sm[1] == m[1] && sm[3] == m[3] && s.Name != pkg.Name {
				siblings = append(siblings, s)
			}
		}
	case "rpm":
		all, err := tool.Installed(ctx, pkg.Name)
		if err != nil {
			toolFailed("list the installed kernels", err)
			break
		}
		for _, s := range all {
			if s.Version != pkg.Version {
				siblings = append(siblings, s)
			}
		}
	}
	var compareErr error
	for _, s := range siblings {
		c, err := tool.Compare(ctx, s.Version, running)
		if err != nil {
			compareErr = err
		} else if c > 0 {
			reasons = append(reasons, fmt.Sprintf("a newer kernel package is installed: %s %s", s.Name, s.Version))
		}
	}
	if compareErr != nil {
		toolFailed("compare kernel versions", compareErr)
	}
	return reasons, problems
}

func (k kernelCollector) origin(family osrel.Family, pkg *pkgtool.Package, distroBuild bool, rel, upstream string) Origin {
	if family.BackportsKernelFixes() {
		if pkg != nil && distroKernel(*pkg, distroBuild) {
			return packageOrigin(k.distro, *pkg)
		}
		if pkg == nil && k.resolver == nil {
			return Origin{ID: UnresolvedOriginID("kernel"), Kind: OriginUnresolved,
				Reason: "package ownership is unknown because the package tool failed, and this distribution's kernel is matched through its package"}
		}
	}
	if upstream == "" {
		return Origin{ID: UnresolvedOriginID("kernel"), Kind: OriginUnresolved, Reason: fmt.Sprintf("the kernel release %q has no version number", rel)}
	}
	return Origin{ID: KernelUpstreamOriginID(upstream), Kind: OriginKernelUpstream, UpstreamVersion: upstream}
}

// modulesDir returns the running release's modules directory and whether it exists.
func modulesDir(root, rel string) (string, bool) {
	for _, d := range []string{"/usr/lib/modules/" + rel, "/lib/modules/" + rel} {
		if fi, err := os.Stat(filepath.Join(root, d)); err == nil && fi.IsDir() {
			return d, true
		}
	}
	if fi, err := os.Stat(filepath.Join(root, "usr/lib/modules")); err == nil && fi.IsDir() {
		return "/usr/lib/modules/" + rel, false
	}
	return "/lib/modules/" + rel, false
}

func readTrimmed(root, p string) string {
	data, err := os.ReadFile(filepath.Join(root, p))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readModules(root string) []string {
	var out []string
	for _, line := range strings.Split(readTrimmed(root, "proc/modules"), "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			out = append(out, f[0])
		}
	}
	sort.Strings(out)
	return out
}
