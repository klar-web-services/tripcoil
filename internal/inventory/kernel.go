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
	upstreamLead  = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)?`)
	// rpmKernelName matches the distributions' own kernel packages, as listed from the real
	// repositories on 2026-11-14: RHEL family kernel, kernel-core, kernel-modules(-core),
	// kernel-debug(-core), kernel-rt(-core), kernel-uki-virt, Oracle's kernel-uek(-core); Amazon
	// Linux 2023 kernel6.12, kernel6.18; SUSE kernel-default(-base), kernel-azure, kernel-rt,
	// kernel-kvmsmall, kernel-64kb. Third-party ones such as ELRepo's kernel-ml do not match. A
	// distribution flavor missing here is matched by upstream version: noisier, never silent.
	rpmKernelName = regexp.MustCompile(`^kernel(\d+\.\d+)?(-(core|modules|modules-core|debug|debug-core|debug-modules|debug-modules-core|rt|rt-core|rt_debug|uki-virt|default|default-base|azure|kvmsmall|64kb|64k|64k-core|uek|uek-core))?$`)
	// debKernelName splits <prefix>-<abi>-<flavor>. ABIs: 6.1.0-28 (Debian 12), 6.12.117+deb13
	// (Debian 13), 6.12.95+deb12 and 6.1.0-0.deb11.17 (backports), 5.15.0-91 (Ubuntu, where
	// linux-modules-* owns modules.builtin). Metapackages such as linux-image-amd64 do not match.
	debKernelName = regexp.MustCompile(`^(linux-(?:image-unsigned|image|modules))-(\d+\.\d+\.\d+(?:-\d+(?:\.deb\d+\.\d+)?|\+deb\d+|\+bpo))-(.+)$`)
)

func (k kernelCollector) collect(ctx context.Context) (Item, Origin) {
	it := Item{ID: KernelItemID, Kind: KindKernel, Name: "kernel"}
	rel := readTrimmed(k.root, "proc/sys/kernel/osrelease")
	it.Release = rel
	it.Modules = readModules(k.root)
	family := k.release.Family()
	modDir, modDirExists := modulesDir(k.root, rel)
	pkg := k.kernelPackage(ctx, modDir, modDirExists)
	it.RunningVersion, it.UpstreamVersion = runningVersions(family, rel,
		readTrimmed(k.root, "proc/version"), readTrimmed(k.root, "proc/version_signature"), pkg)
	it.RebootReasons = k.rebootReasons(ctx, family, modDir, modDirExists, pkg, it.RunningVersion)
	it.RebootPending = len(it.RebootReasons) > 0
	o := k.origin(family, pkg, rel, it.UpstreamVersion)
	it.Origins = []string{o.ID}
	return it, o
}

// kernelPackage is the package that owns modules.builtin in the running release's modules
// directory: one file, so one package even where several own parts of the directory.
func (k kernelCollector) kernelPackage(ctx context.Context, modDir string, exists bool) *pkgtool.Package {
	if k.resolver == nil || !exists {
		return nil
	}
	builtin := modDir + "/modules.builtin"
	owners, err := k.resolver.Owners(ctx, []string{builtin})
	if err != nil {
		return nil
	}
	if p, ok := owners[builtin]; ok {
		return &p
	}
	return nil
}

func runningVersions(family osrel.Family, rel, procVersion, signature string, pkg *pkgtool.Package) (running, upstream string) {
	running, upstream = rel, upstreamLead.FindString(rel)
	if pkg != nil {
		running = pkg.Version
	}
	switch family {
	case osrel.Debian:
		if m := debianRunning.FindStringSubmatch(procVersion); m != nil {
			running = m[1]
			upstream = upstreamLead.FindString(withoutEpoch(running))
		}
	case osrel.Ubuntu:
		// "Ubuntu 5.15.0-91.101-generic 5.15.131": package version plus flavor, then upstream.
		if f := strings.Fields(signature); len(f) == 3 && f[0] == "Ubuntu" {
			running = strings.TrimSuffix(f[1], "-"+kernelFlavor(rel))
			upstream = f[2]
		}
	}
	return running, upstream
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
// is matched by upstream version instead, so it is never shown as clean by default.
func distroKernel(pkg pkgtool.Package) bool {
	switch pkg.Type {
	case "deb":
		return debKernelName.MatchString(pkg.Name)
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

func (k kernelCollector) rebootReasons(ctx context.Context, family osrel.Family, modDir string, modDirExists bool, pkg *pkgtool.Package, running string) []string {
	var reasons []string
	if !modDirExists {
		reasons = append(reasons, fmt.Sprintf("the running kernel's modules directory %s is gone, so a newer kernel was installed", modDir))
	}
	if pkg == nil || k.resolver == nil {
		return reasons
	}
	tool := k.resolver.Tool
	if (family == osrel.Debian || family == osrel.Ubuntu) && pkg.Version != running {
		reasons = append(reasons, fmt.Sprintf("kernel package %s is now at %s, but the running kernel is %s", pkg.Name, pkg.Version, running))
	}
	var siblings []pkgtool.Package
	switch tool.Type() {
	case "deb":
		m := debKernelName.FindStringSubmatch(pkg.Name)
		if m == nil {
			break
		}
		all, err := tool.Installed(ctx, m[1]+"-*")
		if err != nil {
			break
		}
		for _, s := range all {
			if sm := debKernelName.FindStringSubmatch(s.Name); sm != nil && sm[1] == m[1] && sm[3] == m[3] && s.Name != pkg.Name {
				siblings = append(siblings, s)
			}
		}
	case "rpm":
		all, err := tool.Installed(ctx, pkg.Name)
		if err != nil {
			break
		}
		for _, s := range all {
			if s.Version != pkg.Version {
				siblings = append(siblings, s)
			}
		}
	}
	for _, s := range siblings {
		if c, err := tool.Compare(ctx, s.Version, running); err == nil && c > 0 {
			reasons = append(reasons, fmt.Sprintf("a newer kernel package is installed: %s %s", s.Name, s.Version))
		}
	}
	return reasons
}

func (k kernelCollector) origin(family osrel.Family, pkg *pkgtool.Package, rel, upstream string) Origin {
	if family.BackportsKernelFixes() {
		if pkg != nil && distroKernel(*pkg) {
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
