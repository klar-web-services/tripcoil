package facts

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/klar-web-services/tripcoil/internal/inventory"
)

type Kernel struct {
	Cmdline         string            `json:"cmdline"`
	Modules         []string          `json:"modules"`
	Lockdown        string            `json:"lockdown"`
	LSMs            []string          `json:"lsms"`
	AppArmor        string            `json:"apparmor"`
	SELinux         string            `json:"selinux"`
	Vulnerabilities map[string]string `json:"cpuVulnerabilities"`
	Sysctls         map[string]string `json:"sysctls"`
}

var sysctls = []string{"kernel.unprivileged_userns_clone", "user.max_user_namespaces", "kernel.unprivileged_bpf_disabled", "kernel.kptr_restrict",
	"kernel.dmesg_restrict", "kernel.yama.ptrace_scope", "fs.protected_symlinks", "fs.protected_hardlinks", "net.ipv4.ip_forward"}

func (c collector) kernel() (Kernel, error) {
	read := func(p string) string {
		data, err := os.ReadFile(filepath.Join(c.d.Root, p))
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(data))
	}
	cmdline, err := os.ReadFile(filepath.Join(c.d.Root, "proc/cmdline"))
	if err != nil {
		return Kernel{}, err
	}
	k := Kernel{Cmdline: strings.TrimSpace(string(cmdline)), Modules: []string{}, LSMs: []string{}, Vulnerabilities: map[string]string{}, Sysctls: map[string]string{}}
	for _, it := range c.inv.Items {
		if it.Kind == inventory.KindKernel && it.Modules != nil {
			k.Modules = it.Modules
		}
	}
	if l := read("sys/kernel/security/lockdown"); l != "" {
		if i, j := strings.Index(l, "["), strings.Index(l, "]"); i >= 0 && j > i {
			k.Lockdown = l[i+1 : j]
		}
	}
	if l := read("sys/kernel/security/lsm"); l != "" {
		k.LSMs = strings.Split(l, ",")
	}
	k.AppArmor = read("sys/module/apparmor/parameters/enabled")
	switch read("sys/fs/selinux/enforce") {
	case "1":
		k.SELinux = "enforcing"
	case "0":
		k.SELinux = "permissive"
	}
	vulns, _ := os.ReadDir(filepath.Join(c.d.Root, "sys/devices/system/cpu/vulnerabilities"))
	for _, e := range vulns {
		k.Vulnerabilities[e.Name()] = read(filepath.Join("sys/devices/system/cpu/vulnerabilities", e.Name()))
	}
	for _, s := range sysctls {
		if _, err := os.Stat(filepath.Join(c.d.Root, "proc/sys", strings.ReplaceAll(s, ".", "/"))); err == nil {
			k.Sysctls[s] = read(filepath.Join("proc/sys", strings.ReplaceAll(s, ".", "/")))
		}
	}
	return k, nil
}
