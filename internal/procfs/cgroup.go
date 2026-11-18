package procfs

import (
	"regexp"
	"strings"
)

func ParseCgroup(data []byte) string {
	var unified, systemd string
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "0" && parts[1] == "" {
			unified = parts[2]
		}
		if parts[1] == "name=systemd" {
			systemd = parts[2]
		}
	}
	if systemd != "" && (unified == "" || unified == "/") {
		return systemd
	}
	return unified
}

var dockerID = regexp.MustCompile(`(?m)(?:/docker-|/docker/)([0-9a-f]{64})(?:\.scope)?(?:/|$)`)

var userManager = regexp.MustCompile(`/user@[^/]*\.service/`)

// nestedRuntime matches another runtime's tree (LXC/LXD/Incus, Proxmox CTs, systemd-nspawn): a
// Docker inside it is not the host's. A machine needs its own cgroup below machine.slice, so the
// host's Docker run with cgroup-parent machine.slice still counts.
var nestedRuntime = regexp.MustCompile(`/(lxc\.payload\.[^/]+|lxc/[^/]+|machine\.slice/[^/]+)/`)

func UserManaged(cgroup string) bool { return userManager.MatchString(cgroup) }

func DockerContainerID(cgroup string) string {
	for _, line := range strings.Split(cgroup, "\n") {
		m := dockerID.FindStringSubmatchIndex(line)
		if m == nil || userManager.MatchString(line[:m[0]+1]) || nestedRuntime.MatchString(line[:m[0]+1]) {
			continue
		}
		return line[m[2]:m[3]]
	}
	return ""
}

func SystemdUnit(cgroup string) string {
	parts := strings.Split(cgroup, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if strings.HasSuffix(parts[i], ".service") {
			return parts[i]
		}
	}
	return ""
}
