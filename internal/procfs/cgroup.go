package procfs

import (
	"regexp"
	"strings"
)

// ParseCgroup returns the unified (v2) path from /proc/<pid>/cgroup, or the name=systemd path
// when the unified path is missing or "/" (a v1 host, also one where cgroup2 was mounted).
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

// userManager matches a user's own systemd tree, which the user can write to: rootless Docker,
// or a cgroup named like a container that anyone can create there.
var userManager = regexp.MustCompile(`/user@[^/]*\.service/`)

// DockerContainerID returns the Docker container ID in /proc/<pid>/cgroup content (systemd or
// cgroupfs driver, any line, so hybrid hosts work too), or "". A Docker path
// below a user's own systemd tree never counts.
func DockerContainerID(cgroup string) string {
	for _, line := range strings.Split(cgroup, "\n") {
		m := dockerID.FindStringSubmatchIndex(line)
		if m == nil || userManager.MatchString(line[:m[0]+1]) {
			continue
		}
		return line[m[2]:m[3]]
	}
	return ""
}

// SystemdUnit returns the deepest systemd service in a cgroup path, or "".
func SystemdUnit(cgroup string) string {
	parts := strings.Split(cgroup, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if strings.HasSuffix(parts[i], ".service") {
			return parts[i]
		}
	}
	return ""
}
