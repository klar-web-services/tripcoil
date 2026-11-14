package procfs

import (
	"regexp"
	"strings"
)

// ParseCgroup returns the unified (v2) cgroup path from /proc/<pid>/cgroup, or on a v1 host the
// path in the systemd hierarchy.
func ParseCgroup(data []byte) string {
	var v1 string
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "0" && parts[1] == "" {
			return parts[2]
		}
		if parts[1] == "name=systemd" {
			v1 = parts[2]
		}
	}
	return v1
}

var dockerID = regexp.MustCompile(`(?m)(?:/docker-|/docker/)([0-9a-f]{64})(?:\.scope)?(?:/|$)`)

// userManager matches a user's own systemd tree, which the user can write to: rootless Docker,
// or a cgroup named like a container that anyone can create there.
var userManager = regexp.MustCompile(`/user@[^/]*\.service/`)

// DockerContainerID returns the Docker container ID in /proc/<pid>/cgroup content (systemd or
// cgroupfs driver, any line, so hybrid hosts work too), or "". Paths in a user's own systemd
// tree never count.
func DockerContainerID(cgroup string) string {
	for _, line := range strings.Split(cgroup, "\n") {
		if userManager.MatchString(line) {
			continue
		}
		if m := dockerID.FindStringSubmatch(line); m != nil {
			return m[1]
		}
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
