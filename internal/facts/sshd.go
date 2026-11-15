package facts

import (
	"errors"
	"strings"
)

var errNoDocker = errors.New("no Docker client, so the containers cannot be inspected")

// sshd is facts/sshd.txt: `sshd -T`, the effective sshd configuration. sshd -T needs its privilege
// separation directory, which Debian and Ubuntu create only while sshd runs (with socket
// activation, sshd may not run while port 22 listens). On systemd hosts it is then run in a
// transient unit that has the directory as its own runtime directory, so nothing on the host
// changes. installed is false when there is no sshd.
func (c collector) sshd() (out string, installed bool, err error) {
	data, err := c.d.Run(c.ctx, "sshd", "-T")
	if errors.Is(err, errNotFound) {
		return "", false, nil
	}
	if err != nil && strings.Contains(err.Error(), "Missing privilege separation directory") && c.inv.Host.Init == "systemd" {
		path, lerr := c.d.LookPath("sshd")
		if lerr != nil {
			return "", true, lerr
		}
		data, err = c.d.Run(c.ctx, "systemd-run", "--wait", "--pipe", "--quiet", "--collect",
			"-p", "RuntimeDirectory=sshd", "-p", "PrivateNetwork=yes", "--", path, "-T")
	}
	if err != nil {
		return "", true, err
	}
	return string(data), true, nil
}
