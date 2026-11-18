package procfs

import "testing"

const cid = "23665d1635863a96dce002582f0cc899b885bcacbd2d186b54858a079c5600d1"

func TestParseCgroup(t *testing.T) {
	if got := ParseCgroup([]byte("0::/system.slice/nginx.service\n")); got != "/system.slice/nginx.service" {
		t.Fatalf("v2: %q", got)
	}
	v1 := "12:memory:/system.slice/nginx.service\n1:name=systemd:/system.slice/nginx.service\n"
	if got := ParseCgroup([]byte(v1)); got != "/system.slice/nginx.service" {
		t.Fatalf("v1: %q", got)
	}
	mounted := "1:name=systemd:/\n0::/system.slice/nginx.service\n"
	if got := ParseCgroup([]byte(mounted)); got != "/system.slice/nginx.service" {
		t.Fatalf("v2 with name=systemd mounted: %q", got)
	}
	legacy := "12:memory:/system.slice/nginx.service\n1:name=systemd:/system.slice/nginx.service\n0::/\n"
	if got := ParseCgroup([]byte(legacy)); got != "/system.slice/nginx.service" {
		t.Fatalf("legacy v1 with 0::: %q", got)
	}
}

func TestDockerContainerID(t *testing.T) {
	cases := map[string]string{
		"0::/system.slice/docker-" + cid + ".scope\n":    cid,
		"0::/docker/" + cid + "\n":                       cid,
		"12:memory:/docker/" + cid + "\n0::/\n":          cid,
		"0::/system.slice/docker.service\n":              "",
		"0::/user.slice/user-1000.slice/session-2.scope": "",
		"0::/system.slice/docker-" + cid + ".scope/user.slice/user-1000.slice/user@1000.service/init.scope\n": cid,
		"0::/user.slice/user-1000.slice/user@1000.service/docker/" + cid + "\n":                               "",
		"0::/user.slice/user-1000.slice/user@1000.service/user.slice/docker-" + cid + ".scope\n":              "",
		"0::/lxc.payload.c1/system.slice/docker-" + cid + ".scope\n":                                          "",
		"0::/lxc/101/ns/system.slice/docker-" + cid + ".scope\n":                                              "",
		"0::/machine.slice/systemd-nspawn@box.service/payload/system.slice/docker-" + cid + ".scope\n":        "",
		"12:memory:/lxc/101/ns/docker/" + cid + "\n0::/\n":                                                    "",
		"0::/machine.slice/docker-" + cid + ".scope\n":                                                        cid,
	}
	for in, want := range cases {
		if got := DockerContainerID(in); got != want {
			t.Errorf("DockerContainerID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSystemdUnit(t *testing.T) {
	cases := map[string]string{
		"/system.slice/nginx.service":                         "nginx.service",
		"/system.slice/php8.2-fpm.service":                    "php8.2-fpm.service",
		"/system.slice/docker-" + cid + ".scope":              "",
		"/user.slice/user-1000.slice/session-2.scope":         "",
		"/system.slice/system-getty.slice/getty@tty1.service": "getty@tty1.service",
		"/": "",
	}
	for in, want := range cases {
		if got := SystemdUnit(in); got != want {
			t.Errorf("SystemdUnit(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUserManaged(t *testing.T) {
	cases := map[string]bool{
		"0::/system.slice/docker.service\n":                                                        false,
		"0::/user.slice/user-1000.slice/user@1000.service/app.slice/docker.service\n":              true,
		"12:memory:/user.slice/user-1000.slice/user@1000.service/app.slice/docker.service\n0::/\n": true,
		"0::/user.slice/user-1000.slice/session-2.scope\n":                                         false,
	}
	for in, want := range cases {
		if got := UserManaged(in); got != want {
			t.Errorf("UserManaged(%q) = %v, want %v", in, got, want)
		}
	}
}
