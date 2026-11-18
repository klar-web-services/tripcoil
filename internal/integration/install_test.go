//go:build integration

package integration

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func release(t *testing.T, bin, version string, bad bool) string {
	t.Helper()
	site := t.TempDir()
	dir := filepath.Join(site, "v"+version)
	os.MkdirAll(dir, 0o755)
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	name := "tripcoil-x86_64-unknown-linux-gnu.tar.gz"
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "tripcoil", Mode: 0o755, Size: int64(len(data))})
	tw.Write(data)
	tw.Close()
	gz.Close()
	f.Close()
	archive, _ := os.ReadFile(filepath.Join(dir, name))
	sum := sha256.Sum256(archive)
	if bad {
		sum[0] ^= 1
	}
	os.WriteFile(filepath.Join(dir, "checksums.txt"), []byte(hex.EncodeToString(sum[:])+"  "+name+"\n"), 0o644)
	os.WriteFile(filepath.Join(site, "latest"), []byte(version+"\n"), 0o644)
	return site
}

func TestInstall(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	bin := buildBinary(t)
	script, err := filepath.Abs("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	serve := func(site string) string {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: http.FileServer(http.Dir(site))}
		go srv.Serve(l)
		t.Cleanup(func() { srv.Close() })
		return "http://" + l.Addr().String()
	}
	good := serve(release(t, bin, "9.8.7", false))
	bad := serve(release(t, bin, "9.8.7", true))
	for _, c := range []struct {
		name, setup, env, user string
		code                   int
		out                    string
	}{
		{"wget", "", "TRIPCOIL_BASE_URL=" + good, "root", 0, "Installed tripcoil 9.8.7 to /usr/local/bin/tripcoil\nNext: tripcoil setup\nok tripcoil "},
		{"curl", "apk add -q curl >/dev/null && mkdir -p /etc/init.d && touch /etc/init.d/tripcoil;", "TRIPCOIL_BASE_URL=" + good + " TRIPCOIL_VERSION=v9.8.7", "root", 0,
			"Installed tripcoil 9.8.7 to /usr/local/bin/tripcoil\nRestart the service to use it: rc-service tripcoil restart\nok"},
		{"not root", "", "TRIPCOIL_BASE_URL=" + good, "nobody", 1, "tripcoil installer: run it as root"},
		{"bad checksum", "", "TRIPCOIL_BASE_URL=" + bad, "root", 1, "checksum verification failed for tripcoil-x86_64-unknown-linux-gnu.tar.gz; nothing was installed"},
		{"missing version", "", "TRIPCOIL_BASE_URL=" + good + " TRIPCOIL_VERSION=1.0.0", "root", 1, "tripcoil 1.0.0 not found at " + good + "/v1.0.0"},
	} {
		t.Run(c.name, func(t *testing.T) {
			check := `test -e /usr/local/bin/tripcoil && echo "ok $(/usr/local/bin/tripcoil version | head -1) $(stat -c '%u:%g %a' /usr/local/bin/tripcoil)"`
			sh := fmt.Sprintf(`%s su -s /bin/sh %s -c "env %s sh /install.sh" 2>&1; code=$?; %s; exit $code`, c.setup, c.user, c.env, check)
			out, err := exec.CommandContext(interrupt, "docker", "run", "--rm", "--network", "host", "-v", script+":/install.sh:ro", "alpine:3.21", "sh", "-c", sh).CombinedOutput()
			code := 0
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != c.code || !strings.Contains(string(out), c.out) {
				t.Fatalf("exit %d, want %d; output:\n%s\nwant it to contain:\n%s", code, c.code, out, c.out)
			}
			if c.code != 0 && strings.Contains(string(out), "ok tripcoil") {
				t.Fatalf("a failed install left a binary:\n%s", out)
			}
			if c.code == 0 && !strings.Contains(string(out), " 0:0 755\n") {
				t.Fatalf("the binary must be root's, mode 755:\n%s", out)
			}
		})
	}
}
