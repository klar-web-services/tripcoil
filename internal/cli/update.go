package cli

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/klar-web-services/tripcoil"
	"github.com/klar-web-services/tripcoil/internal/buildinfo"
	"github.com/klar-web-services/tripcoil/internal/setup"
)

const updateUsage = `Usage: tripcoil update

Update tripcoil to the latest release, as root, in the folder it is installed in. It runs the
installer that came with this version, which checks the download's SHA-256 checksum. A running
service is then restarted; when a run is in progress, update asks before it interrupts it.
`

func runUpdate(args []string, stdout, stderr io.Writer, d deps) int {
	fs := flag.NewFlagSet("tripcoil update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, updateUsage) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tripcoil update: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if d.euid() != 0 {
		fmt.Fprintf(stderr, "tripcoil update must run as root (try: sudo tripcoil update)\n")
		return 2
	}
	if err := d.update(stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "tripcoil update: %v\n", err)
		return 1
	}
	return 0
}

func updateHost(stdout, stderr io.Writer) error {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return fmt.Errorf("cannot find Tripcoil's own binary: %v", err)
	}
	changed, err := installLatest(tripcoil.InstallScript, exe, buildinfo.Version, stdout, stderr)
	if err != nil || !changed {
		return err
	}
	return setup.NewHost(exe, os.Stdin, stdout).RestartUpdated(StateDir)
}

func installLatest(script []byte, exe, version string, stdout, stderr io.Writer) (changed bool, err error) {
	if filepath.Base(exe) != "tripcoil" {
		return false, fmt.Errorf("%s is not named tripcoil, so the installer cannot replace it", exe)
	}
	before, err := os.Stat(exe)
	if err != nil {
		return false, err
	}
	cmd := exec.Command("sh", "-s")
	cmd.Stdin = bytes.NewReader(script)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.Env = append(os.Environ(), "TRIPCOIL_INSTALL_DIR="+filepath.Dir(exe), "TRIPCOIL_UPDATE_FROM="+version)
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return false, errors.New("nothing was updated")
		}
		return false, err
	}
	after, err := os.Stat(exe)
	if err != nil {
		return false, err
	}
	return !os.SameFile(before, after), nil
}
