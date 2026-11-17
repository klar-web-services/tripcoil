package run

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// AgentGroup may read run folders: the review agent's user is its only member (Plan 3).
const AgentGroup = "tripcoil-agent"

// AgentGID returns the agent group's ID when the group exists (tripcoil setup creates it in
// Plan 4). Tests replace it, so they do not depend on the machine they run on.
var AgentGID = func() (int, bool) {
	g, err := user.LookupGroup(AgentGroup)
	if err != nil {
		return 0, false
	}
	gid, err := strconv.Atoi(g.Gid)
	return gid, err == nil
}

func shareWithAgent(path string) error {
	if gid, ok := AgentGID(); ok {
		return os.Lchown(path, -1, gid)
	}
	return nil
}

// Lock takes the exclusive run lock in stateDir. If another run holds it, waiting is called once
// and Lock blocks until the lock is free.
func Lock(stateDir string, waiting func()) (unlock func(), err error) {
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, err
	}
	if err := os.Chmod(stateDir, 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(stateDir, "run.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			f.Close()
			return nil, err
		}
		waiting()
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
			f.Close()
			return nil, err
		}
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

// CreateFolder makes stateDir/runs/<id> with mode 0750 and the agent group. An existing folder
// is an error: a run ID is never reused.
func CreateFolder(stateDir, id string) (string, error) {
	runs := filepath.Join(stateDir, "runs")
	if err := os.MkdirAll(runs, 0o750); err != nil {
		return "", err
	}
	dir := filepath.Join(runs, id)
	if err := os.Mkdir(dir, 0o750); err != nil {
		return "", err
	}
	for _, p := range []string{runs, dir} {
		if err := os.Chmod(p, 0o750); err != nil {
			return "", err
		}
		if err := shareWithAgent(p); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// CreateSubfolder makes dir/name, such as a run's raw/, with mode 0750 and the agent group.
func CreateSubfolder(dir, name string) (string, error) {
	p := filepath.Join(dir, name)
	if err := os.Mkdir(p, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", err
	}
	return p, Share(p, 0o750)
}

// Share gives a file in a run folder its mode and the agent group, for files that another
// program wrote, such as Grype's raw output.
func Share(path string, mode fs.FileMode) error {
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	return shareWithAgent(path)
}

// WriteJSON writes v as indented JSON with the given mode and the agent group, atomically.
func WriteJSON(path string, v any, mode fs.FileMode) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return WriteFile(path, append(data, '\n'), mode)
}

// WriteFile writes data with the given mode and the agent group, atomically.
func WriteFile(path string, data []byte, mode fs.FileMode) error {
	return writeAtomic(path, data, mode, true)
}

// writeAtomic writes data through a temporary file and a rename; share gives it the agent group.
func writeAtomic(path string, data []byte, mode fs.FileMode, share bool) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // nothing left to remove after the rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if share {
		if err := shareWithAgent(tmp.Name()); err != nil {
			return err
		}
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// syncDir flushes a directory so a rename inside it survives a power loss.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return err
	}
	return d.Close()
}

// UpdateLatest points stateDir/runs/<name> (latest, latest-reviewed) at the run folder id,
// atomically.
func UpdateLatest(stateDir, name, id string) error {
	runs := filepath.Join(stateDir, "runs")
	tmp := filepath.Join(runs, "."+name+"-"+id)
	_ = os.Remove(tmp)
	if err := os.Symlink(id, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(runs, name)); err != nil {
		return err
	}
	return syncDir(runs)
}

// ReadRecord reads a run folder's run.json.
func ReadRecord(dir string) (*Record, error) {
	data, err := os.ReadFile(filepath.Join(dir, "run.json"))
	if err != nil {
		return nil, err
	}
	var r Record
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
