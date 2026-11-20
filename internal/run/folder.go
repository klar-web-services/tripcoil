package run

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

const AgentGroup = "tripcoil-agent"

var AgentGID = func() (int, bool) {
	g, err := user.LookupGroup(AgentGroup)
	if err != nil {
		return 0, false
	}
	gid, err := strconv.Atoi(g.Gid)
	return gid, err == nil
}

// Busy reports whether a run holds the run lock.
func Busy(stateDir string) (bool, error) {
	f, err := os.Open(filepath.Join(stateDir, "run.lock"))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return true, nil
	}
	return false, err
}

func shareWithAgent(path string) error {
	if gid, ok := AgentGID(); ok {
		return os.Lchown(path, -1, gid)
	}
	return nil
}

func Lock(stateDir string, waiting func()) (unlock func(), err error) {
	return LockContext(context.Background(), stateDir, waiting)
}

const lockPoll = 250 * time.Millisecond

func LockContext(ctx context.Context, stateDir string, waiting func()) (unlock func(), err error) {
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
	for told := false; ; told = true {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			f.Close()
			return nil, err
		}
		if !told {
			waiting()
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(lockPoll):
		}
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

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

func CreateSubfolder(dir, name string) (string, error) {
	p := filepath.Join(dir, name)
	if err := os.Mkdir(p, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", err
	}
	return p, Share(p, 0o750)
}

func Share(path string, mode fs.FileMode) error {
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	return shareWithAgent(path)
}

func WriteJSON(path string, v any, mode fs.FileMode) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return WriteFile(path, append(data, '\n'), mode)
}

func WriteFile(path string, data []byte, mode fs.FileMode) error {
	return writeAtomic(path, data, mode, true)
}

func writeAtomic(path string, data []byte, mode fs.FileMode, share bool) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
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
