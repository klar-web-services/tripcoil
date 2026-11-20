package zosia

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// MachineKey names this machine to Zosia without sending its machine ID: an HMAC of the 16-byte
// machine ID (as systemd's app-specific IDs), or, without one, 16 random bytes kept in keyPath.
func MachineKey(machineIDPath, keyPath string, random io.Reader) (string, error) {
	if data, err := os.ReadFile(machineIDPath); err == nil {
		if id, err := hex.DecodeString(strings.TrimSpace(string(data))); err == nil && len(id) == 16 {
			mac := hmac.New(sha256.New, id)
			mac.Write([]byte("tripcoil zosia machine"))
			return hex.EncodeToString(mac.Sum(nil)[:16]), nil
		}
	}
	if data, err := os.ReadFile(keyPath); err == nil {
		if k := strings.TrimSpace(string(data)); validKey(k) {
			return k, nil
		}
	}
	b := make([]byte, 16)
	if _, err := io.ReadFull(random, b); err != nil {
		return "", err
	}
	k := hex.EncodeToString(b)
	tmp, err := os.CreateTemp(filepath.Dir(keyPath), ".machine-key-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(k + "\n"); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	return k, os.Rename(tmp.Name(), keyPath)
}

func validKey(k string) bool {
	b, err := hex.DecodeString(k)
	return err == nil && len(b) == 16
}
