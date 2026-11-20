package zosia

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestMachineKeyFromMachineID(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "machine-id")
	os.WriteFile(id, []byte("0123456789abcdef0123456789abcdef\n"), 0o444)
	a, err := MachineKey(id, filepath.Join(dir, "machine-key"), bytes.NewReader(nil))
	if err != nil || len(a) != 32 || a == "0123456789abcdef0123456789abcdef" {
		t.Fatalf("%q %v", a, err)
	}
	b, _ := MachineKey(id, filepath.Join(dir, "machine-key"), bytes.NewReader(nil))
	if a != b {
		t.Fatal("not stable")
	}
	if _, err := os.Stat(filepath.Join(dir, "machine-key")); err == nil {
		t.Fatal("wrote a key file although the machine ID exists")
	}
}

func TestMachineKeyWithoutMachineIDIsKept(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "machine-key")
	a, err := MachineKey(filepath.Join(dir, "none"), key, bytes.NewReader(bytes.Repeat([]byte{1}, 16)))
	if err != nil || a != "01010101010101010101010101010101" {
		t.Fatalf("%q %v", a, err)
	}
	if fi, err := os.Stat(key); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", fi, err)
	}
	b, err := MachineKey(filepath.Join(dir, "none"), key, bytes.NewReader(nil))
	if err != nil || a != b {
		t.Fatalf("second key %q %v", b, err)
	}
}
