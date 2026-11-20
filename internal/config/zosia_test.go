package config

import (
	"strings"
	"testing"
)

func TestZosiaDefaultsAndOverrides(t *testing.T) {
	c, err := Parse("x.yaml", []byte("version: 1\n"), noStat)
	if err != nil || c.Zosia.SecretFile != DefaultZosiaSecretFile || c.Zosia.URL != "" || c.Zosia.Key != "" {
		t.Fatalf("%+v %v", c.Zosia, err)
	}
	c, err = Parse("x.yaml", []byte("version: 1\nzosia:\n  url: http://127.0.0.1:3000\n  key: test:X9R2M7XkP8p7rRv75CT-rLF12dTUow8Wbb0wY28LRGs\n"), noStat)
	if err != nil || c.Zosia.SecretFile != DefaultZosiaSecretFile || c.Zosia.URL != "http://127.0.0.1:3000" {
		t.Fatalf("%+v %v", c.Zosia, err)
	}
	c, err = Parse("x.yaml", []byte("version: 1\nzosia:\n  secretFile: \"\"\n"), noStat)
	if err != nil || c.Zosia.SecretFile != "" {
		t.Fatalf("%+v %v", c.Zosia, err)
	}
}

func TestZosiaProblems(t *testing.T) {
	for _, tc := range []struct{ yaml, want string }{
		{"version: 1\nzosia:\n  secretFile: zosia.secret\n", "line 3: zosia.secretFile must be an absolute path"},
		{"version: 1\nzosia:\n  url: zosiasec.com\n", "line 3: zosia.url must start with https://"},
		{"version: 1\nzosia:\n  key: nope\n", "line 3: zosia.key: a Zosia key has the form"},
		{"version: 1\nzosia:\n  token: x\n", `unknown field "token"`},
	} {
		if _, err := Parse("/etc/tripcoil/tripcoil.yaml", []byte(tc.yaml), noStat); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: %v", tc.yaml, err)
		}
	}
}
