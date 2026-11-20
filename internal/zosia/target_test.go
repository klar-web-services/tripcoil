package zosia

import "testing"

func TestTargetUsesOverrides(t *testing.T) {
	k, _ := testKey(t)
	pub := "test:" + encodeKey(k)
	url, got, err := Target("http://127.0.0.1:3000", pub)
	if err != nil || url != "http://127.0.0.1:3000" || got.ID != "test" {
		t.Fatalf("%q %+v %v", url, got, err)
	}
}

func TestTargetWithoutAnyKeyRefuses(t *testing.T) {
	if DefaultKey != "" {
		t.Skip("a default key is built in")
	}
	if _, _, err := Target("", ""); err == nil || err.Error() != "this build has no Zosia key" {
		t.Fatal(err)
	}
}

func TestParseKeyRejectsMalformedKeys(t *testing.T) {
	for _, s := range []string{"", "nokid", ":abc", "k:not-base64!", "k:AAAA"} {
		if _, err := ParseKey(s); err == nil {
			t.Errorf("ParseKey(%q) accepted", s)
		}
	}
}
