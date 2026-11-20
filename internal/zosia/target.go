package zosia

import "errors"

const DefaultURL = "https://zosiasec.com"

// DefaultKey is Zosia's current report key, "<key id>:<base64url X25519 public key>". The owner
// generates the pair (Zosia's npm run keygen) and fills this in before the first release that sends.
const DefaultKey = ""

// Target resolves the URL and key, with overrides for tests and staging.
func Target(url, key string) (string, Key, error) {
	if url == "" {
		url = DefaultURL
	}
	if key == "" {
		key = DefaultKey
	}
	if key == "" {
		return "", Key{}, errors.New("this build has no Zosia key")
	}
	k, err := ParseKey(key)
	if err != nil {
		return "", Key{}, err
	}
	return url, k, nil
}
