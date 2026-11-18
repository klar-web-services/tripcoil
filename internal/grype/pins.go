package grype

const Version = "0.121.2"

var Checksums = map[string]string{
	"linux_amd64": "9c8965ced9df657e5e851c14021bae838802f711edd7a48f9bc3c923a8d28f12",
	"linux_arm64": "d7d2e160255b0f087280feabf6f213cf4c45d475690f3f1fe5dc336eb1037bf0",
}

// BinaryChecksums holds the SHA-256 of the grype executable inside each release archive, keyed like Checksums.
// Computed from the verified official archives; update together with Version and Checksums.
// To recompute on a version bump, after verifying the archive against the release's checksums file:
//
//	tar -xzOf grype_<version>_<os>_<arch>.tar.gz grype | sha256sum
var BinaryChecksums = map[string]string{
	"linux_amd64": "e668ae615893f6b1525f6ee43473fa0111a082fa128409c0982809fd75f63e86",
	"linux_arm64": "18544168137b142f56c7b4f15b4c0c525f3df2475204316fe606b0b7a9a7c6d5",
}
