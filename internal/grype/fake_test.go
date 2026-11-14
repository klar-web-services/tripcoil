package grype

import (
	"os"
	"path/filepath"
	"testing"
)

const fakeGrypeScript = `#!/bin/sh
# Fake Grype for the runner tests, controlled by FAKE_GRYPE_* variables; see fakeGrype.
log="${FAKE_GRYPE_LOG:-/dev/null}"
printf '%s\n' "$@" > "$log"
if [ "$log" != /dev/null ]; then env > "$log.env"; pwd > "$log.pwd"; printf '%s\n' "$@" "" >> "$log.calls"; fi
if [ "$1 $2" = "db update" ] && [ -n "$FAKE_GRYPE_DB" ]; then
  if [ "$log" != /dev/null ]; then ls "$FAKE_GRYPE_DB" > "$log.db"; fi
  mkdir -p "$FAKE_GRYPE_DB/grype-db-download2"
  printf 'partial' > "$FAKE_GRYPE_DB/grype-db-download2/vulnerability.db"
fi
if [ "$1 $2" = "db status" ]; then
  if [ -n "$FAKE_GRYPE_STATUS" ]; then printf '%s\n' "$FAKE_GRYPE_STATUS"; fi
  exit "${FAKE_GRYPE_STATUS_EXIT:-0}"
fi
if [ "$1 $2" = "db search" ]; then
  printf '%s' "$FAKE_GRYPE_SEARCH"
  exit "${FAKE_GRYPE_EXIT:-0}"
fi
default_json='{"matches":[],"source":{"type":"sbom"},"descriptor":{"name":"grype","version":"0.121.2","db":{"status":{"built":"2026-11-14T03:12:00Z","schemaVersion":"v6.1.10"}}}}'
default_sbom='{"bomFormat":"CycloneDX","components":[{"type":"library","name":"left-pad","purl":"pkg:npm/left-pad@1.3.0"}]}'
while [ $# -gt 0 ]; do
  case "$1" in
    -o)
      case "$2" in
        json=*)
          if [ -n "$FAKE_GRYPE_JSON_FILE" ]; then cp "$FAKE_GRYPE_JSON_FILE" "${2#json=}"
          else printf '%s' "${FAKE_GRYPE_JSON:-$default_json}" > "${2#json=}"; fi ;;
        cyclonedx-json=*) printf '%s' "${FAKE_GRYPE_SBOM:-$default_sbom}" > "${2#cyclonedx-json=}" ;;
      esac
      shift ;;
    -c)
      if [ "$log" != /dev/null ]; then cp "$2" "$log.cfg"; fi
      shift ;;
  esac
  shift
done
if [ -n "$FAKE_GRYPE_STDERR" ]; then printf '%s\n' "$FAKE_GRYPE_STDERR" >&2; fi
if [ -n "$FAKE_GRYPE_PID" ]; then echo $$ > "$FAKE_GRYPE_PID"; fi
if [ -n "$FAKE_GRYPE_SLEEP" ]; then exec sleep "$FAKE_GRYPE_SLEEP"; fi
exit "${FAKE_GRYPE_EXIT:-0}"
`

// fakeGrype writes an executable that imitates Grype's command line and returns its path.
// FAKE_GRYPE_LOG receives the arguments ("<log>.env", ".pwd" and ".cfg" get the environment,
// working directory and config; ".calls" collects the arguments of every call, each followed by
// an empty line). FAKE_GRYPE_JSON and FAKE_GRYPE_SBOM are written for -o json= and
// -o cyclonedx-json=; the file FAKE_GRYPE_JSON_FILE, when set, is copied for -o json=. FAKE_GRYPE_STATUS and FAKE_GRYPE_STATUS_EXIT are the output and exit code
// of "db status", FAKE_GRYPE_SEARCH the output of "db search". FAKE_GRYPE_DB is the database
// directory: "db update" lists it to "<log>.db" and leaves a half-unpacked grype-db-download2 in
// it. FAKE_GRYPE_EXIT, FAKE_GRYPE_STDERR and FAKE_GRYPE_SLEEP apply to every other command, and
// FAKE_GRYPE_PID receives its process ID, which stays that of the sleep.
func fakeGrype(t testing.TB) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "grype")
	if err := os.WriteFile(path, []byte(fakeGrypeScript), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}
