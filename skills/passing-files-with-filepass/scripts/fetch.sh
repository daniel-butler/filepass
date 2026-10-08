#!/usr/bin/env bash
# Download a filepass link, verify it, and print where it landed — never its contents.
# Usage: bash fetch.sh <link> [expected-sha256] [dest-dir]
set -u

link="${1:?usage: fetch.sh <link> [expected-sha256] [dest-dir]}"
want="${2:-}"
dir="${3:-${TMPDIR:-/tmp}/filepass}"
mkdir -p "$dir"
name="${link##*/}"
dest="$dir/$name"
headers=$(mktemp); trap 'rm -f "$headers"' EXIT

code=$(curl -sS -C - -D "$headers" -o "$dest" -w '%{http_code}' "$link")
rc=$?

if [ "$code" = "410" ]; then
  rm -f "$dest"; echo "fetch.sh: link expired or revoked (410) — ask the sender to upload again" >&2; exit 3
elif [ "$code" = "404" ]; then
  rm -f "$dest"; echo "fetch.sh: link not found (404) — it was mistyped or truncated in the message, or expired over 48h ago; ask the sender to resend" >&2; exit 3
elif [ $rc -eq 18 ]; then
  echo "fetch.sh: transfer cut off (curl 18) — the link was revoked or timed out mid-download; run fetch.sh again once to resume, then ask the sender" >&2; exit 4
elif [ $rc -ne 0 ] || { [ "$code" != "200" ] && [ "$code" != "206" ] && [ "$code" != "416" ]; }; then
  echo "fetch.sh: download failed (http ${code:-none}, curl exit $rc) — see references/errors.md" >&2; exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then got=$(sha256sum "$dest" | cut -d' ' -f1)
else got=$(shasum -a 256 "$dest" | cut -d' ' -f1); fi
[ -n "$want" ] || want=$(grep -i '^filepass-sha256:' "$headers" | tr -d '\r' | cut -d' ' -f2)
if [ -n "$want" ] && [ "$got" != "$want" ]; then
  echo "fetch.sh: SHA-256 mismatch — got $got, expected $want. Do not use this file; ask the sender to resend." >&2; exit 5
fi

echo "saved: $dest"
echo "size: $(wc -c < "$dest" | tr -d ' ') bytes"
echo "sha256: verified"
