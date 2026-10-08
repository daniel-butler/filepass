#!/usr/bin/env bash
# Upload a file to filepass and print the block to paste into your message.
# Usage: bash send.sh <file> [ttl]          e.g. bash send.sh build.zip 4h
#        some-command | bash send.sh - <name> [ttl]
set -u

url="${FILEPASS_URL:?FILEPASS_URL is not set — run check.sh}"
url="${url%/}"
: "${FILEPASS_TOKEN:?FILEPASS_TOKEN is not set — run check.sh}"

usage() { echo "usage: send.sh <file> [ttl]   |   <command> | send.sh - <name> [ttl]" >&2; exit 2; }
src="${1:-}"; [ -n "$src" ] || usage
if [ "$src" = "-" ]; then
  name="${2:-}"; [ -n "$name" ] || { echo "send.sh: piped uploads need a name" >&2; usage; }
  ttl="${3:-}"
  target="$url/$name"
else
  [ -f "$src" ] || { echo "send.sh: no such file: $src" >&2; exit 2; }
  ttl="${2:-}"; target="$url/"   # curl appends the file's name
fi

headers=$(mktemp); body=$(mktemp)
trap 'rm -f "$headers" "$body"' EXIT

ttl_args=()
[ -n "$ttl" ] && ttl_args=(-H "Filepass-TTL: $ttl")

code=$(curl -sS -T "$src" -H "Authorization: Bearer $FILEPASS_TOKEN" \
  ${ttl_args[@]+"${ttl_args[@]}"} -D "$headers" -o "$body" -w '%{http_code}' "$target")
rc=$?

if [ $rc -ne 0 ] || [ "$code" != "201" ]; then
  echo "send.sh: upload failed (http ${code:-none}, curl exit $rc)" >&2
  case "$rc:$code" in
    55:*|56:*) echo "hint: the server rejected the upload before reading it — usually a bad token (401), too large (413), throttled (429/503) or out of space (507). Run check.sh, then retry." >&2 ;;
    *:401) echo "hint: token rejected — run check.sh" >&2 ;;
    *:400) msg=$(cat "$body"); echo "hint: ${msg:-bad file name or Filepass-TTL (use e.g. 30m or 4h, at most 24h)}" >&2 ;;
    *) echo "hint: see references/errors.md for http $code" >&2 ;;
  esac
  retry=$(grep -i '^retry-after:' "$headers" | tr -d '\r' | awk '{print $2}')
  [ -n "$retry" ] && echo "retry after: ${retry}s" >&2
  exit 1
fi

header() { grep -i "^$1:" "$headers" | tr -d '\r' | cut -d' ' -f2-; }

link=$(tr -d '\r\n' < "$body")
echo "filepass link: $link"
echo "sha256: $(header Filepass-SHA256)"
echo "expires: $(header Filepass-Expires)"
