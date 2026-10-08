#!/usr/bin/env bash
# Check that filepass is usable from this session, without storing anything.
# Usage: bash check.sh
# Exit 0 = ready to send and receive. Exit 10 = can receive, no token to send.
# Any other exit prints the problem and the fix.
set -u

fail() { echo "filepass: NOT READY — $1" >&2; echo "fix: $2" >&2; exit "${3:-1}"; }

command -v curl >/dev/null 2>&1 || fail "curl is not installed" "install curl" 2
[ -n "${FILEPASS_URL:-}" ] || fail "FILEPASS_URL is not set" \
  "ask the user for the server URL and set FILEPASS_URL (see references/setup.md)" 2
url="${FILEPASS_URL%/}"

err=$(mktemp); trap 'rm -f "$err"' EXIT
health=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$url/healthz" 2>"$err")
case "$health" in
  200) ;;
  000)
    fail "cannot reach $url ($(head -1 "$err" | sed 's/^curl: //'))" \
      "check the URL; in a cloud session the environment's network policy must allow this host" 3 ;;
  *) fail "$url/healthz answered $health, expected 200" \
       "FILEPASS_URL probably points at the wrong host or path" 3 ;;
esac

if [ -z "${FILEPASS_TOKEN:-}" ]; then
  echo "filepass: receive-only — $url reachable; downloading links works without a token."
  echo "sending needs FILEPASS_TOKEN: ask the user for this agent's token (see references/setup.md)."
  exit 10
fi

# PUT / with a valid token is rejected with 400 before anything is stored;
# an invalid token gets 401. This tests the token without uploading.
auth=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 -X PUT \
  -H "Authorization: Bearer $FILEPASS_TOKEN" --data-binary '' "$url/" 2>&1)
case "$auth" in
  400) echo "filepass: ready — $url reachable, token accepted" ;;
  401) fail "token rejected (401)" \
         "FILEPASS_TOKEN is wrong or was removed from the server config; ask the user for a new one" 4 ;;
  *) fail "token check answered $auth" "see references/errors.md" 4 ;;
esac
