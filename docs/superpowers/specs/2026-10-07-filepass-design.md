# filepass — design

Date: 2026-10-07
Status: draft, revised after two reviews and a threat-model pass, awaiting approval
License: MIT
Repo: `daniel-butler/filepass`

## Purpose

Agents already message each other. Those messages are small and text-only.
filepass carries the attachments: agent A uploads a file, gets back a URL,
and pastes that URL into its message to agent B. B downloads it with `curl`.

filepass is a single Rust binary that runs on a locked-down server behind a
TLS-terminating reverse proxy. It faces the public internet: agents reach it
from wherever they run, so no network allowlist protects it. One operator owns
every agent; the agent name is the only identity. filepass stores nothing
permanent: every file expires, by default after 30 minutes.

## Goals

- Plain HTTP. An agent needs only `curl`; there is no client to install.
- Files up to 2 GiB of any type: zips, tarballs, binaries.
- Each agent authenticates uploads with its own token.
- Links expire. The uploader can revoke one early, and revocation is immediate.
- The server never exhausts its disk, inodes, file descriptors, or memory.
- Strangers on the internet cannot store files, guess tokens, scan for links,
  or lock out legitimate agents.
- Operators see what happens through structured logs and metric events.
- Nothing leaves the server. No phone-home telemetry.

## Non-goals (v1)

- Resumable uploads. Files stay under 2 GiB and come from well-connected
  hosts; a failed upload restarts.
- Recipient-bound links (see Future work).
- A client CLI, web UI, or MCP server.
- TLS termination, and slow-header protection. The reverse proxy does both.
- More than one server node.
- A Prometheus endpoint.
- More than one human user, or self-service token issuance.
- Per-agent overrides of quotas and limits. Every agent shares one set.
- Multi-range requests. A request for several ranges gets the whole file.

## HTTP API

### Upload: `PUT /{filename}`

```
curl -T build.zip -H "Authorization: Bearer $FILEPASS_TOKEN" https://filepass.host/
curl -T build.zip -H "Authorization: Bearer $FILEPASS_TOKEN" -H "Filepass-TTL: 4h" https://filepass.host/
tar czf - ./dist | curl -T - -H "Authorization: Bearer $FILEPASS_TOKEN" https://filepass.host/dist.tar.gz
```

curl appends the local filename when the URL ends in `/` and has no query
string. It never appends a name for `-T -`, so piped uploads must name the
file in the URL. TTL travels in a header, not the query string, because a
query string stops curl from appending the filename.

- **Auth:** `Authorization: Bearer <token>` is required.
- **TTL:** the `Filepass-TTL` header is optional, a humantime duration such as
  `10m` or `4h`. The default is `default_ttl` (30m). Zero, values above
  `max_ttl` (24h), and unparseable values return `400`.
- **Path:** exactly one non-empty segment. An explicit `PUT` fallback route
  answers `PUT /` with `400` and the body
  `name the file: PUT /<filename> (curl -T - needs an explicit name)`, and
  answers paths with more than one segment with `400`. These `400`s do not
  charge the failure budget. `PUT /healthz` uploads a file named `healthz`
  like any other name.
- **Filename:** the segment, percent-decoded. filepass returns `400` when the
  decoded bytes are not valid UTF-8; when the name is `.` or `..`; when it
  contains `/` or `\`; when it contains a C0 control (U+0000–U+001F), DEL
  (U+007F), a C1 control (U+0080–U+009F), or a bidi control (U+200E, U+200F,
  U+202A–U+202E, U+2066–U+2069); or when it exceeds 255 bytes. The name is
  metadata only; it never becomes a path on disk.
- **URL name:** filepass derives a URL-safe form of the name for the download
  URL by replacing every character outside `[A-Za-z0-9._+-]` with `_`.
  `my file.zip` becomes `my_file.zip`, so `curl -O` saves a clean name. The
  original name survives in `Content-Disposition`.
- **Empty files** are allowed.
- **Success:** `201 Created`. The body is the download URL plus a newline.
  Headers:
  - `Location`: the download URL
  - `Filepass-Expires`: expiry, RFC 3339 UTC
  - `Filepass-SHA256`: hex digest of the stored bytes
- **Expiry clock** starts when the upload completes, not when it starts.

**Check order.** filepass evaluates an upload in this order and stops at the
first failure:

1. IP lockout, unless the request carries a valid token → `429`
2. Token → `401`
3. Path, filename, `Filepass-TTL` → `400`
4. Agent's concurrent uploads at `max_uploads_per_agent` → `429`;
   server-wide uploads at `max_concurrent_uploads` → `503`
5. Upload rate bucket empty → `429` (only requests that reach this step spend
   a token)
6. Declared `Content-Length` over `max_file_size` → `413`
7. Declared length or a new file over any quota → `507`
8. Read the body; limits are re-checked as bytes arrive (see Space protection)

### Download: `GET /d/{id}/{urlname}` (also `HEAD`)

```
curl -fO https://filepass.host/d/3f9c2a7e1b3d4c5e8f9a0b1c2d3e4f5a/build.zip
curl -C - -fO https://filepass.host/d/3f9c.../build.zip   # resume
```

- **No auth.** Possession of the URL grants access until expiry or revocation.
- `{id}` is 128 random bits as 32 lowercase hex characters. It cannot be
  guessed, so the URL itself is the credential.
- `{urlname}` must equal the stored URL-safe name; a mismatch returns `404`.
- Supports single-range `Range` requests, so interrupted downloads resume. An
  unsatisfiable range returns `416` with `Content-Range: bytes */<size>`.
- Response headers:
  - `Content-Type: application/octet-stream`, always
  - `Content-Disposition: attachment; filename="<urlname>"; filename*=UTF-8''<percent-encoded original>`
  - `X-Content-Type-Options: nosniff`
  - `Cache-Control: private, no-store`
  - `Referrer-Policy: no-referrer`
  - `Filepass-SHA256` and `Filepass-Expires`

  filepass never lets a browser render an uploaded file inline, so an uploaded
  `.html` or `.svg` cannot run script on the server's origin.
- **Expiry mid-download:** a download in progress when the file expires
  finishes, subject to `max_download_duration`.
- **Revoke mid-download:** revocation aborts every download of that file in
  progress. Revocation exists for leaked links, so it must stop transfers, not
  only new requests.
- **Slots.** A `GET` takes a download slot only after the id, name, and state
  checks pass, so invalid requests never consume one. `HEAD` takes no slot.
  At most `max_concurrent_downloads` (64) run server-wide, beyond which
  filepass returns `503`; at most `max_downloads_per_ip` (8) run per client
  IP, beyond which it returns `429`.
- **Timeouts.** A download whose client accepts no bytes for
  `download_idle_timeout` (60s), or that runs longer than
  `max_download_duration` (2h), is dropped. A slow reader cannot hold a slot,
  or an expired file's disk space, indefinitely.

### Revoke: `DELETE /d/{id}/{urlname}`

filepass checks in this order:

| Condition | Response |
|---|---|
| IP locked out and no valid token | `429` |
| Missing or unknown token | `401` |
| Unknown id, or name mismatch | `404` |
| Token belongs to an agent other than the uploader | `403` |
| Already expired, revoked, or being expired | `410` |
| Otherwise | `204`; the file is revoked |

### Health: `GET /healthz`

Returns `200 ok`. No auth.

### Status codes

| Code | Meaning |
|---|---|
| 400 | Bad path, filename, or `Filepass-TTL` |
| 401 | Missing or unknown token |
| 403 | DELETE by an agent that did not upload the file |
| 404 | Unknown id, or name mismatch |
| 408 | Upload stalled or exceeded `max_upload_duration` |
| 410 | The file existed but has expired or been revoked |
| 413 | Larger than `max_file_size` |
| 416 | Unsatisfiable range |
| 429 | IP locked out; or a per-agent or per-IP limit reached |
| 500 | Disk or I/O error; logged with detail, never the id |
| 503 | A server-wide concurrency limit reached |
| 507 | Would exceed the agent quota, `max_files`, the total quota, or the free-space floor |

`410` differs from `404` on purpose. It tells B to ask A for a fresh upload,
where `404` means the link was never valid. Every `429` and `503` carries
`Retry-After`.

**Early rejection.** When filepass rejects an upload before reading its body
(`400`, `401`, `413`, `429`, `503`, or `507`), the server closes the
connection with body bytes unread. curl often reports this as a send error
(exit 55) rather than printing the status. The README says so. Behind nginx,
`client_max_body_size` rejects oversize uploads before they reach filepass.

## Storage

```
data_dir/
  tmp/              uploads and metadata writes in progress; emptied at startup
  files/{id}        file contents
  files/{id}.json   metadata
```

Metadata (`{id}.json`):

```json
{
  "id": "3f9c2a7e1b3d4c5e8f9a0b1c2d3e4f5a",
  "name": "my file.zip",
  "urlname": "my_file.zip",
  "size": 734003200,
  "sha256": "…",
  "uploader": "planner",
  "created_at": "2026-10-07T14:00:00Z",
  "expires_at": "2026-10-07T14:30:00Z",
  "state": "live",
  "ended_at": null
}
```

`state` is `live`, `expired`, or `revoked`. `ended_at` records when the file
stopped being live; tombstone lifetime counts from it.

**Metadata writes** go to a uniquely named file in `tmp/`, which filepass
writes, flushes, fsyncs, renames into `files/`, and then fsyncs `files/`.
Unique temp names mean concurrent writers can never interleave in one file.

**File writes** use `tokio::fs::File`; filepass calls `flush()` before
`sync_all()` so write errors surface.

### Upload write order

1. Stream the body into `tmp/{id}`, hashing and counting bytes as they arrive.
2. On completion, flush and fsync the file and rename it to `files/{id}`.
3. Write `files/{id}.json`, then insert the entry into the index as `live`.

A link is live only once its `.json` exists and the index holds it. No crash
can produce a live link to a partial file.

### Index states and ending a file

Each index entry has an in-memory state: `live`, `ending`, `expired`, or
`revoked`. Every transition happens under the index lock.

To revoke or expire a file:

1. **Under the lock**, move the entry from `live` to `ending`. If it is not
   `live`, stop: a revoke answers `410`, and the sweeper skips it. This flip,
   not the disk write, is what blocks new downloads and makes concurrent
   revokes and sweeps race-free; exactly one caller wins.
2. Write the `.json` with the final `state` and `ended_at`.
3. Fire the file's cancellation token (revoke only), aborting its downloads.
4. Unlink `files/{id}` and fsync `files/`.
5. Under the lock, set the entry to `expired` or `revoked`.

Downloads treat `ending` like `expired`/`revoked`: `410`. Writing the state
before unlinking means a crash can leave an orphaned blob, which startup
deletes, but can never bring a revoked file back.

### Startup recovery

Recovery runs to completion before the listener binds.

| Found | Action |
|---|---|
| Anything in `tmp/` | Delete |
| A name in `files/` that is neither `{32 hex}` nor `{32 hex}.json` | Delete; log a warning |
| A blob with no `.json` | Delete |
| A `.json` that fails to parse | Delete it and its blob; log a warning |
| `expired`/`revoked` `.json` whose blob still exists | Delete the blob |
| `live` `.json` with no blob | Mark `expired`, `ended_at` = now |
| `live` `.json` past `expires_at` | End it as expired (steps 2–4 above) |
| `expired`/`revoked` `.json` past `ended_at + tombstone_ttl` | Delete |

### Permissions

At startup filepass refuses to run unless `data_dir` is owned by its own user
with mode `0700`. It creates every file with mode `0600`. Paths on disk are
built only from hex ids, so names cannot traverse or follow symlinks.

### In-memory index

The index holds every `.json` loaded at startup and updated since. It answers
lookups, tracks per-agent bytes and live-file counts, holds reservations, and
drives expiry. Each live file also carries, in memory only, a cancellation
token, its first-download time, an in-flight download count, and whether it
was loaded at startup.

### Expiry

A sweeper runs every 60 seconds. For each `live` entry past `expires_at` it
ends the file as expired. For each `expired` or `revoked` entry past
`ended_at + tombstone_ttl` (48h) it deletes the `.json`, after which the id
returns `404`.

Downloads also check `expires_at` directly, so a file is unreachable the moment
it expires, even before the sweeper runs.

Tombstones do not count toward `max_files`. The upload rate bounds them: at
most `upload_rate × 60 × 48` (172,800) per agent at the defaults. As a
backstop, when tombstones exceed `max_tombstones` (200,000) the sweeper deletes
the oldest; those ids return `404` early.

### Space protection

Every upload passes these limits:

- `max_file_size` (2 GiB)
- `agent_quota` (10 GiB) bytes per agent, live files plus reservations
- `max_files` (1000) live files per agent, plus uploads in progress
- `total_quota` (50 GiB), all agents
- `min_free_space` (5 GiB), measured with `nix::sys::statvfs`

The free-space check accounts for bytes promised but not yet written:

```
f_bavail × f_frsize − Σ(reserved − written) − incoming ≥ min_free_space
```

How filepass enforces the limits:

- Every upload reserves a file slot when it passes the check order, so two
  uploads cannot both take the last slot.
- With a declared `Content-Length`, filepass reserves the full length before
  reading the body. Two uploads cannot both pass the check and then collide.
- Without one (`curl -T -`), filepass reserves bytes as they stream and
  re-checks free space once per MiB received.
- When a limit trips mid-stream, filepass stops reading, deletes the temp
  file, releases the reservation, and returns `413` or `507`.
- An upload that sends no bytes for `upload_idle_timeout` (60s), or runs
  longer than `max_upload_duration` (1h), aborts with `408`. A trickling
  client cannot hold a reservation forever.

## Abuse protection

filepass faces the internet, so it enforces its own limits rather than relying
on a firewall or fail2ban.

### Client IP

filepass trusts forwarding headers only from `trusted_proxies` (default
`127.0.0.1` and `::1`). When the socket peer is a trusted proxy, the client IP
is the rightmost `X-Forwarded-For` entry that is not itself a trusted proxy.
Otherwise the client IP is the socket peer, and filepass ignores any
`X-Forwarded-For` the client sent. The proxy must overwrite the header, not
append a client-supplied one (see Deployment).

IPv6 clients are keyed by their /64 prefix, since one host commonly controls a
whole /64. IPv4 clients are keyed by full address.

### Failure budget per client

Every `401`, `403`, or `404` response charges the client key one unit. A key
that spends `failure_budget` (20) units within `failure_window` (1m) is locked
out for `failure_lockout` (10m). While locked out, requests without a valid
token get `429` with `Retry-After`.

**A valid token bypasses the lockout.** Every agent on one host shares an IP,
so a single agent retrying with a stale token must not lock out the others,
and an attacker must not be able to lock out legitimate agents. Checking the
token costs one SHA-256.

filepass tracks at most `max_tracked_ips` (10,000) keys. When full, it evicts
the least recently seen key that is not locked out. It evicts an active
lockout only when every tracked key is locked out.

### Upload rate per agent

Each agent has a token bucket of capacity `upload_rate` (60), refilling at
`upload_rate` per minute. Only uploads that pass auth and validation spend a
token. The rate caps how hard a leaked token can hit the server and bounds
tombstone growth.

### Concurrency

- `max_concurrent_uploads` (32) server-wide, `max_uploads_per_agent` (8)
- `max_concurrent_downloads` (64) server-wide, `max_downloads_per_ip` (8)

Each upload or download holds one file descriptor. These caps keep the total
far below the file-descriptor limit, which the systemd unit raises to 65,536.

All limiter state lives in memory and resets on restart.

## Authentication

Each agent has a random token: `fp_` followed by 32 random bytes in
base64url. The config stores only the SHA-256 of each token. A leaked config
file grants no access.

SHA-256 suffices because tokens carry 256 bits of entropy. Slow hashes such
as Argon2 protect low-entropy passwords from guessing; they add nothing here.

`filepass token` prints a new token and its hash. The operator puts the hash
in the config and gives the token to the agent. Adding or removing an agent
takes a restart. Uploads in flight during the restart fail, and the agent
must run them again.

## Configuration

`filepass serve --config /etc/filepass/filepass.toml`

```toml
listen                   = "127.0.0.1:8080"
public_url               = "https://filepass.host"
data_dir                 = "/var/lib/filepass"
log_format               = "text"      # or "json"
trusted_proxies          = ["127.0.0.1", "::1"]

max_file_size            = "2GiB"
default_ttl              = "30m"
max_ttl                  = "24h"
tombstone_ttl            = "48h"
max_tombstones           = 200000
upload_idle_timeout      = "60s"
max_upload_duration      = "1h"
download_idle_timeout    = "60s"
max_download_duration    = "2h"
shutdown_grace           = "30s"

total_quota              = "50GiB"
agent_quota              = "10GiB"
max_files                = 1000
min_free_space           = "5GiB"

failure_budget           = 20          # failed requests per client ...
failure_window           = "1m"        # ... within this window
failure_lockout          = "10m"
max_tracked_ips          = 10000
upload_rate              = 60          # uploads per agent per minute
max_concurrent_uploads   = 32
max_uploads_per_agent    = 8
max_concurrent_downloads = 64
max_downloads_per_ip     = 8

[agents.planner]
token_sha256 = "9b1c…"

[agents.builder]
token_sha256 = "77ae…"
```

filepass validates the config at startup and refuses to run on errors:

- unknown keys, a malformed `public_url`, duplicate token hashes, or an
  unparseable `trusted_proxies` entry;
- `default_ttl` above `max_ttl`;
- any duration, count, size, or rate that is zero, except `min_free_space`.

## Shutdown

On SIGTERM filepass stops accepting connections and wraps axum's graceful
shutdown in `tokio::time::timeout(shutdown_grace)`; axum's own graceful
shutdown waits indefinitely. When the grace period (30s) ends, filepass exits
regardless. Keep `shutdown_grace` below systemd's `TimeoutStopSec` (default
90s). Interrupted uploads leave temp files, which the next startup deletes.

## Telemetry

filepass writes everything through `tracing` to stdout; under systemd it lands
in journald. `log_format` selects text or JSON. Nothing leaves the server.

It follows the `obs.rs` convention from `running-app-backend-deploy`. A metric
is one structured event on the `metric` target, paired with a readable log line
at the same call site. Count the metric; read the log.

### Metric events

| Metric | Kind | Labels | Emitted |
|---|---|---|---|
| `upload` | counter | `agent`, `result` | each upload attempt |
| `upload_bytes` | counter | `agent` | each successful upload |
| `upload_duration_ms` | timing | `agent` | each successful upload |
| `download` | counter | `result` | each download request |
| `download_bytes` | counter | — | bytes sent, at the end of each download |
| `time_to_first_download_ms` | timing | `agent` | first download of a file |
| `expired_undownloaded` | counter | `agent` | sweeper expires a file never downloaded |
| `revoke` | counter | `agent`, `result` | each DELETE |
| `throttled` | counter | `reason` | each `429` or `503` from a limiter |
| `ip_lockout` | counter | — | each time a client key is locked out |
| `stored_bytes` | gauge | `agent`, plus `total` | each sweep |
| `live_files` | gauge | — | each sweep |
| `tombstones` | gauge | — | each sweep |
| `uploads_in_flight` | gauge | — | each sweep |
| `downloads_in_flight` | gauge | — | each sweep |

`agent` is `-` when no valid token was presented. `reason` is one of
`ip_lockout`, `upload_rate`, `uploads_per_agent`, `uploads_total`,
`downloads_per_ip`, `downloads_total`.

A **download** is a `GET` answered `200` or `206`. `HEAD` requests do not
count. The first such response sets a file's first-download time. Range resumes
count as further downloads but never reset that time.

`expired_undownloaded` skips files loaded at startup, because their
first-download time was not persisted and is unknown.

`result` takes a fixed set of values: `ok`, `unauthorized`, `forbidden`,
`not_found`, `gone`, `too_large`, `range_not_satisfiable`,
`insufficient_storage`, `timeout`, `bad_request`, `busy`, `rate_limited`,
`revoked`, `client_aborted`, `error`.

Labels never include file ids, filenames, or IPs, which keeps series count
bounded.

`time_to_first_download_ms` and `expired_undownloaded` exist to tune
`default_ttl`. If first downloads cluster near 30 minutes, or many files expire
untouched, raise it.

### Log hygiene

The download URL is the credential. filepass therefore:

- never logs a full id; it logs the first 8 characters;
- never logs tokens or token hashes;
- never records the request URI in a span or log field. It does not use
  tower-http's default `TraceLayer` URI fields, and its own request span
  records the route template (`/d/{id}/{urlname}`), not the path.

Each request log names the agent, the id prefix, the original filename, the
size, and the client IP as determined under Abuse protection.

Reverse-proxy access logs record full URLs. The README tells operators to
strip the path from the proxy's log for `/d/` requests, or to restrict who
reads those logs.

## Code layout

| Module | Responsibility |
|---|---|
| `main.rs` | CLI (`serve`, `token`), startup, shutdown |
| `config.rs` | Parse and validate TOML; size and duration types |
| `auth.rs` | Token hashing and lookup; `Agent` extractor |
| `client_ip.rs` | Trusted-proxy resolution and IPv6 /64 keying |
| `names.rs` | Filename validation and URL-safe name derivation |
| `store.rs` | Blob and metadata files, index and its states, reservations, recovery |
| `upload.rs` | PUT handler and fallback: check order, streaming, hashing, limits, timeouts |
| `download.rs` | GET, HEAD, and DELETE handlers; range serving; cancellation |
| `limits.rs` | Failure budget, upload rate, concurrency caps |
| `sweeper.rs` | Expiry, tombstone removal, gauge emission |
| `obs.rs` | Metric event helpers |
| `clock.rs` | `Clock` trait; system clock and a test clock |

**Downloads do not use tower-http's `ServeFile`.** `ServeFile` opens the file
by path after the handler's index check, so a concurrent revoke or expiry turns
an intended `410` into `404`. It also emits its own ETag and Last-Modified.
filepass instead opens the file descriptor while holding the index entry,
maps a vanished file to `410`, parses `Range` with the `http-range-header`
crate, and streams the descriptor with
`tokio_util::io::ReaderStream::with_capacity(file, 256 * 1024)`. The default
4 KiB buffer would mean half a million blocking reads per 2 GiB file. The
stream stops when the file's cancellation token fires, the client stalls past
`download_idle_timeout`, or the transfer passes `max_download_duration`.

Main crates: `axum`, `tokio`, `tokio-util`, `http-range-header`, `sha2`,
`rand`, `serde`, `serde_json`, `toml`, `humantime`, `tracing`,
`tracing-subscriber`, `clap`, `ipnet`, and `nix` (`fs` feature, for
`statvfs`).

## Deployment

- Builds as a static `x86_64-unknown-linux-musl` binary.
- Ships an example systemd unit: dedicated unprivileged user,
  `StateDirectory=filepass` with `StateDirectoryMode=0700`,
  `ProtectSystem=strict`, `LimitNOFILE=65536`, listening on localhost.
- `axum::serve` sets no header-read timeout, so filepass relies on the reverse
  proxy to drop clients that send headers slowly. The README warns against
  exposing filepass without a proxy.
- The README gives reverse-proxy config. nginx needs:

  ```nginx
  client_max_body_size    2g;      # nginx's default is 1m
  proxy_http_version      1.1;     # without it, nginx < 1.29.7 spools chunked uploads to disk
  proxy_request_buffering off;     # stream to filepass instead of spooling to disk
  proxy_buffering         off;
  proxy_read_timeout      300s;
  proxy_send_timeout      300s;
  proxy_set_header        X-Forwarded-For $remote_addr;   # overwrite; never pass the client's own
  ```

  Without `proxy_http_version 1.1`, nginx writes every `curl -T -` upload to
  its own disk before forwarding it. That space escapes filepass's quotas and
  free-space floor. Without the `X-Forwarded-For` line, nginx sends no client
  IP, and every client shares the proxy's address and one failure budget.

  Caddy needs no body-size setting. Its `reverse_proxy` sets
  `X-Forwarded-For` to the client address and ignores client-supplied values
  unless Caddy's own `trusted_proxies` says otherwise.

## Testing

Integration tests start the real server on a random port with a temp
`data_dir` and an injected test clock. They cover:

- Upload then download round trip; the SHA-256 header matches the bytes.
- `curl -T file URL/` and `curl -T - URL/name` both work, run with the real
  curl binary. An empty file round-trips.
- `PUT /` and multi-segment paths return `400` without charging the budget.
  `PUT /healthz` uploads a file.
- Upload check order: each step's status wins over every later step's.
- `Filepass-TTL`: default, explicit, over the cap, zero, malformed.
- `401` without a token or with a bad one.
- `413` from a declared length, and from a stream that crosses the limit.
- `507` from agent quota, `max_files`, total quota, and the free-space floor.
- Two concurrent uploads cannot jointly exceed a quota or take the last file
  slot.
- `408` for an idle upload and for one past `max_upload_duration`.
- Filename rejection: invalid UTF-8, `..`, slashes, C0, DEL, C1, bidi
  controls, overlong names. URL-safe name derivation.
- `410` after expiry (advance the test clock) and after revoke.
- `404` after the tombstone expires, and for a name mismatch.
- DELETE order: `401`, `404`, `403`, `410`, `204`.
- Concurrent revokes, and a revoke racing the sweeper: exactly one wins; the
  other gets `410` or skips.
- Revoke aborts a download in progress.
- Range request returns the requested slice; resume reassembles the file;
  an unsatisfiable range returns `416`.
- Download limits: `503` server-wide, `429` per IP; invalid requests and
  `HEAD` take no slot; `max_download_duration` drops a slow reader.
- Upload concurrency: `429` per agent, `503` server-wide.
- Client IP: `X-Forwarded-For` from an untrusted peer is ignored; from a
  trusted peer, the rightmost untrusted entry wins; IPv6 keys by /64.
- Failure budget: lockout after the budget, `429` for tokenless requests, a
  valid token bypasses it, it lifts after `failure_lockout`, other keys are
  unaffected.
- The IP table stays within `max_tracked_ips` and keeps active lockouts.
- Upload rate: `429` once the bucket empties; rejected requests spend nothing.
- Tombstones beyond `max_tombstones` are evicted oldest first.
- Response headers: `nosniff`, `attachment`, octet-stream, `no-referrer`.
- Startup recovery: every row of the recovery table.
- Startup refuses a `data_dir` with the wrong owner or mode, and a config
  with a zero limit.
- Shutdown exits within `shutdown_grace` while a download is in progress.
- Logs contain no token, full id, or URI, including on error paths.

Unit tests cover config validation, filename validation, URL-safe name
derivation, client-IP resolution, and token hashing.

## Future work

- **Recipient-bound links.** The uploader names a recipient with a
  `Filepass-To: builder` header. filepass records it in the metadata, and
  downloads then require that agent's token. Every agent already has a token,
  so this changes no setup.
- **GitHub login for more than one user.** If filepass ever serves other
  people, users sign in with GitHub's device flow, an allowlist of GitHub
  accounts gates access, and agent tokens are minted under each user through
  `POST /tokens`. Not needed while one operator owns every agent.
- Prometheus `/metrics` on a separate localhost port.
- Config reload on SIGHUP.
- SQLite index if live files outgrow memory.
