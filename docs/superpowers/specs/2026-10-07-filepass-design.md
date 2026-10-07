# filepass — design

Date: 2026-10-07
Status: draft, revised after review, awaiting approval
License: MIT
Repo: `daniel-butler/filepass`

## Purpose

Agents already message each other. Those messages are small and text-only.
filepass carries the attachments: agent A uploads a file, gets back a URL,
and pastes that URL into its message to agent B. B downloads it with `curl`.

filepass is a single Rust binary that runs on a locked-down server behind a
TLS-terminating reverse proxy. It stores nothing permanent: every file expires,
by default after 30 minutes.

## Goals

- Plain HTTP. An agent needs only `curl`; there is no client to install.
- Files up to 2 GiB of any type: zips, tarballs, binaries.
- Each agent authenticates uploads with its own token.
- Links expire. The uploader can revoke one early, and revocation is immediate.
- The server never fills its disk, its inodes, or its memory.
- Operators see what happens through structured logs and metric events.
- Nothing leaves the server. No phone-home telemetry.

## Non-goals (v1)

- Resumable uploads. Files stay under 2 GiB and come from well-connected
  hosts; a failed upload restarts.
- Recipient-bound links (see Future work).
- A client CLI, web UI, or MCP server.
- TLS termination. The reverse proxy does it.
- More than one server node.
- A Prometheus endpoint.
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
- **Path:** exactly one non-empty segment. `PUT /` returns `400` with the body
  `name the file: PUT /<filename> (curl -T - needs an explicit name)`.
  Paths with more than one segment return `400`.
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
- **Success:** `201 Created`. The body is the download URL plus a newline.
  Headers:
  - `Location`: the download URL
  - `Filepass-Expires`: expiry, RFC 3339 UTC
  - `Filepass-SHA256`: hex digest of the stored bytes
- **Expiry clock** starts when the upload completes, not when it starts.

### Download: `GET /d/{id}/{urlname}` (also `HEAD`)

```
curl -fO https://filepass.host/d/3f9c2a7e1b3d4c5e8f9a0b1c2d3e4f5a/build.zip
curl -C - -fO https://filepass.host/d/3f9c.../build.zip   # resume
```

- **No auth.** Possession of the URL grants access until expiry or revocation.
- `{id}` is 128 random bits as 32 lowercase hex characters. It cannot be
  guessed, so the URL itself is the credential.
- `{urlname}` must equal the stored URL-safe name; a mismatch returns `404`.
- Supports single-range `Range` requests, so interrupted downloads resume.
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
  finishes.
- **Revoke mid-download:** revocation aborts every download of that file in
  progress. Revocation exists for leaked links, so it must stop transfers, not
  only new requests.
- **Limits:** at most `max_concurrent_downloads` (64) run at once; beyond that,
  `503`. A download whose client accepts no bytes for `download_idle_timeout`
  (60s) is dropped.

### Revoke: `DELETE /d/{id}/{urlname}`

Requires a token. filepass checks in this order:

| Condition | Response |
|---|---|
| Unknown id, or name mismatch | `404` |
| Token belongs to an agent other than the uploader | `403` |
| Already expired or revoked | `410` |
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
| 503 | Too many concurrent downloads |
| 507 | Would exceed the agent's byte quota, its `max_files`, the total quota, or the free-space floor |

`410` differs from `404` on purpose. It tells B to ask A for a fresh upload,
where `404` means the link was never valid.

**Early rejection.** When filepass rejects an upload before reading its body
(`401`, `413`, or `507` from a declared length), the server closes the
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
  "state": "live"
}
```

`state` is `live`, `expired`, or `revoked`. Every metadata write goes to
`tmp/`, is fsynced, then renamed into `files/`; filepass then fsyncs
`files/`.

### Upload write order

1. Stream the body into `tmp/{id}`, hashing and counting bytes as they arrive.
2. On completion, fsync the file and rename it to `files/{id}`.
3. Write `files/{id}.json` (as above), then fsync `files/`.

A link is live only once its `.json` exists. No crash can produce a live link
to a partial file.

### Revoke and expiry order

1. Rewrite the `.json` with `state` set to `revoked` or `expired`, durably.
2. Fire the file's cancellation token (revoke only), aborting its downloads.
3. Unlink `files/{id}` and fsync `files/`.

Writing the state first means a crash can leave an orphaned blob, which startup
deletes, but can never bring a revoked file back.

### Startup recovery

Recovery runs to completion before the listener binds.

| Found | Action |
|---|---|
| Anything in `tmp/` | Delete |
| A blob with no `.json` | Delete |
| A `.json` that fails to parse | Delete it and its blob; log a warning |
| `live` `.json` with no blob | Mark `expired` |
| `live` `.json` past `expires_at` | Expire it (revoke and expiry order) |
| `expired`/`revoked` `.json` past `expires_at + tombstone_ttl` | Delete |

### Permissions

At startup filepass refuses to run unless `data_dir` is owned by its own user
with mode `0700`. It creates every file with mode `0600`. Paths on disk are
built only from hex ids, so names cannot traverse or follow symlinks.

### In-memory index

The index holds every `.json` loaded at startup and updated since. It answers
lookups, tracks per-agent bytes and file counts, holds reservations, and
drives expiry. Each live file also carries in memory a cancellation token, its
first-download time, and an in-flight download count; none of these persist.

### Expiry

A sweeper runs every 60 seconds. For each live file past `expires_at` it runs
the expiry order above. It keeps the `.json` as a tombstone for
`tombstone_ttl` (48h) so late downloads get `410`, then deletes it, and the id
returns `404`.

Downloads also check `expires_at` directly, so a file is unreachable the moment
it expires, even before the sweeper runs.

### Space protection

Every upload passes these limits:

- `max_file_size` (2 GiB)
- the uploader's byte `quota` (default `agent_quota`)
- the uploader's `max_files` (default 1000), counting live files and tombstones
- `total_quota`
- `min_free_space`, measured with `nix::sys::statvfs` as `f_bavail × f_frsize`

How filepass enforces them:

- With a declared `Content-Length`, filepass checks every limit and reserves
  the full length before reading the body. Two uploads cannot both pass the
  check and then collide.
- Without one (`curl -T -`), filepass reserves bytes as they stream and
  re-checks free space once per MiB received.
- When a limit trips mid-stream, filepass stops reading, deletes the temp
  file, releases the reservation, and returns `413` or `507`.
- An upload that sends no bytes for `upload_idle_timeout` (60s), or runs
  longer than `max_upload_duration` (1h), aborts with `408`. A trickling
  client cannot hold a reservation forever.

The `max_files` limit counts tombstones so that upload-then-revoke loops cannot
exhaust inodes or grow the index.

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

max_file_size            = "2GiB"
default_ttl              = "30m"
max_ttl                  = "24h"
tombstone_ttl            = "48h"
upload_idle_timeout      = "60s"
max_upload_duration      = "1h"
download_idle_timeout    = "60s"
max_concurrent_downloads = 64
shutdown_grace           = "30s"

total_quota              = "50GiB"
agent_quota              = "10GiB"     # default bytes per agent
agent_max_files          = 1000        # default files per agent, incl. tombstones
min_free_space           = "5GiB"

[agents.planner]
token_sha256 = "9b1c…"

[agents.builder]
token_sha256 = "77ae…"
quota        = "20GiB"                 # overrides agent_quota
max_files    = 5000                    # overrides agent_max_files
```

filepass validates the config at startup and refuses to run on errors: unknown
keys, `default_ttl` above `max_ttl`, duplicate token hashes, or a malformed
`public_url`.

## Shutdown

On SIGTERM filepass stops accepting connections and waits up to
`shutdown_grace` (30s) for requests in flight, then exits. Keep
`shutdown_grace` below systemd's `TimeoutStopSec` (default 90s). Interrupted
uploads leave temp files, which the next startup deletes.

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
| `stored_bytes` | gauge | `agent`, plus `total` | each sweep |
| `live_files` | gauge | — | each sweep |
| `uploads_in_flight` | gauge | — | each sweep |
| `downloads_in_flight` | gauge | — | each sweep |

A **download** is a `GET` answered `200` or `206`. `HEAD` requests do not
count. The first such response sets a file's first-download time. Range resumes
count as further downloads but never reset that time.

`result` takes a fixed set of values: `ok`, `unauthorized`, `forbidden`,
`not_found`, `gone`, `too_large`, `insufficient_storage`, `timeout`,
`bad_request`, `busy`, `revoked`, `client_aborted`.

Labels never include file ids or filenames, which keeps series count bounded.

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
size, and the client address: the rightmost `X-Forwarded-For` entry when
present (the one the proxy appended), else the socket peer.

Reverse-proxy access logs record full URLs. The README tells operators to
strip the path from the proxy's log for `/d/` requests, or to restrict who
reads those logs.

## Code layout

| Module | Responsibility |
|---|---|
| `main.rs` | CLI (`serve`, `token`), startup, shutdown |
| `config.rs` | Parse and validate TOML; size and duration types |
| `auth.rs` | Token hashing and lookup; `Agent` extractor |
| `names.rs` | Filename validation and URL-safe name derivation |
| `store.rs` | Blob and metadata files, in-memory index, reservations, recovery |
| `upload.rs` | PUT handler: streaming, hashing, limits, timeouts |
| `download.rs` | GET, HEAD, and DELETE handlers; range serving; cancellation |
| `sweeper.rs` | Expiry, tombstone removal, gauge emission |
| `obs.rs` | Metric event helpers |
| `clock.rs` | `Clock` trait; system clock and a test clock |

**Downloads do not use tower-http's `ServeFile`.** `ServeFile` opens the file
by path after the handler's index check, so a concurrent revoke or expiry turns
an intended `410` into `404`. It also emits its own ETag and Last-Modified.
filepass instead opens the file descriptor while holding the index entry,
maps a vanished file to `410`, parses `Range` with the `http-range-header`
crate, and streams the descriptor with `tokio_util::io::ReaderStream`. The
stream stops when the file's cancellation token fires or the client stalls
past `download_idle_timeout`.

Main crates: `axum`, `tokio`, `tokio-util`, `http-range-header`, `sha2`,
`rand`, `serde`, `serde_json`, `toml`, `humantime`, `tracing`,
`tracing-subscriber`, `clap`, and `nix` (`fs` feature, for `statvfs`).

## Deployment

- Builds as a static `x86_64-unknown-linux-musl` binary.
- Ships an example systemd unit: dedicated unprivileged user, `ProtectSystem=strict`,
  `ReadWritePaths` set to `data_dir`, listening on localhost.
- The README gives reverse-proxy config. nginx needs:

  ```nginx
  client_max_body_size    2g;      # nginx's default is 1m
  proxy_http_version      1.1;     # without it, nginx < 1.29.7 spools chunked uploads to disk
  proxy_request_buffering off;     # stream to filepass instead of spooling to disk
  proxy_buffering         off;
  proxy_read_timeout      300s;
  proxy_send_timeout      300s;
  ```

  Without `proxy_http_version 1.1`, nginx writes every `curl -T -` upload to
  its own disk before forwarding it. That space escapes filepass's quotas and
  free-space floor. Caddy needs no body-size setting.

## Testing

Integration tests start the real server on a random port with a temp
`data_dir` and an injected test clock. They cover:

- Upload then download round trip; the SHA-256 header matches the bytes.
- `curl -T file URL/` and `curl -T - URL/name` both work, run with the real
  curl binary.
- `PUT /` and multi-segment paths return `400`.
- `Filepass-TTL`: default, explicit, over the cap, zero, malformed.
- `401` without a token or with a bad one.
- `413` from a declared length, and from a stream that crosses the limit.
- `507` from agent byte quota, agent `max_files`, total quota, and the
  free-space floor.
- Two concurrent uploads with declared lengths cannot jointly exceed a quota.
- `408` for an idle upload and for one past `max_upload_duration`.
- Filename rejection: invalid UTF-8, `..`, slashes, C0, DEL, C1, bidi
  controls, overlong names. URL-safe name derivation.
- `410` after expiry (advance the test clock) and after revoke.
- `404` after the tombstone expires, and for a name mismatch.
- DELETE ordering: `404`, `403`, `410`, `204`.
- Revoke aborts a download in progress.
- `503` beyond `max_concurrent_downloads`.
- Range request returns the requested slice; resume reassembles the file.
- Response headers: `nosniff`, `attachment`, octet-stream, `no-referrer`.
- Startup recovery: every row of the recovery table.
- Startup refuses a `data_dir` with the wrong owner or mode.
- Logs contain no token and no full id, including on error paths.

Unit tests cover config validation, filename validation, URL-safe name
derivation, and token hashing.

## Future work

- **Recipient-bound links.** The uploader names a recipient with a
  `Filepass-To: builder` header. filepass records it in the metadata, and
  downloads then require that agent's token. Every agent already has a token,
  so this changes no setup.
- Prometheus `/metrics` on a separate localhost port.
- Config reload on SIGHUP.
- SQLite index if live files outgrow memory.
