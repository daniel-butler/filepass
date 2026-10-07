# filepass — design

Date: 2026-10-07
Status: draft, awaiting review
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
- Links expire. The uploader can revoke one early.
- The server never fills its disk.
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

## HTTP API

### Upload: `PUT /{filename}`

```
curl -T build.zip -H "Authorization: Bearer $FILEPASS_TOKEN" https://filepass.host/
tar czf - ./dist | curl -T - -H "Authorization: Bearer $FILEPASS_TOKEN" https://filepass.host/dist.tar.gz
```

`curl -T file URL/` sends `PUT /file`, so the uploader needs no extra flags.

- **Auth:** `Authorization: Bearer <token>` is required.
- **Query:** `ttl` is optional, a humantime duration such as `10m` or `4h`.
  The default is `default_ttl` (30m). Values above `max_ttl` (24h), zero, or
  unparseable values return `400`.
- **Filename:** the last path segment, percent-decoded. filepass rejects
  empty names, `.`, `..`, names containing `/`, `\` or control characters,
  and names over 255 bytes, all with `400`. The name is metadata only; it
  never becomes a path on disk.
- **Success:** `201 Created`. The body is the download URL plus a newline.
  Headers:
  - `Location`: the download URL
  - `Filepass-Expires`: expiry, RFC 3339 UTC
  - `Filepass-SHA256`: hex digest of the stored bytes
  - `Filepass-Size`: size in bytes
- **Expiry clock** starts when the upload completes, not when it starts.

### Download: `GET /d/{id}/{filename}` (also `HEAD`)

```
curl -fO https://filepass.host/d/3f9c2a7e1b3d4c5e8f9a0b1c2d3e4f5a/build.zip
curl -C - -fO https://filepass.host/d/3f9c.../build.zip   # resume
```

- **No auth.** Possession of the URL grants access until expiry.
- `{id}` is 128 random bits as 32 lowercase hex characters. It cannot be
  guessed, so the URL itself is the credential.
- `{filename}` must match the stored name; a mismatch returns `404`. It exists
  so `curl -O` saves under the right name.
- Supports `Range` requests, so interrupted downloads resume.
- Response headers:
  - `Content-Type: application/octet-stream`, always
  - `Content-Disposition: attachment; filename*=UTF-8''<name>`
  - `X-Content-Type-Options: nosniff`
  - `Cache-Control: private, no-store`
  - `ETag`: the SHA-256 digest
  - `Filepass-SHA256` and `Filepass-Expires`

  filepass never lets a browser render an uploaded file inline, so an uploaded
  `.html` or `.svg` cannot run script on the server's origin.
- A file that expires mid-download finishes. Unix keeps an unlinked file
  readable through an open descriptor.

### Revoke: `DELETE /d/{id}/{filename}`

- Requires the uploader's own token. Another agent's token gets `403`.
- Success is `204`. Later downloads get `410`.

### Health: `GET /healthz`

Returns `200 ok`. No auth.

### Status codes

| Code | Meaning |
|---|---|
| 400 | Bad filename or `ttl` |
| 401 | Missing or unknown token |
| 403 | DELETE by an agent that did not upload the file |
| 404 | Unknown id, or filename mismatch |
| 408 | Upload stalled: no bytes for `upload_idle_timeout` |
| 410 | The file existed but has expired or been revoked |
| 413 | Larger than `max_file_size` |
| 507 | Would exceed the agent quota, total quota, or free-space floor |

`410` differs from `404` on purpose. It tells B to ask A for a fresh upload,
where `404` means the link was never valid.

## Storage

```
data_dir/
  tmp/              uploads in progress; emptied at startup
  files/{id}        file contents
  files/{id}.json   metadata
```

Metadata (`{id}.json`):

```json
{
  "id": "3f9c2a7e1b3d4c5e8f9a0b1c2d3e4f5a",
  "name": "build.zip",
  "size": 734003200,
  "sha256": "…",
  "uploader": "planner",
  "created_at": "2026-10-07T14:00:00Z",
  "expires_at": "2026-10-07T14:30:00Z",
  "state": "live",
  "first_download_at": null,
  "download_count": 0
}
```

`state` is `live`, `expired`, or `revoked`.

### Write order

1. Stream the body into `tmp/{id}`, hashing and counting bytes as they arrive.
2. On completion, `fsync` and rename it to `files/{id}`.
3. Write `files/{id}.json` through a temp file and rename.

A link is live only once its `.json` exists. A crash between steps 2 and 3
leaves an orphaned file, which startup deletes. A crash during step 1 leaves a
temp file, which startup also deletes. No crash can produce a live link to a
partial file.

### In-memory index

At startup filepass reads every `.json` into memory. The index answers
lookups, tracks per-agent and total usage, and drives expiry. This holds up to
tens of thousands of live files; beyond that, SQLite replaces the sidecar files.

`download_count` and `first_download_at` are updated in memory and written to
the `.json` when the file expires or is revoked. A crash loses download
counts, which are only telemetry.

### Expiry

A sweeper runs every 60 seconds. For each live file past `expires_at` it
deletes the contents, sets `state` to `expired`, and keeps the `.json` as a
tombstone for `tombstone_ttl` (7 days). Tombstones let late downloads get
`410`. After `tombstone_ttl` the sweeper deletes the `.json`, and the id
returns `404`.

Downloads also check `expires_at` directly, so a file is unreachable the moment
it expires, even before the sweeper runs.

### Space protection

Every upload passes three limits: `max_file_size`, the uploader's `quota`
(default `agent_quota`), and `total_quota`. The filesystem must also keep
`min_free_space` free.

- If the request declares `Content-Length`, filepass checks all limits before
  reading the body and returns `413` or `507` at once.
- filepass reserves bytes as they stream, so concurrent uploads cannot jointly
  overshoot a quota. Piped uploads (`curl -T -`) declare no length; the
  streamed-byte check catches them.
- When any limit trips mid-stream, filepass stops reading, deletes the temp
  file, releases the reservation, and returns `413` or `507`.
- An upload that sends no bytes for `upload_idle_timeout` (60s) aborts with
  `408`. A stalled client cannot hold a reservation forever.

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
listen              = "127.0.0.1:8080"
public_url          = "https://filepass.host"
data_dir            = "/var/lib/filepass"
log_format          = "text"        # or "json"
trust_proxy_headers = true          # take client IP from X-Forwarded-For

max_file_size       = "2GiB"
default_ttl         = "30m"
max_ttl             = "24h"
tombstone_ttl       = "7d"
upload_idle_timeout = "60s"

total_quota         = "50GiB"
agent_quota         = "10GiB"      # default per agent
min_free_space      = "5GiB"

[agents.planner]
token_sha256 = "9b1c…"

[agents.builder]
token_sha256 = "77ae…"
quota        = "20GiB"            # overrides agent_quota
```

filepass validates the config at startup and refuses to run on errors: unknown
keys, `default_ttl` above `max_ttl`, duplicate token hashes, or a malformed
`public_url`.

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
| `download_bytes` | counter | — | each completed download |
| `time_to_first_download_ms` | timing | `agent` | first download of a file |
| `expired_undownloaded` | counter | `agent` | sweeper expires a file never downloaded |
| `revoke` | counter | `agent`, `result` | each DELETE |
| `stored_bytes` | gauge | `agent`, plus `total` | each sweep |
| `live_files` | gauge | — | each sweep |
| `uploads_in_flight` | gauge | — | each sweep |

`result` takes a fixed set of values: `ok`, `unauthorized`, `forbidden`,
`not_found`, `gone`, `too_large`, `insufficient_storage`, `timeout`,
`bad_request`, `client_aborted`.

Labels never include file ids or filenames, which keeps series count bounded.

`time_to_first_download_ms` and `expired_undownloaded` exist to tune
`default_ttl`. If first downloads cluster near 30 minutes, or many files expire
untouched, raise it.

### Log hygiene

The download URL is the credential. Logs therefore never contain a full id:
they show its first 8 characters. They never contain tokens or token hashes.
Each log line names the agent, the id prefix, the filename, the size, and the
client IP (from `X-Forwarded-For` when `trust_proxy_headers = true`).

Reverse-proxy access logs record full URLs. The README tells operators to
strip the path from the proxy's log for `/d/` requests, or to restrict who
reads those logs.

## Code layout

| Module | Responsibility |
|---|---|
| `main.rs` | CLI (`serve`, `token`), startup, shutdown |
| `config.rs` | Parse and validate TOML; size and duration types |
| `auth.rs` | Token hashing and lookup; `Agent` extractor |
| `store.rs` | Blob and metadata files, in-memory index, reservations, startup recovery |
| `upload.rs` | PUT handler: name validation, streaming, hashing, limits |
| `download.rs` | GET, HEAD, and DELETE handlers |
| `sweeper.rs` | Expiry, tombstone removal, gauge emission |
| `obs.rs` | Metric event helpers |
| `clock.rs` | `Clock` trait; system clock and a test clock |

Main crates: `axum`, `tokio`, `tower-http` (Range support via `ServeFile`),
`sha2`, `rand`, `serde`, `toml`, `humantime`, `tracing`, `tracing-subscriber`,
`clap`, and `nix` for `statvfs`.

## Deployment

- Builds as a static `x86_64-unknown-linux-musl` binary.
- Ships an example systemd unit: dedicated unprivileged user, `ProtectSystem=strict`,
  `ReadWritePaths` set to `data_dir`, listening on localhost.
- The README gives reverse-proxy config. nginx needs:

  ```nginx
  client_max_body_size    2g;      # nginx's default is 1m
  proxy_request_buffering off;     # stream to filepass instead of spooling to disk
  proxy_buffering         off;
  proxy_read_timeout      300s;
  proxy_send_timeout      300s;
  ```

  Caddy needs no body-size setting.

## Testing

Integration tests start the real server on a random port with a temp
`data_dir` and an injected test clock. They cover:

- Upload then download round trip; the SHA-256 header matches the bytes.
- Piped upload without `Content-Length`.
- `401` without a token or with a bad one.
- `413` from a declared length, and from a stream that crosses the limit mid-way.
- `507` from agent quota, total quota, and the free-space floor.
- Concurrent uploads cannot jointly exceed a quota.
- `408` when an upload stalls.
- Filename rejection: `..`, slashes, control characters, overlong names.
- `ttl` default, explicit, over the cap, and malformed.
- `410` after expiry (advance the test clock) and after revoke.
- `404` after the tombstone expires, and for a filename mismatch.
- `403` when another agent tries to revoke.
- Range request returns the requested slice; resume reassembles the file.
- Response headers: `nosniff`, `attachment`, octet-stream.
- Startup recovery deletes temp files and orphaned blobs.
- Logs contain neither tokens nor full ids.

Unit tests cover config validation, filename validation, and token hashing.

## Future work

- **Recipient-bound links.** The uploader names a recipient with `?to=builder`.
  filepass records it in the metadata, and downloads then require that agent's
  token. Every agent already has a token, so this changes no setup.
- Prometheus `/metrics` on a separate localhost port.
- Config reload on SIGHUP.
- SQLite index if live files outgrow memory.
