# filepass

filepass hands files between agents over plain HTTP. Agent A uploads a file
with `curl` and gets back a URL; it pastes that URL into its message to
agent B, who downloads it with `curl`. Nothing is stored permanently: every
file expires, by default after 30 minutes.

## Quick start

Build the binary:

```
cargo build --release
```

Mint a token for an agent:

```
filepass token
```

This prints a token and its SHA-256. Put the hash in your config under
`[agents.<name>]`; give the token to the agent. The config stores only the
hash, so a leaked config file grants no access.

Write a config (see `deploy/filepass.example.toml`) and start the server:

```
filepass serve --config /etc/filepass/filepass.toml
```

## Agent usage

Upload, with an optional TTL:

```
curl -T build.zip -H "Authorization: Bearer $FILEPASS_TOKEN" https://filepass.host/
curl -T build.zip -H "Authorization: Bearer $FILEPASS_TOKEN" -H "Filepass-TTL: 4h" https://filepass.host/
tar czf - ./dist | curl -T - -H "Authorization: Bearer $FILEPASS_TOKEN" https://filepass.host/dist.tar.gz
```

curl appends the local filename when the URL ends in `/` and has no query
string. It never appends a name for `-T -`, so piped uploads must name the
file in the URL. The response is `201 Created`; the body is the download
URL plus a newline, and the `Filepass-Expires` and `Filepass-SHA256` headers
carry the expiry and the hash of the stored bytes.

Download, and resume an interrupted download:

```
curl -fO https://filepass.host/d/3f9c2a7e1b3d4c5e8f9a0b1c2d3e4f5a/build.zip
curl -C - -fO https://filepass.host/d/3f9c2a7e1b3d4c5e8f9a0b1c2d3e4f5a/build.zip
```

Possession of the download URL grants access; there is no separate download
token. Revoke a link early (for example, a link pasted into the wrong
message):

```
curl -X DELETE -H "Authorization: Bearer $FILEPASS_TOKEN" https://filepass.host/d/3f9c2a7e1b3d4c5e8f9a0b1c2d3e4f5a/build.zip
```

Only the uploading agent's token can revoke a file. Revocation is immediate:
it aborts any download of that file already in progress.

Check the downloaded bytes against the hash the upload returned:

```
echo "$FILEPASS_SHA256  build.zip" | sha256sum -c
```

### Status codes

| Code | Meaning |
|---|---|
| 400 | Bad path, filename, or `Filepass-TTL` |
| 401 | Missing or unknown token |
| 403 | DELETE by an agent that did not upload the file |
| 404 | Unknown id, name mismatch, or no route |
| 405 | Method not allowed on a matched path |
| 408 | Upload stalled or exceeded `max_upload_duration` |
| 410 | The file existed but has expired or been revoked |
| 413 | Larger than `max_file_size` |
| 416 | Unsatisfiable range |
| 429 | A per-agent or per-client limit reached |
| 500 | Disk or I/O error |
| 503 | A server-wide concurrency limit reached |
| 507 | Would exceed the agent quota, `max_files`, the total quota, or the free-space or free-inode floor |

`410` differs from `404` on purpose: `410` tells the downloader to ask the
uploader for a fresh upload; `404` means the link was never valid. Every
`429` and `503` carries `Retry-After`.

### Early rejection

When filepass rejects an upload before reading its body (`400`, `401`,
`413`, `429`, `503`, or `507`), it closes the connection with body bytes
still unread. curl often reports this as a send error, exit code 55,
instead of printing the status. If you see curl exit 55 on upload, check
the response status rather than assuming a network problem.

On download, curl exit code 18 ("transfer closed with ... bytes remaining
to read") means the link was revoked, or the connection was dropped mid
transfer (idle timeout or `max_download_duration`) — not a truncated-but-
successful download. filepass always sets `Content-Length`, so a download
that stops early fails rather than completing with a short file.

## Security model

- **Upload token.** Each agent authenticates uploads with its own
  `Authorization: Bearer` token. The config stores only the token's
  SHA-256; the raw token exists only at mint time and on the agent.
- **Bearer links.** A download URL contains a 128-bit random id. Nobody can
  guess it, so the URL itself is the download credential — no token is
  needed for `GET`/`HEAD`. `DELETE` (revoke) additionally requires the
  uploading agent's own token, so only the uploader can revoke a link.
- **TTL.** Every file expires. The default is 30 minutes
  (`default_ttl`); an upload can request up to 24 hours (`max_ttl`) with
  the `Filepass-TTL` header.

## Deployment

filepass is a single static binary
(`x86_64-unknown-linux-musl`). It expects to run behind a TLS-terminating
reverse proxy and listens on localhost only.

**Never expose filepass directly to the internet.** `axum::serve` sets no
header-read timeout, so filepass relies on the reverse proxy to drop
clients that send headers slowly.

### systemd

See `deploy/filepass.service`. It runs as a dedicated unprivileged user,
with `StateDirectory=filepass` (mode `0700`), `ProtectSystem=strict`, and
`LimitNOFILE=65536` so upload and download file descriptors never approach
the process limit. Copy it to `/etc/systemd/system/filepass.service`,
adjust the binary path if needed, and:

```
systemctl daemon-reload
systemctl enable --now filepass
```

### nginx

See `deploy/nginx.conf`. The `location /` block needs:

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
IP, and every client shares the proxy's address and one per-client download
limit.

### Caddy

See `deploy/Caddyfile`:

```
filepass.example.com {
	reverse_proxy 127.0.0.1:8080
}
```

Caddy needs no body-size setting. filepass's own producer task enforces the
download idle timeout, so neither proxy's send timeout is load-bearing.
Caddy's `reverse_proxy` sets `X-Forwarded-For` to the client address and
ignores client-supplied values unless Caddy's own `trusted_proxies` says
otherwise.

### Proxy access logs

The download URL is the credential — anyone who reads it can download the
file until it expires. filepass's own logs never record a full id, a
token, or a request URI, but a reverse proxy's access log records the full
URL by default. Configure your proxy to strip the path from `/d/` requests
in its access log, or restrict who can read those logs.

## Telemetry

filepass writes everything through `tracing` to stdout; under systemd it
lands in journald. `log_format` (`text` or `json`) selects the format.
**Nothing leaves the server** — there is no phone-home telemetry.

A metric is one structured log event on the `metric` tracing target, with
fields `metric=<name>`, its labels, and `value` (the increment for
counters, the reading for gauges, or milliseconds for timings). For
example, a successful upload emits something like:

```
metric=upload agent=planner result=ok value=1
metric=upload_bytes agent=planner value=734003200
metric=upload_duration_ms agent=planner value=842 unit=ms
```

Each counter and timing is paired with a readable log line at the same call
site, so operators can read the log or count the metric. A log shipper such
as Vector can turn these events into counters without code changes. Labels
never include file ids, filenames, or IPs.

## Future work

- **Recipient-bound links.** The uploader names a recipient with a
  `Filepass-To: builder` header. filepass records it in the metadata, and
  downloads then require that agent's token. Every agent already has a
  token, so this changes no setup.
- **GitHub login for more than one user.** If filepass ever serves other
  people, users sign in with GitHub's device flow, an allowlist of GitHub
  accounts gates access, and agent tokens are minted under each user
  through `POST /tokens`. Not needed while one operator owns every agent.
- Prometheus `/metrics` on a separate localhost port.
- Config reload on SIGHUP.
- SQLite index if live files outgrow memory.

## License

MIT
