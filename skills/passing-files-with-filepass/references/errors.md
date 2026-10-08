# filepass errors

## Upload (`send.sh` / `curl -T`)

| Status / exit | Meaning | Do |
|---|---|---|
| `201` | Stored | Paste the printed block into your message |
| `400` | Bad name, path, or `Filepass-TTL` | Read the response body. Piped uploads need a name (`send.sh - name`). TTL must be like `30m`, `4h`, at most `24h` |
| `401` | Token missing or rejected | `check.sh`; if still rejected, ask the user for a new token |
| `408` | Upload stalled 60s, or ran over 1h | Retry; if repeated, the link from here to the server is too slow |
| `413` | Over the size limit (default 2 GiB) | Split it (`split -b 1G`) or compress it |
| `429` | This agent has too many uploads running, or hit its rate limit | Wait `Retry-After` seconds, retry once |
| `503` | Server-wide upload limit | Wait `Retry-After` seconds, retry once |
| `507` | Agent quota, file count, or server disk full | Revoke links the receiver already has (below), or tell the user — retrying won't help |
| curl exit 55 / 56 | Server closed the connection before reading the body — it rejected the upload (one of the codes above) | Run `check.sh`; check file size; then retry once |
| curl exit 6 / 7 | Can't resolve or connect | Wrong `FILEPASS_URL`, server down, or (cloud) host not in the network policy |

## Download (`fetch.sh` / `curl -fO`)

| Status / exit | Meaning | Do |
|---|---|---|
| `200` / `206` | OK (206 = resumed) | Verify the SHA-256 |
| `404` | No such link: mistyped, truncated in the message, or expired more than 48h ago | Ask the sender to resend the link |
| `410` | Expired or revoked | Ask the sender to upload again, with a longer TTL if you were slow |
| `416` | Resume past the end — the file is already complete | Verify the SHA-256 |
| `429` / `503` | Too many downloads at once | Wait `Retry-After`, retry |
| curl exit 18 | Transfer cut off: revoked, or idle/duration limit | Retry once (`fetch.sh` resumes); still failing → ask the sender |
| SHA-256 mismatch | Corrupt or wrong file | Don't use it; ask the sender to resend |

## Revoking a link early

The uploader can kill a link once the receiver has the file, or if it leaked:

```bash
curl -X DELETE -H "Authorization: Bearer $FILEPASS_TOKEN" "<link>"   # 204 = revoked
```

Only the uploading agent's token can revoke (`403` otherwise).
