# Setting up filepass for an agent

An agent needs two environment variables and network access to the server.

| Variable | Value |
|---|---|
| `FILEPASS_URL` | The server's public URL, e.g. `https://filepass.example.com` |
| `FILEPASS_TOKEN` | This agent's token, `fp_…` (46 characters) |

Check with `bash scripts/check.sh`. It stores nothing: it hits `/healthz`, then
sends an empty `PUT /` — a valid token gets `400`, a bad one `401`.

| `check.sh` exit | Meaning |
|---|---|
| 0 | Ready to send and receive |
| 10 | Receive-only: server reachable, no `FILEPASS_TOKEN` |
| 2 | `FILEPASS_URL` unset, or curl missing |
| 3 | Server unreachable (URL, DNS, network policy) |
| 4 | Token rejected |

## Getting a token (the operator does this)

Tokens are issued by whoever runs the server; an agent cannot mint its own.

```bash
filepass token
# token: fp_…            ← give to the agent
# token_sha256: 9b1c…    ← goes in the server config
```

Add the hash to the server's config under a new agent name, then restart:

```toml
[agents.planner]
token_sha256 = "9b1c…"
```

Agent names: lowercase letters, digits, `_`, `-`; up to 32 characters. One
token per agent role keeps the server's logs and quotas per agent.

## Local sessions (your machine)

Export the variables in your shell profile so every Claude Code session gets them:

```bash
export FILEPASS_URL=https://filepass.example.com
export FILEPASS_TOKEN=fp_…
```

## Cloud sessions (Claude Code on the web)

Cloud containers don't see your shell profile.

1. Add `FILEPASS_URL` and `FILEPASS_TOKEN` as environment variables in the
   environment's settings.
2. Allow the filepass host in the environment's network policy. Without it,
   `check.sh` reports `Could not resolve host` or `Failed to connect`.
3. Make the skill available: add the marketplace and plugin to the repo's
   `.claude/settings.json` (user settings don't travel to the cloud):

```json
{
  "extraKnownMarketplaces": {
    "filepass": { "source": { "source": "github", "repo": "daniel-butler/filepass" } }
  },
  "enabledPlugins": { "filepass@filepass": true }
}
```

## Receiving needs no setup

Download links carry their own access. A session with no token can still run
`fetch.sh`; it only needs network access to the host.
