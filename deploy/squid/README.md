# Egress Proxy (Squid)

Production network isolation for LatchGate action execution.

## Security model

The Squid image ships with a **deny-all default** — no outbound domains
are permitted until the gate populates the allowlist at runtime.

Three layers enforce egress, each with a distinct role:

| Layer | Role | Source |
|---|---|---|
| **Kernel** (`validate_sink`) | Per-action domain enforcement | Manifests + learned domains |
| **Squid proxy** | Network-layer domain allowlist | Live file from gate |
| **OpenShell** (NemoClaw) | Binary scoping (who may egress) | Static policy |

Both the kernel and proxy must allow a request. Either blocking is
sufficient to deny.

## How it works

```
                      ┌─────────────────────────┐
                      │     Action Manifests     │
                      │  (single source of truth)│
                      └────────────┬─────────────┘
                                   │
                           gate startup +
                          domain mutations
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │  /var/run/latchgate/egress/   │
                    │  allowlist.txt                │
                    │  (atomic write, live sync)    │
                    └──────────────┬───────────────┘
                                   │
                          squid -k reconfigure
                                   │
                                   ▼
    Agent ──► LatchGate ──► WASM provider ──► Squid ──► Internet
                 │                              │
                 │ validate_sink()              deny private IPs
                 │ (per-action)                deny metadata
                 │                              allowlist only
```

The gate writes `(manifest_domains ∪ learned_domains) ∩ runtime_allowlist`
to the live file at startup, after `domains add/remove/clear`, and after
approval domain learning.

## Setup

### 1. Configure live sync in `latchgate.toml`

```toml
egress_proxy_url = "http://squid:3128"
egress_live_allowlist_path = "/var/run/latchgate/egress/allowlist.txt"
egress_reload_command = "squid -k reconfigure"
```

### 2. Share the allowlist volume

```yaml
# docker-compose.yml
services:
  gate:
    volumes:
      - egress-allowlist:/var/run/latchgate/egress

  squid:
    image: ghcr.io/latchgate-ai/latchgate-egress:latest
    volumes:
      - egress-allowlist:/etc/squid:rw
    networks:
      - toolnet
      - egress

volumes:
  egress-allowlist:

networks:
  toolnet:
    internal: true    # no direct internet
  egress:
    driver: bridge    # Squid's outbound path
```

### 3. Verify

```bash
# After gate starts, the allowlist is populated:
docker exec <squid-container> cat /etc/squid/allowlist.txt

# Add a learned domain — Squid updates automatically:
latchgate domains add web_read newapi.example.com
```

## Manual generation (offline / CI)

For environments without live sync, generate from a specific set of
action manifests:

```bash
latchgate manifests export-egress --format squid \
  --include-actions http_fetch,gmail_send \
  --output allowlist.txt
```

<!-- GENERATED — do not hand-edit domain lists. -->

## Logs

```bash
docker exec <squid-container> cat /var/log/squid/access.log
```

Format: `timestamp duration client_ip status size method url hierarchy content_type`
