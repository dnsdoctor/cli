# dns-doctor — DNS Doctor from the terminal

Scan, fix and verify a domain's DNS without leaving the shell: email
authentication (SPF, DMARC, DKIM), MX, DNS health, blacklists, domain/SSL expiry
and propagation read from six locations on four continents. Every fix record
comes from a deterministic, validating engine — RFC grammar plus the SPF
10-lookup counter — **never an AI guess**, and a human approves every DNS change.

```
npx dns-doctor scan example.com
```

No account, no key. The CLI calls the public DNS Doctor API
(https://dnsdoctor.dev) and prints what it returns.

## Commands

Every tool the DNS Doctor MCP server exposes has a command here.

```
scan & fix
  dns-doctor scan <domain> [--fresh]              the seven-check report (persisted, or fresh on a miss)
  dns-doctor dmarc-upgrade <domain>               the next safe DMARC step as a record, or why there is none
  dns-doctor parked <domain> --confirm-no-mail    the hardening pack for a domain that sends no mail
  dns-doctor signup-url <domain>                  a sign-up link to hand the domain's owner for monitoring

records
  dns-doctor dmarc-validate "<record>"            every tag checked, with the safe next step
  dns-doctor dmarc-generate <none|quarantine|reject> [--rua <email>] [--subdomain-policy <p>] [--strict]
  dns-doctor spf-count <domain | "v=spf1 …">      DNS lookups against the 10-lookup limit
  dns-doctor spf-audit <domain>                   the SPF include tree with registration and lookup findings
  dns-doctor dkim <domain> --selector <s>         a DKIM selector's published key
  dns-doctor report-parse <file.xml|.gz|.zip>     one DMARC aggregate report as a table

live DNS
  dns-doctor record <domain> --kind <spf|dmarc|txt|mx|cname|a|aaaa> [--host <label>]
  dns-doctor propagation <name> [--type A] [--expect <value>]
  dns-doctor reverse-dns <ip>

monitoring (DNSDOCTOR_API_TOKEN required)
  dns-doctor alerts [--domain d] [--since t] [--before t] [--alert-type t] [--limit n]
  dns-doctor readiness <domain>
```

Add `--json` to any command to print the API response verbatim — the path for
scripts and agents.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | nothing failing |
| 1 | a failing verdict (a failed check, an invalid or over-limit record, a name not propagated, a reverse name that does not point back, nameservers that disagree) |
| 2 | an error — including every transient: rate limit, a paid-retry offer (HTTP 402), an outage. **Never read 2 as a verdict about the domain.** |

## Example

```
$ dns-doctor scan example.com
example.com  (scanned 2026-09-06T10:12:03Z)
  FAIL  dmarc    No DMARC record found — receivers can't verify your mail
        fix (paste verbatim, a human must approve the DNS change):
        v=DMARC1; p=none; np=reject
  WARN  dkim     No DKIM key found at the common selectors
  PASS  spf      SPF record is valid
  …
  report: https://dnsdoctor.dev/scan/example.com
```

The record printed under `fix` is the API's bytes. The CLI never composes,
reformats or "improves" a record; SPF is diagnose-only by design (an SPF edit
can silently de-authorise a real sender), so no SPF record is ever proposed.

## Environment

- `DNSDOCTOR_API_TOKEN` — optional bearer token (mint one in the DNS Doctor
  dashboard); raises the anonymous budget. Never required for the commands above.
- `DNSDOCTOR_API_BASE` — override the API origin for local runs.

Past the free per-caller allowance the API answers HTTP 402 with an x402 offer
(USDC on Base). This CLI holds no wallet: it reports the offer and exits 2. Pay
with an x402 client or wait and retry.

## Also

- Hosted MCP server: `https://dnsdoctor.dev/mcp` · stdio client: `npx -y @dnsdoctor/mcp`
- Methodology: https://dnsdoctor.dev/methodology · API: https://dnsdoctor.dev/openapi.json

Apache-2.0.
