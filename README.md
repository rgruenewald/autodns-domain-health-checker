# AutoDNS Domain Health Monitor

Checks and automatically corrects SPF, DMARC, DKIM, and other DNS health records for domains via the AutoDNS API.

## Features

- **SPF**: Validation, include flattening, automatic UDP-safe splitting
- **DMARC**: Validation, creation/updates, external reporting authorization
- **DKIM**: Selector detection via DNS/zone enumeration, sync with `dkim.config.json`
- **Additional Checks**: NS, SOA, CAA, MTA-STS, TLS-RPT, PTR, MX
- **Reports**: SMTP email delivery, file reports in `reports/`
- **Dry-Run**: Audit mode without modifying AutoDNS
- **Modular Architecture**: Clean module separation, Vitest test suite

## Quick Start

```bash
npm install
cp .env.example .env
# edit .env and optionally dkim.config.json
npm start
```

Dry-run: `npm start -- --dry-run` or set `DRY_RUN=true` in `.env`.

## Docker (with Cron)

```bash
cp .env.example .env
cp dkim.config.example.json dkim.config.json
docker-compose up -d --build
```

Default cron: 1:00 AM and 1:00 PM. Edit `crontab`, then `docker-compose up -d --build`.

Manual execution inside container:
```bash
docker-compose exec domain-health-checker node src/index.js
```

## Checks in Detail

Each domain is summarized in a compact one-liner ending with `H:` followed by health flags.

| Check | Source | OK Criteria |
|---|---|---|
| **SPF** | DNS TXT apex | Matches expected policy; flattens includes, splits if >450 bytes |
| **DMARC** | `_dmarc.<domain>` | Matches expected policy (whitespace-normalized) |
| **DKIM** | `<selector>._domainkey.<domain>` | Selector present in `dkim.config.json` and value matches (empty = skipped) |
| **A/AAAA/MX** | AutoDNS zone / DNS fallback | Display only |
| **NS** | DNS NS | ≥2 NS and each hostname resolves to A/AAAA |
| **SOA** | DNS SOA | Values within typical ranges |
| **CAA** | DNS CAA | None present, or at least one `issue`/`issuewild` |
| **MTA-STS** | `_mta-sts.<domain>` + HTTPS policy | TXT `v=STSv1` and policy reachable with `version: STSv1` |
| **TLS-RPT** | `_smtp._tls.<domain>` | TXT contains `v=TLSRPTv1` and `rua=` |
| **PTR** | Reverse DNS of first MX IP | PTR exists |
| **MX** | DNS MX | At least 1 MX and each host resolves to A/AAAA |

**Line-end report flags:** `H: NS:<ok/fail>; SOA:<ok/fail>; CAA:<ok/fail>; MTA:<ok/fail>; TLS:<ok/fail>; PTR:<ok/fail>`

## Configuration (`.env`)

| Variable | Description |
|---|---|
| `AUTODNS_USER` / `AUTODNS_PASSWORD` | API credentials (required) |
| `AUTODNS_CONTEXT` | API context (default: 4) |
| `AUTODNS_API_URL` | API endpoint (default: `https://api.autodns.com/v1`) |
| `DRY_RUN` | `true` = no changes (default: `false`) |
| `MAIN_SPF_RECORD_NAME` / `MAIN_SPF_RECORD_VALUE` | Expected SPF records |
| `EXPECTED_DMARC` / `DMARC_REPORT_AUTH_DOMAIN` | DMARC policy + reporting domain |
| `DKIM_SELECTORS` | Comma-separated selectors |
| `DKIM_CONFIG_PATH` | Path to JSON (default: `dkim.config.json`) |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_SECURE` / `SMTP_USER` / `SMTP_PASSWORD` | SMTP access |
| `EMAIL_FROM` / `EMAIL_TO` / `EMAIL_SUBJECT` | Sender, recipient(s), subject |

## Tests

```bash
npm test
npm run test:watch
npm run test:coverage
```

## Troubleshooting

| Problem | Solution |
|---|---|
| Auth error | Check credentials in `.env` |
| Update failure | Verify AutoDNS zone management permissions |
| Email not sent | Check SMTP settings and timeouts |
| DKIM not found | Verify selectors in `.env` / `dkim.config.json` |
| SPF conflict | Apex CNAME prevents TXT record |

## License

ISC
