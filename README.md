# AutoDNS Domain Health Monitor

A modular Node.js application to query and validate domain health from AutoDNS API. Checks SPF, DMARC, and DKIM records, automatically corrects misconfigurations, and sends email reports.

## Features

- **SPF Record Validation**: Checks and updates SPF records, with automatic flattening of includes
- **DMARC Record Management**: Validates DMARC policies, creates/updates records, and adds external reporting authorization
- **DKIM Record Discovery**: Detects DKIM selectors via DNS or zone enumeration, updates records from local config
- **Email Reports**: Sends detailed plain-text reports via SMTP with summary counts
- **Multi-Domain Support**: Tests specific domains with configurable filtering
- **Automated Remediation**: Updates incorrect DNS records via AutoDNS API
- **Modular Architecture**: Well-organized codebase with separation of concerns
- **Unit Tests**: Comprehensive test coverage with Vitest

## Project Structure

```
diebasis-domain-health/
├── src/
│   ├── index.js                    # Main entry point
│   ├── lib/
│   │   ├── config.js               # Configuration management
│   │   ├── autodns-client.js       # AutoDNS API client with rate limiting
│   │   ├── dns-operations.js       # DNS resolution utilities
│   │   ├── spf.js                  # SPF validation and flattening
│   │   ├── dmarc.js                # DMARC validation and updates
│   │   ├── dkim.js                 # DKIM checking and config management
│   │   ├── domain-processor.js     # Domain checking orchestration
│   │   └── reporting.js            # Report generation and email
│   └── utils/
│       └── helpers.js              # Utility functions (timestamps, colors)
├── tests/
│   ├── lib/
│   │   ├── dmarc.test.js           # DMARC module tests
│   │   └── spf.test.js             # SPF module tests
│   └── utils/
│       └── helpers.test.js         # Helper function tests
├── index.js                        # Legacy entry point (deprecated)
├── vitest.config.js                # Test configuration
└── package.json                    # Dependencies and scripts
```

## Prerequisites

- Node.js (version 14 or higher)
- AutoDNS account with API access and zone management permissions
- SMTP server access for email reports

## Installation

1. Clone or download this repository

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure your credentials and settings:
   ```bash
   cp .env.example .env
   ```

4. Edit the `.env` file with your AutoDNS, SMTP, and domain policy settings (see Configuration below)

5. (Optional) Create `dkim.config.json` to specify desired DKIM records per domain:
   ```json
   {
     "example.com": {
       "selector1": "v=DKIM1;k=rsa;p=MIGfMA0GCSqGSIb3DQEBAQUAA...",
       "selector2": "v=DKIM1;k=rsa;p=MIGfMA0GCSqGSIb3DQEBAQUAA..."
     }
   }
   ```

## Usage

Run the application:
```bash
npm start
```

Run in dry-run mode (reports only, no changes to AutoDNS):
```bash
npm start -- --dry-run
```

Or set `DRY_RUN=true` in your `.env` file.

Run the legacy monolithic version:
```bash
npm run legacy
```

The application will:
- Query all domains from your AutoDNS account
- Filter to test-specific domains (configurable in code)
- Check SPF, DMARC, and DKIM records
- Update incorrect or missing records automatically (unless in dry-run mode)
- Generate a report and send it by email

## Checks performed (domain health)

Each domain is evaluated with a compact one-line summary and an additional
health flag `H:` at the end. Below is what we check and how we decide ok/fail.

1) SPF (Sender Policy Framework)
- Source: DNS TXT for the zone apex
- Pass when the current TXT record starting with `v=spf1` matches the
   expected policy. The tool also builds a flattened SPF (resolves include:
   and certain A/MX mechanisms) and updates `_spf.diebasis.de` with it.
- Remediation: auto-create/update SPF at apex (guarding against apex CNAME);
   dry-run prevents changes.

2) DMARC
- Source: DNS TXT at `_dmarc.<domain>`
- Normalization removes spaces after semicolons before comparing to the
   expected policy.
- Remediation: auto-create/update DMARC TXT; additionally creates the
   external reporting authorization TXT under the configured
   `DMARC_REPORT_AUTH_DOMAIN`.

3) DKIM
- Source: DNS TXT at `<selector>._domainkey.<domain>` and AutoDNS zone
   enumeration as fallback.
- Desired selectors/values are loaded from `dkim.config.json`. Empty values
   are skipped and will show `DKIM: skipped`.
- Remediation: auto-create/update missing or mismatched selectors with non-
   empty desired values.

4) DNS records (display only)
- A/AAAA/MX at apex are shown from AutoDNS zone; if not present there, a
   DNS lookup fallback is used (covers AutoDNS "main IP" cases).

5) NS (delegation)
- Source: DNS NS set at the domain
- ok when there are at least 2 NS records and the NS hostnames resolve to
   at least one A or AAAA address each.

6) SOA sanity
- Source: DNS SOA at the domain
- ok when typical ranges are met (rough heuristic):
   - refresh: 3600–86400
   - retry: 300–7200
   - expire: 604800–2419200
   - minimum TTL: 60–86400

7) CAA
- Source: DNS CAA at the domain
- ok if no CAA is present (optional) or at least one `issue`/`issuewild`
   directive exists. If present but malformed, it shows as fail.

8) MTA‑STS (mail transport security)
- Source: DNS TXT `_mta-sts.<domain>` and HTTPS policy at
   `https://mta-sts.<domain>/.well-known/mta-sts.txt`
- ok when the TXT indicates `v=STSv1` and the policy file is reachable and
   contains `version: STSv1` (HTTP 5s timeout).

9) TLS‑RPT (SMTP TLS reporting)
- Source: DNS TXT `_smtp._tls.<domain>`
- ok when the TXT contains `v=TLSRPTv1` and a `rua=` destination.

10) PTR for outbound (reverse DNS)
- Source: First resolved IP of the first MX host (best-effort)
- ok when a reverse PTR exists for that IP.

11) MX integrity
- Source: MX records at apex + A/AAAA resolution of each MX host
- ok when there is at least one MX and every MX host resolves to A or AAAA
   (≥2 MX is recommended but not enforced).

Report format quick reference
- Each domain line includes at the end: `H: NS:<ok|fail>; SOA:<ok|fail>;
   CAA:<ok|fail>; MTA:<ok|fail>; TLS:<ok|fail>; PTR:<ok|fail>`.
- SPF/DMARC/DKIM show `ok`, `needs-update`, or `error` details.
- In dry-run mode the report is annotated and no AutoDNS changes are made.

## Testing

Run all tests:
```bash
npm test
```

Run tests in watch mode:
```bash
npm run test:watch
```

Run tests with UI:
```bash
npm run test:ui
```

Run tests with coverage:
```bash
npm run test:coverage
```

### Test Structure

Tests are organized by module:
- `tests/utils/helpers.test.js`: Utility function tests
- `tests/lib/dmarc.test.js`: DMARC normalization tests
- `tests/lib/spf.test.js`: SPF parsing and flattening tests

Each test file validates the core functionality of its respective module without external dependencies.

## Configuration

All configuration is done through the `.env` file:

### AutoDNS API
- `AUTODNS_USER`: Your AutoDNS API username (required)
- `AUTODNS_PASSWORD`: Your AutoDNS API password (required)
- `AUTODNS_CONTEXT`: API context, usually 4 for production (default: 4)
- `AUTODNS_API_URL`: AutoDNS API endpoint (default: https://api.autodns.com/v1)

### Dry-Run Mode
- `DRY_RUN`: Set to `true` to generate reports without making changes (default: `false`)

### SPF Configuration
- `DIEBASIS_DE_SPF_RECORD_NAME`: Name of the SPF record to update (e.g., `_spf.diebasis.de`)
- `DIEBASIS_DE_SPF_RECORD_VALUE`: Expected SPF record value

### DMARC Configuration
- `EXPECTED_DMARC`: Expected DMARC policy (no spaces after semicolons for strict compliance)
- `DMARC_REPORT_AUTH_DOMAIN`: Domain under which to create external reporting authorization TXT records

### DKIM Configuration
- `DKIM_SELECTORS`: Comma-separated list of DKIM selectors to check (e.g., `s1,s2`)
- `DKIM_CONFIG_PATH`: Path to JSON file with desired DKIM records per domain (default: `dkim.config.json`)

### Email Configuration
- `SMTP_HOST`: SMTP server hostname
- `SMTP_PORT`: SMTP server port (e.g., 587)
- `SMTP_SECURE`: Use TLS/SSL (true/false)
- `SMTP_USER`: SMTP username
- `SMTP_PASSWORD`: SMTP password
- `EMAIL_FROM`: Sender email address
- `EMAIL_TO`: Recipient email address
- `EMAIL_SUBJECT`: Email subject line

## How It Works

### SPF Validation
- Queries SPF record for each domain
- Compares to expected value
- Updates if mismatch or missing
- Flattens includes to prevent lookup limit issues
- Guards against apex CNAME conflicts

### DMARC Validation
- Queries `_dmarc` TXT record
- Normalizes spacing for comparison
- Updates if policy mismatch or missing
- Creates external reporting authorization TXT in specified domain (e.g., `domainname._report._dmarc.diebasis.de`)

### DKIM Detection
- Checks DNS for configured selectors (e.g., `selector._domainkey.domain.com`)
- Falls back to zone enumeration to discover any `*._domainkey` TXT records
- Compares found selectors to desired config from `dkim.config.json`
- Creates or updates selectors as needed

### Email Reports
- Generates summary with counts (SPF/DMARC/DKIM)
- Includes full report content with timestamps and outcomes
- Sends as plain-text body (not attachment)
- Uses SMTP connection timeouts and verification to prevent hangs

### Report Files
- Stores reports in `reports/` directory
- Automatic cleanup keeps last 30 reports
- Includes SPF flattening logs

## Security Note

**Important**: Never commit your `.env` file to version control! The `.gitignore` file is configured to exclude it automatically.

## API Documentation

For more information about the AutoDNS API, visit:
https://help.internetx.com/display/APIXMLEN/Domain+API

## Troubleshooting

- **Authentication Error**: Verify AutoDNS credentials in `.env`
- **Update Failures**: Check that your AutoDNS account has zone management permissions
- **Email Not Sent**: Verify SMTP credentials and connection; check timeouts
- **DKIM Not Found**: Ensure selectors are correct or use zone enumeration fallback
- **SPF Update Conflict**: Check for apex CNAME records (incompatible with apex TXT)

## License

ISC
