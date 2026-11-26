# dpdpward

[![ci](https://github.com/Breaktroughf1/dpdpward/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Breaktroughf1/dpdpward/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Map personal data in your code for India's DPDP Act, and keep the map true in CI.**

The DPDP Act, 2023 and the DPDP Rules, 2025 are fully in force from **13 May 2027**: notice, consent, erasure, Rule 6 security safeguards and Rule 7 breach intimation. The first question any of these raises is *where is the personal data, and why do we hold it?* dpdpward answers it from the code you already have:

- **Data map:** finds personal data fields across SQL DDL, Prisma, Django, SQLAlchemy, TypeORM, Mongoose, Rails, JPA/Hibernate and Go structs. It has an Indian focus: Aadhaar, PAN, UPI, ABHA, GSTIN, IFSC, voter ID, plus children's-data indicators.
- **Record of Processing Activities (ROPA):** joins that map with the purposes, lawful basis, retention and processors you declare in `dpdpward.yaml`.
- **Rule 6 safeguards evidence:** reads Terraform for encryption at rest, public exposure, audit logging, backups and one-year log retention, and combines it with your attested evidence into a machine-checkable record.
- **Breach clocks:** prints the CERT-In 6-hour and Rule 7 72-hour deadlines from the moment you became aware, scoped to the data your code holds.
- **CI gate:** fails a pull request that adds personal data no purpose covers.

It reads source files only: no database connections, no network calls, no data values from production. **Not legal advice.**

```text
$ dpdpward scan --dir .
**Personal data:** 21 fields in 6 stores (7 high-sensitivity) · 0 identifier values in files
**Findings:** 1 critical · 5 high · 6 medium · 2 low · 0 info
- CRITICAL DP003 — src/payments/card.entity.ts:12: saved_cards.cvv appears to store a card CVV or PIN …
- HIGH DP001 — prisma/schema.prisma:4: students holds personal data (Person's name, Date of birth / age, Parent / guardian details) but no purpose in dpdpward.yaml covers it …
- HIGH DP002 — db/schema.sql:8: customers.aadhaar_number appears to store Aadhaar numbers …
```

## Install

| Channel | Command |
|---|---|
| Go | `go install github.com/Breaktroughf1/dpdpward/cmd/dpdpward@latest` |
| npm | `npx dpdpward scan` |
| PyPI | `uvx dpdpward scan` or `pipx install dpdpward` |
| Homebrew | `brew install breaktroughf1/tap/dpdpward` |
| Container | `docker run --rm -v "$PWD:/src:ro" ghcr.io/breaktroughf1/dpdpward scan --dir /src` |
| GitHub Action | see [below](#github-action) |

npm, PyPI, Homebrew and the container are published from the first tagged release. Release archives are built reproducibly, `checksums.txt` is signed keylessly with Sigstore, and SLSA provenance is attached. The npm and PyPI packages contain no binary: they download the archive for your platform and refuse it unless its SHA-256 matches the value pinned from the verified checksums.

## Quick start

```bash
dpdpward init            # writes dpdpward.yaml listing every store that holds personal data
$EDITOR dpdpward.yaml    # split stores into purposes; add basis, retention, processors, evidence
dpdpward scan            # data map, Rule 6 safeguards, findings
dpdpward ropa > ROPA.md  # Record of Processing Activities (also --format csv|json)
dpdpward evidence -o dpdp-evidence.json --check   # exit 1 until every safeguard is attested
dpdpward breach --aware now                        # notification deadlines, if it ever comes to that
```

Try it on the fictional demo app: `make demo`.

## Commands

| Command | What it does |
|---|---|
| `scan` | Data map, identifier values in files, Rule 6 safeguards, 15 rules; `md`, `json`, `sarif`, `csv` |
| `init` | Starter `dpdpward.yaml` with every store that holds personal data |
| `ropa` | Record of Processing Activities (`md`, `csv`, `json`) |
| `evidence` | Machine-checkable Rule 6 evidence record; `--check` exits 1 unless every safeguard is attested |
| `breach --aware TIME` | CERT-In and Rule 7 deadlines, contacts, and the personal data in scope |
| `baseline` / `scan --baseline` | Approve today's data map; fail CI on *new* personal data or findings |

Exit codes: `0` ok, `1` threshold exceeded or new personal data since the baseline, `2` error.

## GitHub Action

```yaml
permissions:
  contents: read
  actions: read
  security-events: write
steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
    with: { persist-credentials: false }
  - uses: Breaktroughf1/dpdpward@<full-commit-sha>   # pin to a release commit
    with:
      fail-on: high
      baseline: .github/dpdpward-baseline.json
```

## How it stays honest

- **Fails safe.** A Rule 6 safeguard is reported **PASS** only with attested evidence that exists. Terraform settings alone make it **PARTIAL**. Anything undecided is **UNKNOWN**, never met.
- **Precision for identifier values.** An Aadhaar number must pass the Verhoeff check, a GSTIN its check character, and a UPI ID must use a known payment handle. Values are always redacted in output.
- **Strict config.** A misspelt key in `dpdpward.yaml` is an error, so a declaration is never silently dropped. An `ignore` entry needs a reason, or it is not applied.
- **No production access.** dpdpward never connects to databases and never sends data anywhere.

## How it relates to other tools

- **dpdp-kit** (Node) and **dpdpkit** (Python): consent and rights SDKs you build into an application. dpdpward does not compete with them. It maps the personal data you already hold, in any stack, and evidences safeguards.
- **PII scanners** (Presidio-based tools, piicatcher, data catalogues): general PII discovery in data. dpdpward works on code and infrastructure, and adds DPDP-specific outputs: ROPA, Rule 6 evidence, breach clocks.

## Documentation

- [Legal basis and its limits](docs/legal-basis.md)
- [Configuration (`dpdpward.yaml`)](docs/config.md)
- [Rules](docs/rules.md)
- [Evidence record](docs/evidence.md)

## Licence

Apache-2.0. dpdpward is a technical aid, not legal advice. It cannot decide whether processing is lawful; verify obligations against the official Gazette text and with your counsel.
