# Changelog

## v0.1.0 — 2026-11-27

First release.

- **Data map:** personal data fields found in SQL DDL, Prisma, Django, SQLAlchemy/SQLModel, TypeORM, Mongoose, Rails, JPA/Hibernate (Java and Kotlin) and Go structs with persistence tags. Indian identifiers (Aadhaar, PAN, UPI, ABHA, GSTIN, IFSC, voter ID, driving licence), contact, financial, health, biometric and children's-data indicators.
- **Identifier values in files:** Aadhaar numbers (Verhoeff-valid), PANs, GSTINs (checksum-valid) and UPI IDs in code, fixtures, logs and config, always redacted in output.
- **dpdpward.yaml:** purposes, lawful basis, retention, processors, transfers, children's consent mechanism, safeguard attestations and reasoned ignores. Strict parsing: unknown keys are errors. `init` writes a starter file from the scan.
- **ROPA** (Markdown, CSV, JSON), **Rule 6 safeguards evidence** from Terraform (AWS, plus core GCP and Azure checks) and attestations, with a fail-safe status model (pass, partial, fail, unknown) and `evidence --check`.
- **Breach clock:** CERT-In 6-hour and DPDP Rules 2025 Rule 7 deadlines, with contacts and the personal data in scope.
- 15 rules; Markdown, JSON, SARIF and CSV output; stable fingerprints; `baseline` / `scan --baseline` to fail CI on new personal data.
- Composite GitHub Action; CI with race tests, an 80% coverage gate, fuzzing, a self-scan and launcher tests; signed reproducible releases with npm, PyPI, GHCR and Homebrew distribution.
