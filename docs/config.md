# dpdpward.yaml

`dpdpward init` writes a starter file. Unknown keys are errors, so a misspelt key never silently drops a declaration.

```yaml
version: 1

organisation:
  name: Example Pvt Ltd
  grievance_contact: grievance@example.in   # DP015 when empty
  dpo: dpo@example.in                       # Significant Data Fiduciaries
  cert_in_contact: security@example.in      # DP015 when empty
  consent_records: user_consents            # store name/glob, or an external system (DP016)
  significant_data_fiduciary: false         # if notified under s.10 (DP017)

exclude: ["test/fixtures/**"]               # paths not scanned (synthetic test data)

purposes:
  - id: accounts
    description: Create and manage customer accounts
    basis: consent                          # consent | legitimate-use
    legitimate_use: ""                      # the s.7 clause, required with legitimate-use
    data_principals: [customers]
    stores: [users, "user_*"]               # store names or globs (case-insensitive)
    retention: "3 years after account closure"
    processors: ["AWS ap-south-1 (hosting)"]
    transfers_outside_india: []             # countries
    children: false

children:
  verifiable_consent: true                  # s.9
  mechanism: "Parent confirms via DigiLocker age token before account creation"

safeguards:                                 # Rule 6(1); evidence = repo paths or https URLs
  encryption: { evidence: [docs/security/encryption.md] }
  access_control: { evidence: [docs/security/access.md] }
  logging: { evidence: [] }
  backups: { evidence: [] }
  log_retention: { evidence: [] }
  processor_contracts: { evidence: [docs/dpa/] }
  organisational: { evidence: ["https://intranet.example.in/isms"], notes: "ISO 27001 certified" }

sdf:                                        # only for Significant Data Fiduciaries (s.10)
  dpia: { evidence: [docs/dpia-2027.pdf] }
  audit: { evidence: ["https://auditor.example.in/report-2027"] }

ignore:
  - { store: audit_log, field: actor_email, reason: "staff work e-mail, covered by the HR purpose" }
```

Rules that depend on the file:
- **Store mapping (DP001):** every store with personal data must match at least one purpose's `stores`.
- **Stale purposes (DP012):** a purpose whose `stores` match nothing in the code is reported.
- **Safeguard status:**
  - **pass:** attested evidence exists and no Terraform check fails;
  - **partial:** Terraform checks pass but there is no attestation;
  - **fail:** any Terraform check fails;
  - **unknown:** anything else.
- **Missing evidence (DP010):** evidence paths are checked for existence; a missing path is reported and does not count.
