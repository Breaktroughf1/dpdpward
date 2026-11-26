# Legal basis and its limits

dpdpward is a technical aid, **not legal advice**. This page lists the provisions its rules refer to, as summarised from the Act, the Rules and public commentary. **Verify every reference against the official Gazette text** (egazette.gov.in) and with your counsel before relying on it.

| Topic | Source | What dpdpward does |
|---|---|---|
| Lawful processing: consent or legitimate use | DPDP Act ss.4, 6, 7 | Requires a `basis` per purpose (DP006), and the s.7 clause when relying on legitimate use |
| Erasure when the purpose is served | DPDP Act s.8(7) | Requires a `retention` per purpose (DP005) |
| Children's data: verifiable parental consent | DPDP Act s.9; Rules 2025 r.10 | Flags dates of birth and guardian fields without a recorded mechanism (DP004) |
| Reasonable security safeguards | DPDP Rules 2025 r.6(1)(a)–(g) | Rule 6 evidence model (DP008, DP009, DP010) |
| One-year retention of logs and personal data | DPDP Rules 2025 r.6(1)(e) | Fails Terraform log groups kept for less than 365 days (DP008) |
| Personal data breach intimation | DPDP Rules 2025 r.7: affected Data Principals and the Board without delay, detailed report to the Board within 72 hours | `breach` command |
| Cyber incident reporting | CERT-In Directions under s.70B(6) of the IT Act, 28 April 2022: within 6 hours of noticing | `breach` command |
| Transfers outside India | DPDP Act s.16 (restricted countries, if notified) | Notes declared transfers (DP014) |
| Aadhaar storage | Aadhaar Act and UIDAI regulations and circulars (Aadhaar Data Vault) | Flags Aadhaar columns (DP002) |
| Card security codes | PCI DSS; RBI directions on card data storage | Flags stored CVV or PIN (DP003) |

## Rule 6(1) as modelled

| Key | Clause | Safeguard |
|---|---|---|
| `encryption` | 6(1)(a) | Encryption, obfuscation, masking or virtual tokens mapped to the data |
| `access_control` | 6(1)(b) | Appropriate measures to control access to computer resources |
| `logging` | 6(1)(c) | Visibility of access through logs, monitoring and review |
| `backups` | 6(1)(d) | Continued processing after compromise, including backups |
| `log_retention` | 6(1)(e) | Logs and personal data retained for one year, unless another law requires otherwise |
| `processor_contracts` | 6(1)(f) | Safeguard provisions in contracts with Data Processors |
| `organisational` | 6(1)(g) | Technical and organisational measures to make the safeguards effective |

## Dates

Per the commencement notification of 13 November 2025:
- The Board-related provisions and Rules are in force.
- Consent Manager provisions apply from 13 November 2026.
- Notice, consent, safeguards (Rule 6), breach intimation (Rule 7), children's data and most duties apply from **13 May 2027**.

Some trackers give a different date for ss.9–10, and MeitY consulted on shortening the timeline. Check the current position before planning.

## What dpdpward cannot do

- It cannot decide whether a purpose is lawful, whether consent is valid, or whether a notice is adequate.
- It sees code and Terraform, not your data, your consent records or your contracts. Attestations in `dpdpward.yaml` are your statements; dpdpward only checks that the cited evidence exists.
- Field-name classification has false positives and false negatives. Review the data map, and record genuine exceptions in `ignore` with a reason.
