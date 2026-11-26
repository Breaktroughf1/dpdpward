# Rules

`dpdpward rules` prints this list. SARIF levels: critical and high → error, medium → warning, low and info → note.

| ID | Severity | Name | Meaning |
|---|---|---|---|
| <a id="dp001"></a>DP001 | high | personal-data-without-purpose | A store holds personal data, but no purpose in dpdpward.yaml covers it. |
| <a id="dp002"></a>DP002 | high | aadhaar-number-stored | An Aadhaar number column. Storage is restricted to permitted entities, using an Aadhaar Data Vault. |
| <a id="dp003"></a>DP003 | critical | card-security-code-stored | A CVV/CVC or PIN column. These must never be stored after authorisation. |
| <a id="dp004"></a>DP004 | medium | children-data-without-verifiable-consent | Date-of-birth or guardian fields, but no verifiable-consent mechanism recorded (s.9). |
| <a id="dp005"></a>DP005 | medium | purpose-without-retention | A purpose with no retention period (s.8(7)). |
| <a id="dp006"></a>DP006 | medium | purpose-without-lawful-basis | No basis, or legitimate use without the s.7 clause. |
| <a id="dp007"></a>DP007 | high/medium | identifier-value-in-repository | An Aadhaar (Verhoeff-valid), PAN, GSTIN (checksum-valid) or UPI ID in code, fixtures, logs or config. |
| <a id="dp008"></a>DP008 | high/medium | safeguard-failed | A Terraform setting contradicts Rule 6: unencrypted database or volume, public access, backups off, logs kept under a year. |
| <a id="dp009"></a>DP009 | medium/low | safeguard-unevidenced | A Rule 6 item with no evidence (medium), or with infrastructure evidence only (low). |
| <a id="dp010"></a>DP010 | medium | missing-evidence-file | An attestation cites a file that does not exist. |
| <a id="dp011"></a>DP011 | low | high-sensitivity-data | Health, biometric, ABHA, religion/caste or similar data is stored. |
| <a id="dp012"></a>DP012 | low | stale-purpose-record | A purpose lists stores that are not found in the code. |
| <a id="dp013"></a>DP013 | low | ignore-without-reason | An ignore entry without a reason (it is not applied). |
| <a id="dp014"></a>DP014 | info | cross-border-transfer | A purpose declares transfers outside India. |
| <a id="dp015"></a>DP015 | low | contact-missing | No grievance or CERT-In contact is recorded. |

Each finding has a stable fingerprint (`partialFingerprints["dpdpward/v1"]`), used by baselines and code scanning.
