# Evidence record (v1)

`dpdpward evidence -o dpdp-evidence.json` writes a JSON record for audits and for CI artefacts:

```json
{
  "schema": "https://github.com/Breaktroughf1/dpdpward/blob/main/docs/evidence.md#v1",
  "tool": "dpdpward v0.1.0",
  "generated_at": "2027-05-01T09:00:00Z",
  "git_commit": "…",
  "organisation": "Example Pvt Ltd",
  "safeguards": [
    { "key": "encryption", "clause": "6(1)(a)", "status": "fail",
      "evidence": [], "iac_checks": [ { "status": "fail", "resource": "aws_db_instance.app", "file": "infra/main.tf", "line": 1, "detail": "storage_encrypted is not true…" } ] }
  ],
  "data_map": { "fields": 21, "stores": 6, "fields_high": 7, "identifier_values_in_files": 0 },
  "findings_by_severity": { "critical": 1, "high": 5 },
  "purposes": 2,
  "stores_without_purpose": ["audit_log", "saved_cards", "students"],
  "disclaimer": "…"
}
```

- `status` is one of `pass`, `partial`, `fail` or `unknown`; see the fail-safe rules in [config.md](config.md).
- `--check` exits 1 unless every safeguard is `pass`.
- Attach the record to each release, or archive it with your compliance evidence. It is deterministic for a given commit, apart from `generated_at`.
