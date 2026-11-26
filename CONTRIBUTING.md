# Contributing

Ground rules:

1. **Read code only.** No database connections, no network calls, no execution of scanned code.
2. **Fail safe.** Nothing is reported as met without evidence.
3. **Never commit real identifiers.** Tests generate Aadhaar, GSTIN and UPI values at run time; dpdpward's own CI scans this repository for them.
4. **Every extractor or classifier change needs tests**, including negative cases (fields that must not be flagged).
5. **Legal references need a source.** Prefer the Gazette text, and keep the "not legal advice" framing.

```bash
make lint test fuzz
```

## Releasing

1. Add a `## vX.Y.Z — YYYY-MM-DD` section at the top of `CHANGELOG.md` and merge it.
2. A maintainer pushes the tag: `git tag -a vX.Y.Z -m "dpdpward vX.Y.Z" && git push origin vX.Y.Z`.

`release` builds and signs. When it succeeds, `packages` (npm and PyPI) and `container` (GHCR) follow. Before the first release, complete the one-time setup in [docs/publishing.md](docs/publishing.md).
