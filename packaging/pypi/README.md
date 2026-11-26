# dpdpward (PyPI)

Runs [dpdpward](https://github.com/Breaktroughf1/dpdpward), which maps personal data across a codebase for India's DPDP Act, 2023: where it lives, which purpose covers it, and whether the DPDP Rules, 2025 Rule 6 safeguards are evidenced. Not legal advice.

```sh
uvx dpdpward init
uvx dpdpward scan
uvx dpdpward ropa
```

or `pipx install dpdpward` / `pip install dpdpward`.

This package contains no binary and runs nothing at install time. On first run it downloads the dpdpward release archive for your platform from GitHub, checks it against the SHA-256 baked into this package (copied from the release's Sigstore-verified `checksums.txt` when the package was built in CI, and published to PyPI with trusted publishing and attestations), extracts only the `dpdpward` binary into your user cache, and re-checks the binary's hash on every run. A mismatch stops it before anything runs.

The package version matches the dpdpward version it installs. Exit codes are dpdpward's: 0 ok, 1 threshold exceeded or new personal data since the baseline, 2 error (including a failed download or checksum mismatch). Other ways to install: Homebrew (`brew install breaktroughf1/tap/dpdpward`), `go install`, the GitHub Action, the container image and signed release downloads; see the [README](https://github.com/Breaktroughf1/dpdpward#install).
