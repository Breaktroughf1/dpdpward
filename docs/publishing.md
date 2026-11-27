# Publishing setup (one time)

Release v0.1.0 and later publish to npm, PyPI, GHCR and Homebrew without any stored token. Each registry trusts this repository's workflows through OIDC instead. Do these steps once, before pushing the v0.1.0 tag.

## 1. GitHub environments (Settings → Environments)

Create two environments, **`npm`** and **`pypi`**:
- Add yourself as a **required reviewer**.
- Under deployment branches and tags, choose **Selected branches and tags** and add the rule `main`. The workflow runs on `main` via `workflow_run`.

A publishing job should wait for a person, so give these environments required reviewers. Wardmap's WM007 flags environments without them.

## 2. npm trusted publisher (npmjs.com)

The package name `dpdpward` is free on npm. Configure trusted publishing on npmjs.com the same way as for `lockward`:
- Organization or user: `Breaktroughf1`
- Repository: `dpdpward`
- Workflow filename: `packages.yml`
- Environment: `npm`

If npm only lets you add a trusted publisher to a package that already exists, do the first publish by hand:
1. Run Actions → packages → Run workflow, with tag `v0.1.0` and publish unticked.
2. Download the `packages` artifact.
3. Run `npm publish dpdpward-0.1.0.tgz --access public` once.
4. Add the trusted publisher.

## 3. PyPI pending publisher (pypi.org → Your projects → Publishing)

Add a **pending publisher**:
- PyPI project name: `dpdpward`
- Owner: `Breaktroughf1`
- Repository: `dpdpward`
- Workflow name: `packages.yml`
- Environment name: `pypi`

## 4. Homebrew tap

`Breaktroughf1/homebrew-tap` builds the `dpdpward` formula from the Sigstore-verified checksums. It checks every three hours, or you can run its **update** workflow by hand.

## 5. After the first container push

On GitHub, open the organisation's Packages page → `dpdpward`, then **Package settings**:
- Set the visibility to **Public**. New GHCR packages start private.
- Under **Manage Actions access**, confirm that `Breaktroughf1/dpdpward` has write access.

## Then release

```bash
git pull && git tag -a v0.1.0 origin/main -m "dpdpward v0.1.0" && git push origin v0.1.0
```

`release` builds and signs. When it succeeds, `packages` (npm and PyPI, held for your approval in the environments) and `container` (GHCR) start automatically.

After the release: enable private vulnerability reporting (Settings → Security), set the repository topics, and replace `<full-commit-sha>` in the README Action snippet with `git rev-list -n1 v0.1.0`.
