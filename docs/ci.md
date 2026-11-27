# Running dpdpward in CI

dpdpward is a single static binary with no network access. Every CI system runs it the same way:
1. Scan.
2. Keep the HTML report as an artefact.
3. Fail the job on new personal data (`--baseline`) or on findings at a severity you choose (`--fail-on`).

Create the baseline once on your main branch, commit it, and refresh it whenever you approve changes to the data map:

```bash
dpdpward baseline -o .dpdpward-baseline.json
```

Exit codes: `0` ok, `1` threshold exceeded or new personal data since the baseline, `2` error. Replace `vX.Y.Z` below with a released version, and pin the container by digest in production.

## GitHub Actions

Use the Action; see the [README](../README.md#github-action). It uploads SARIF to code scanning.

## GitLab CI

```yaml
dpdpward:
  image: ghcr.io/breaktroughf1/dpdpward:vX.Y.Z
  stage: test
  script:
    - dpdpward scan --dir . --baseline .dpdpward-baseline.json --fail-on high --format html -o dpdpward.html
  artifacts:
    when: always
    paths: [dpdpward.html]
    expire_in: 30 days
```

The image's entrypoint is `dpdpward`. If your runner needs a shell, add `entrypoint: [""]` under `image:` and call `dpdpward` explicitly as shown.

## Bitbucket Pipelines

```yaml
pipelines:
  pull-requests:
    '**':
      - step:
          name: dpdpward
          image: ghcr.io/breaktroughf1/dpdpward:vX.Y.Z
          script:
            - dpdpward scan --dir . --baseline .dpdpward-baseline.json --fail-on high --format html -o dpdpward.html
          artifacts:
            - dpdpward.html
```

## Jenkins (declarative)

```groovy
stage('dpdpward') {
  agent { docker { image 'ghcr.io/breaktroughf1/dpdpward:vX.Y.Z'; args '--entrypoint=' } }
  steps {
    sh 'dpdpward scan --dir . --baseline .dpdpward-baseline.json --fail-on high --format html -o dpdpward.html'
  }
  post { always { archiveArtifacts artifacts: 'dpdpward.html', allowEmptyArchive: true } }
}
```

## Azure DevOps

```yaml
- script: |
    go install github.com/Breaktroughf1/dpdpward/cmd/dpdpward@vX.Y.Z
    "$(go env GOPATH)/bin/dpdpward" scan --dir . --baseline .dpdpward-baseline.json --fail-on high --format html -o $(Build.ArtifactStagingDirectory)/dpdpward.html
  displayName: dpdpward
- publish: $(Build.ArtifactStagingDirectory)/dpdpward.html
  artifact: dpdpward
  condition: always()
```

## Evidence for audits

On release builds, keep the Rule 6 evidence record alongside the report:

```bash
dpdpward evidence -o dpdp-evidence.json
```
