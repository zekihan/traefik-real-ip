# Workflow security (OPS-43)

Every external Action is pinned to its official upstream release commit with a
version comment. `.github/action-pins.json` records GitHub commit API tag resolutions
reviewed on 2026-10-27. Existing Action versions are preserved; the artifact handoff
adds upload-artifact v4.6.2 and download-artifact v4.3.0. Release identity verification
does not constitute a complete audit of all upstream source.

Renovate uses `helpers:pinGitHubActionDigests` with Action automerge disabled. Review upstream release changes and
commit identity, then update the manifest and human-readable comment together.
Policy regression tests prevent mutable references, inherited secrets, global write
tokens and persistent checkout credentials. PR validation has no private-module
credentials. The checks workflow is reusable and now gates source releases.

The scheduled updater fetches provider data in a read-only job. The writer consumes
the exact immutable artifact ID from that job, verifies SHA-256 checksums before
copying, and limits its PR to the two provider files. Checksums detect corruption;
they are not independent signatures against a compromised producer. The producer
runs the reviewed repository revision; no workflow consumes cross-run artifacts.

This is a source-only Traefik plugin (`builds.skip: true`), so releases have no binary
build outputs. The writer checks out the same event revision tested by the read-only
checks and runs GoReleaser with `--skip=before`; formatting/module hooks and integration
validation remain in the read-only job. GoReleaser is fixed at v2.19.0. Existing tag
and scheduled-update triggers are preserved.

Run locally:

```sh
python3 -m venv /tmp/traefik-policy
/tmp/traefik-policy/bin/pip install -r .github/scripts/requirements-policy.txt
/tmp/traefik-policy/bin/python -m unittest discover -s .github/scripts -p test_workflow_policy.py
/tmp/traefik-policy/bin/python .github/scripts/check_workflows.py
```

Local validation: 15 policy/fixture tests (including successful snapshot consumption
and tampered-file rejection), all three workflow policies, actionlint 1.7.7,
`make test` (unit and race suites), `golangci-lint run`, and `goreleaser check` passed.
