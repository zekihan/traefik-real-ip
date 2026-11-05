# Publishing

Ordinary pull requests run native checks and builds. Container smoke checks and
release cross-compilation run only before publication, on the captured source commit.

Stable releases start from an existing signed `vX.Y.Z` tag whose commit belongs to
main and whose version matches `VERSION`. Prepare the version locally, update any
version adapters, run checks, commit and sign the tag. Push only when ready:

```sh
git push --atomic origin main vX.Y.Z
```

The tagged workflow validates the captured commit and creates its GitHub release.
This is a source release: no container or cross-compiled application binaries.
The public module path, Traefik plugin identity and `vX.Y.Z` tag interface are unchanged.

Publishing uses full-SHA pins to `zekihan/release-workflows`. Review pin updates;
the shared workflow embeds its helpers rather than fetching executable scripts from
a moving branch. Repo-specific build commands run without publication credentials.

Registry updates are not atomic. If publication stops partway, use **Re-run failed
jobs** within seven days to reuse the prepared artifacts. Re-running every job can
produce different bytes and correctly fail the immutability check. Never retag or
overwrite an existing release to recover. After artifact expiry, use a new version
if the original content cannot be recovered.

`make release` prepares local assets only. Publication uses the tagged workflow.
