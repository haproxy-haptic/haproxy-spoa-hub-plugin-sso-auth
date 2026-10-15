# Releasing

Every version tag publishes the plugin shared library for amd64, arm64, and
armv7 as a GitHub release alongside per-file `.sha256` sidecars, a combined
`SHA256SUMS`, and `.cosign.bundle` signatures.

## Prerequisites

- Permission to push tags to the repository.

## Release process

1. **Update `CHANGELOG.md`**: move items from `[Unreleased]` into a new
   `## [x.y.z]` section.

2. **Bump the version** in `Cargo.toml`.

3. **Commit and tag**:
   ```sh
   git add -A && git commit -m "release: v0.2.0"
   git tag v0.2.0
   git push origin main v0.2.0
   ```

4. **CI handles the rest**: `.github/workflows/release.yml`:
   - Cross-compiles for amd64, arm64, and armv7 with `cargo auditable`
     (binaries embed a compressed `Cargo.lock`-equivalent so SBOM tools can
     enumerate Rust deps without source access) and smoke-tests arm64 and armv7
   - Cosign keyless-signs every blob using the GitHub Actions OIDC token,
     producing `.cosign.bundle` files, and verifies each signature against the
     release workflow identity
   - Generates per-file `.sha256` sidecars and a combined `SHA256SUMS`
   - Creates a GitHub release with all artifacts attached

   To exercise build, signing, and verification without publishing, run the
   `release` workflow manually with `dry_run` enabled.

## Verifying a release

After CI finishes, verify the release end-to-end from a clean machine:

```sh
make verify-release VERSION=v0.2.0
```

This downloads `SHA256SUMS`, every artifact named in it, and every artifact's
cosign bundle from the GitHub release, then runs `sha256sum -c` and
`cosign verify-blob` against the project's tag identity. Tags released
before the move to GitHub verify against the GitLab CI identity.
