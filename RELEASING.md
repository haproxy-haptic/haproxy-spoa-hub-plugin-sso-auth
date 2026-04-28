# Releasing

Every version tag publishes the plugin shared library for amd64, arm64, and
armv7 to the GitLab Generic Package Registry alongside per-file `.sha256`
sidecars and `.cosign.bundle` signatures.

## Prerequisites

- Permission to push tags to the repository.
- **Generic packages "Reject duplicates" enabled** under
  Settings > Packages and Registries > Generic packages. Without this, a
  re-run of the release pipeline on the same tag silently overwrites the
  bytes uploaded earlier.

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

4. **CI handles the rest**:
   - Cross-compiles for amd64, arm64, and armv7 with `cargo auditable`
     (binaries embed a compressed `Cargo.lock`-equivalent so SBOM tools can
     enumerate Rust deps without source access)
   - Generates per-file `.sha256` sidecars and a combined `SHA256SUMS`
   - Cosign keyless-signs every blob using the GitLab OIDC id token,
     producing `.cosign.bundle` files
   - Uploads everything to the Generic Package Registry under
     `packages/generic/sso-auth/<tag>/`
   - Creates a GitLab release with all artifacts linked as release assets

## Verifying a release

After CI finishes, verify the release end-to-end from a clean machine:

```sh
make verify-release VERSION=v0.2.0
```

This downloads `SHA256SUMS`, every artifact named in it, and every artifact's
cosign bundle from the package registry, then runs `sha256sum -c` and
`cosign verify-blob` against the project's tag identity.
