# Release checklist

1. Release a new version of `retis-derive` and `btf-rs` if needed.
1. Release a new version on GitHub.
   1. Make sure the README is up-to-date (collectors, build instructions, etc).
   1. Update the version in `Cargo.toml`.
   1. Update the version name in `src/main.rs`.
   1. Run `cargo publish --dry-run` to check for any issue.
   1. Open a PR and get it merged. This must have runtime tests enabled!
   1. Tag the right commit in the `vx.y.z` form and push it.
   1. Write and publish a release notes in the GitHub interface.
1. Release on [crates.io](https://crates.io): `cargo publish`.
1. Release binaries.
   1. Build a new set of packages on [copr](https://copr.fedorainfracloud.org/coprs/g/retis/retis/).
      1. Update the spec file in our [copr](https://github.com/retis-org/copr)
         repository.
      1. Make sure the right set of distributions is enabled for the group. If
         not that can be set in the project settings.
      1. `Packages > Rebuild`.
   1. Build and push the container image.
      1. `$ buildah build -t quay.io/retis/retis:x.y.z`
      1. `$ buildah push quay.io/retis/retis:x.y.z`
      1. Manually tag on the web UI the image pushed with `latest`, if
         applicable.
