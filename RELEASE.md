# Release checklist

1. Release a new version of `btf-rs` and/or sub-crates if needed.
1. Release a new version on GitHub.
   1. Make sure the README is up-to-date (collectors, build instructions, etc).
   1. Add new authors to the authors file if needed, by running
      `./tools/authors.sh` and committing the changes.
   1. Update the version in `Cargo.toml`, retis-events/Cargo.toml and
      retis-derive/Cargo.toml.
   1. Open a PR and get it merged. This must have runtime tests enabled!
   1. Tag the right commit in the `vx.y.z` form and push it.
1. Release binaries.
   1. Build a new set of packages on [copr](https://copr.fedorainfracloud.org/coprs/g/retis/retis/).
      1. Update the spec file in our [copr](https://github.com/retis-org/copr)
         repository.
      1. Make sure the right set of distributions is enabled for the group. If
         not that can be set in the project settings.
      1. `Packages > Rebuild`.
   1. Build and push the container image.
      1. Manually run the workflow [Build and push container image](https://github.com/retis-org/retis/actions/workflows/build_push_image.yaml)
         (in the Actions tab on the Retis Github page) selecting the branch and setting the
         `release_tags` with the space separated list of tags (i.e. release_tags="x.y.z latest").
   1. Build and upload the python bindings.
      1. `podman run --rm --env MATURIN_PYPI_TOKEN=$(cat ~/.my_pypi_token) -v $(pwd):/io:z ghcr.io/pyo3/maturin publish -m retis-events/Cargo.toml -F python-lib`
1. Write and publish a release notes in the GitHub interface. This must be done
   once the rpm and the image successfully built to allow pushing last minute
   build fixes.
