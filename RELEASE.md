# Releasing

1. Release a new version on GitHub:
   1. Make sure the docs and README are up-to-date (collectors, build
      instructions, etc).
   1. Add new authors to the authors file if needed, by running
      `./tools/authors.sh` and committing the changes.
   1. Tag the right commit in the `vx.y.z` form and push it.
1. Write and publish release notes in the GitHub interface:
   1. Make sure "Set as the latest release" is checked only for y-stream
      releases and z-stream releases of the latest major version.
   1. The milestone and `git log --merges <last x.y version>..` can be used to
      find important changes.

## Binary distributions

1. Build and publish on COPR:
   1. Update the [COPR spec file](https://github.com/retis-org/copr).
   1. Trigger a build on [COPR](https://copr.fedorainfracloud.org/coprs/g/retis/retis/).
1. Build and upload the Python bindings:
   1. `podman run --rm --env MATURIN_PYPI_TOKEN=$(cat ~/.my_pypi_token)
       -v $(pwd):/io:z ghcr.io/pyo3/maturin publish -m retis-events/Cargo.toml
       -F python-lib`.

## After the release

1. Update the version in `Cargo.toml` and the name in `retis/Cargo.toml`.
