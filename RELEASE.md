# Release checklist

1. Release a new version on GitHub.
   1. Make sure the README is up-to-date (collectors, build instructions, etc).
   1. Add new authors to the authors file if needed, by running
      `./tools/authors.sh` and committing the changes.
   1. Tag the right commit in the `vx.y.z` form and push it.
1. Write and publish a release notes in the GitHub interface. This must be done
   once the rpm and the image successfully built to allow pushing last minute
   build fixes.
   1. Make sure "Set as the latest release" is checked only for y-stream
      releases and z-stream releases of the latest major version.

## After the release

1. Update the version in `Cargo.toml` and the name in `retis/Cargo.toml`.
1. Build and upload the python bindings.
   1. `podman run --rm --env MATURIN_PYPI_TOKEN=$(cat ~/.my_pypi_token) -v $(pwd):/io:z ghcr.io/pyo3/maturin publish -m retis-events/Cargo.toml -F python-lib`
