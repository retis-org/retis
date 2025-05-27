# Installation

Retis can be installed from a container image,
[COPR](https://copr.fedorainfracloud.org/coprs/g/retis/retis/) for
rpm-compatible distributions, or from sources.

### Fedora

Starting with Fedora 43, Retis is available as an official package.

```none
$ dnf -y install retis
$ retis --help
```

### Container image

We provide a script to run Retis in a container,
[retis_in_container.sh](https://raw.githubusercontent.com/retis-org/retis/main/tools/retis_in_container.sh).
The current directory is mounted with read-write permissions to the container
working directory. This allows Retis to read and write files (eg. events, pcap).
Both the Podman and Docker runtimes are supported (which is auto-detected by the
above script).

```none
$ curl -O https://raw.githubusercontent.com/retis-org/retis/main/tools/retis_in_container.sh
$ chmod +x retis_in_container.sh
$ ./retis_in_container.sh --help
```

By default the above script uses the latest stable version of Retis. An
environment variable, `RETIS_TAG`, can be used to set a specific version.
Available tags can be seen on [quay.io](https://quay.io/repository/retis/retis?tab=tags).

In addition a special tag, `next`, points to the latest daily build of the
[main](https://github.com/retis-org/retis/tree/main) branch. Using this tag
comes with a tradeoff: it allows access to the latest features but might not be
fully functional.

```none
$ RETIS_TAG=next ./retis_in_container.sh --help
```

For those operating in a disconnected environment, an environment variable `RETIS_IMAGE` can be
used to point to an alternate image location.

```none
$ RETIS_IMAGE=my-registry.example.com/retis ./retis_in_container.sh --help
```

`PAGER` and `NOPAGER` environment variables work the same way as with the Retis binary.

### COPR

RPM packages for Fedora (currently supported releases including Rawhide), RHEL (>=
8) and EPEL (>= 8) are available.

```none
$ dnf -y copr enable @retis/retis
$ dnf -y install retis
$ retis --help
```

Or on older distributions,

```none
$ yum -y copr enable @retis/retis
$ yum -y install retis
$ retis --help
```

### From sources

Retis depends on the following (in addition to Git and Cargo):

- rust >= 2021
- clang
- jq
- libelf
- libpcap
- llvm
- make
- pkg-config

If the `python` feature is used (which is by default), the Python3 shared
libraries and headers must be available.

On Fedora, one can run:

```none
$ dnf -y install git cargo clang elfutils-libelf-devel python3-devel \
        jq libpcap-devel llvm make pkgconf-pkg-config
```

On Ubuntu:

```none
$ apt update
$ apt -y install git cargo clang jq libelf-dev libpcap-dev python3-dev \
        llvm make pkg-config
```

Then, to download and build Retis:

```none
$ git clone --depth 1 https://github.com/retis-org/retis; cd retis
$ make release
$ ./target/release/retis --help
```

Finally, profiles should be installed in either `/usr/share/retis/profiles` or
`$HOME/.config/retis/profiles`.

```none
$ mkdir -p /usr/share/retis/profiles
$ cp retis/profiles/* /usr/share/retis/profiles
```

#### Cross-compilation

Retis can be cross-compiled and is currently supported on x86, x86-64 and
aarch64. The target is defined using the `CARGO_BUILD_TARGET` environment
variable, which is documented in the
[Rust reference](https://doc.rust-lang.org/cargo/reference/config.html#buildtarget).

When python support is built (it is enabled by default), `PYO3_CROSS_LIB_DIR=`
needs to be set to the directory containing the target's libpython dynamic
shared object. To disable Python support, use
`CARGO_CMD_OPTS=--no-default-features`.

```none
$ CARGO_BUILD_TARGET=aarch64-unknown-linux-gnu \
      PYO3_CROSS_LIB_DIR=sysroot/usr/lib/python3.14 \
      make release
$ file ./target/aarch64-unknown-linux-gnu/release/retis
[...] ARM aarch64, [...]
```

### Running as non-root

Retis can run as non-root if it has the right capabilities. Note that doing this
alone often means `tracefs` won't be available as it's usually owned by `root`
only and Retis won't be able to fully filter probes.

```none
$ sudo setcap cap_sys_admin,cap_bpf,cap_syslog=ep $(which retis)
$ retis collect
```

### Shell auto-completion

Retis can generate completion files for shells (Bash, Zsh, Fish...).
For example to enable auto-completion of Retis command in Bash, you can
add line `source <(retis sh-complete --shell bash)` in .bashrc, then
the command parameter could be auto-completed when pressing <Tab>.
