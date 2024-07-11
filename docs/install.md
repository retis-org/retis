# Installation

Retis can be installed from [COPR](https://copr.fedorainfracloud.org/coprs/atenart/retis/)
for rpm-compatible distributions, from a container image or from sources.

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

### Container image

The preferred method to run Retis in a container is by using the provided
[retis_in_container.sh](https://raw.githubusercontent.com/retis-org/retis/main/tools/retis_in_container.sh)
script,

```none
$ curl -O https://raw.githubusercontent.com/retis-org/retis/main/tools/retis_in_container.sh
$ chmod +x retis_in_container.sh
$ ./retis_in_container.sh --help
```

The Retis container can also be run manually,

```none
$ podman run --privileged --rm -it --pid=host \
      --cap-add SYS_ADMIN --cap-add BPF --cap-add SYSLOG \
      -v /sys/kernel/btf:/sys/kernel/btf:ro \
      -v /sys/kernel/debug:/sys/kernel/debug:ro \
      -v /boot/config-$(uname -r):/kconfig:ro \
      -v $(pwd):/data:rw \
      quay.io/retis/retis:latest --help
```

- Or using `docker` in place of `podman` in the above.

- When running on CoreOS, Fedora Silverblue and friends replace `-v
  /boot/config-$(uname -r):/kconfig:ro` with `-v /lib/modules/$(uname
  -r)/config:/kconfig:ro` in the above.

The `/data` container mount point is used to allow storing persistent data for
future use (e.g. logged events using the `-o` cli option).

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

On Fedora, one can run:

```none
$ dnf -y install git cargo clang elfutils-libelf-devel \
        jq libpcap-devel llvm make pkgconf-pkg-config
```

On Ubuntu:

```none
$ apt update
$ apt -y install git cargo clang jq libelf-dev libpcap-dev llvm make pkg-config
```

Then, to download and build Retis:

```none
$ git clone --depth 1 https://github.com/retis-org/retis; cd retis
$ make release
$ ./target/release/retis --help
```

Finally, profiles should be installed in either `/etc/retis/profiles` or
`$HOME/.config/retis/profiles`.

```none
$ mkdir -p /etc/retis/profiles
$ cp profiles/* /etc/retis/profiles
```

#### Cross-compilation

Retis can be cross-compiled and is currently supported on x86, x86-64 and
aarch64. The target is defined using the `CARGO_BUILD_TARGET` environment
variable, which is documented in the
[Rust reference](https://doc.rust-lang.org/cargo/reference/config.html#buildtarget).

```none
$ CARGO_BUILD_TARGET=aarch64-unknown-linux-gnu make release
$ file ./target/aarch64-unknown-linux-gnu/release/retis
[...] ARM aarch64, [...]
```

### Running as non-root

Retis can run as non-root if it has the right capabilities. Note that doing this
alone often means `debugfs` won't be available as it's usually owned by `root`
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
