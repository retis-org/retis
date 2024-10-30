FROM quay.io/centos/centos:stream9 as builder

WORKDIR /retis

RUN dnf install -y \
    libpcap-devel \ 
    clang \
    llvm \ 
    cargo \
    elfutils-libelf-devel \
    zlib-devel \
    make \
    jq \
    git \
    python3-devel

# Only the allowlisted files are copied,
# see .containerignore for more details.
COPY . .git /retis

# Build Retis
RUN make clean-ebpf && make CARGO_CMD_OPTS=--locked V=1 release -j$(nproc)

# Final image
FROM quay.io/centos/centos:stream9

LABEL org.opencontainers.image.authors="https://github.com/retis-org"

RUN dnf install -y \
    less \
    libpcap \
    nftables

COPY --from=builder /retis/target/release/retis /usr/bin/retis
COPY --from=builder /retis/retis/profiles /etc/retis/profiles

WORKDIR /data
ENTRYPOINT ["/usr/bin/retis", "--kconf", "/kconfig"]
