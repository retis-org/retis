FROM quay.io/centos/centos:stream9 as builder

WORKDIR /retis

RUN dnf config-manager --set-enabled crb
RUN dnf install -y \
    cargo \
    clang \
    elfutils-libelf-devel \
    git \
    jq \
    libpcap-devel \
    llvm \
    make \
    python3-devel \
    zlib-devel

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
    nftables \
    python3-scapy

COPY --from=builder /retis/target/release/retis /usr/bin/retis
COPY --from=builder /retis/retis/profiles /usr/share/retis/profiles

WORKDIR /data
ENTRYPOINT ["/usr/bin/retis"]
