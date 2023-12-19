FROM quay.io/centos/centos:stream9 as builder

WORKDIR /retis

RUN dnf install -y \
    libpcap-devel \ 
    clang \
    llvm \ 
    rustfmt \
    cargo \
    elfutils-libelf-devel \
    zlib-devel 

RUN cargo install rustfmt
RUN cargo init

# Only download the dependencies for now so these steps can be cached.
COPY retis-derive retis-derive
# `cargo -C <path>` is unstable for now.
RUN cd retis-derive && cargo fetch --locked
COPY Cargo.lock .
COPY Cargo.toml .
RUN cargo fetch --locked

# Now copy the rest of the source and build.
COPY build.rs .
COPY src src
COPY profiles profiles
RUN cargo build --release

# Final image
FROM quay.io/centos/centos:stream9

LABEL org.opencontainers.image.authors="https://github.com/retis-org"

RUN dnf install -y \
    less \
    libpcap \
    nftables

COPY --from=builder /retis/target/release/retis /usr/bin/retis
COPY --from=builder /retis/profiles /etc/retis/profiles

WORKDIR /data
ENTRYPOINT ["/usr/bin/retis", "--kconf", "/kconfig"]
