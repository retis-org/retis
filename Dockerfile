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

# Only download the dependencies for now so these steps can be cached.
RUN cargo init
COPY Cargo.lock .
COPY Cargo.toml .
RUN cargo fetch --locked

# Now copy the rest of the source and build.
COPY . .
RUN cargo install rustfmt
RUN cargo build --release

# Final image
FROM quay.io/centos/centos:stream9

LABEL org.opencontainers.image.authors="https://github.com/retis-org"

RUN dnf install -y \
    libpcap

COPY --from=builder /retis/target/release/retis /usr/bin/retis
ENTRYPOINT ["/usr/bin/retis"]
