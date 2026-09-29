# Build on the MSRV. Alpine's Rust targets musl and links statically, so the
# binary runs with no libc in the final image.
FROM rust:1.98-alpine AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

# Nothing but the binary: no shell, no libc, no package manager.
FROM scratch
COPY --from=build /src/target/release/mdns-alias /mdns-alias
USER 65532:65532
ENTRYPOINT ["/mdns-alias"]
