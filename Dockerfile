# Build on the MSRV. Alpine's Rust targets musl and links statically, so the
# binary runs with no libc in the final image. Pinned by digest, so a rebuild
# of the same commit gets the same toolchain; Dependabot moves the digest.
FROM rust:1.98-alpine@sha256:7cc1c22d77d9432f7fe012a70e6d3e555af54c2a6832700ed7d553f1769ae89f AS build
# cargo-auditable embeds the resolved dependency list in the binary, so
# scanners (cargo audit bin, syft, trivy) can read it out of a scratch image
# that has no Cargo.lock beside it.
RUN cargo install cargo-auditable@0.7.6 --locked
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo auditable build --release --locked

# Nothing but the binary: no shell, no libc, no package manager.
FROM scratch
COPY --from=build /src/target/release/mdns-alias /mdns-alias
USER 65532:65532
ENTRYPOINT ["/mdns-alias"]
