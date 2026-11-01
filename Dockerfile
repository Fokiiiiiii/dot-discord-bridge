# Native ARM64 build on the target Debian 12 host; official multi-arch Rust image.
FROM rust:1.99.1-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo test --locked && cargo build --release --locked

FROM debian:bookworm-slim
RUN groupadd --gid 10001 bridge && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin bridge \
    && mkdir /data && chown 10001:10001 /data && chmod 700 /data
COPY --from=build /build/target/release/discord-dot-bridge /usr/local/bin/discord-dot-bridge
USER 10001:10001
WORKDIR /data
ENV DATABASE_PATH=/data/discord-dm.sqlite3 PORT=8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD ["/usr/local/bin/discord-dot-bridge", "--healthcheck"]
ENTRYPOINT ["/bin/sh", "-c", "umask 077; exec /usr/local/bin/discord-dot-bridge"]
