# syntax=docker/dockerfile:1
FROM rust:1.98.1-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo build --release --locked

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 middles \
    && useradd --uid 10001 --gid middles --no-create-home --shell /usr/sbin/nologin middles \
    && install -d -o middles -g middles /var/lib/middles /etc/middles
COPY --from=build /build/target/release/middles /usr/local/bin/middles
COPY middles.docker.toml /etc/middles/middles.toml
USER 10001:10001
EXPOSE 6280
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["curl", "--fail", "--silent", "--show-error", "--max-time", "2", "http://127.0.0.1:6280/healthz"]
ENTRYPOINT ["/usr/local/bin/middles"]
CMD ["--config", "/etc/middles/middles.toml"]
