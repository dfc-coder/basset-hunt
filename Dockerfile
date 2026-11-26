FROM rust:1.100.0-trixie AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/release/basset /usr/local/bin/basset
USER 65532:65532
WORKDIR /data
ENTRYPOINT ["basset"]
CMD ["--help"]
