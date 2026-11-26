FROM rust:1-trixie AS build
WORKDIR /build
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/release/basset /usr/local/bin/basset
USER 65532:65532
WORKDIR /data
ENTRYPOINT ["basset"]
CMD ["--help"]
