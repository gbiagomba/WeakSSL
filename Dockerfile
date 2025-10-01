# Lightweight builder image
FROM rust:1.80 as builder
WORKDIR /app
COPY Cargo.toml .
COPY src ./src
RUN cargo build --release

FROM debian:stable-slim
WORKDIR /app
RUN useradd -m appuser
COPY --from=builder /app/target/release/weakssl /usr/local/bin/weakssl
USER appuser
ENTRYPOINT ["weakssl"]

