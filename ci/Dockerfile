# Image CI: CLI `appsec` + Semgrep + Gitleaks + Trivy (versi di-pin, checksum diverifikasi).
# Build dari root repo:  docker build -f ci/Dockerfile -t appsec-scanner .
FROM rust:1-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends cmake && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
# CLI tidak butuh shell Tauri (GTK/WebKit).
RUN sed -i 's#, "src-tauri"##' Cargo.toml && cargo build --release -p appsec-cli

FROM python:3.12-slim
ARG SEMGREP=1.183.0
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir semgrep==${SEMGREP} \
    && git config --system --add safe.directory '*'
COPY scripts/fetch-sidecars.sh /tmp/
RUN SIDECAR_DIR=/usr/local/bin /tmp/fetch-sidecars.sh && rm /tmp/fetch-sidecars.sh
COPY --from=build /src/target/release/appsec /usr/local/bin/appsec
# Jangan jalan sebagai root.
RUN useradd --create-home --uid 10001 scanner
USER scanner
CMD ["appsec", "--help"]
