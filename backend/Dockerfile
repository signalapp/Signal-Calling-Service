#
# Copyright 2019-2022 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
#

ARG debian_ver=bullseye

FROM debian:${debian_ver} AS build-stage

# Update system packages.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends --no-install-suggests curl build-essential ca-certificates protobuf-compiler \
    && update-ca-certificates

# Install Rust.
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Take in a build argument to specify RUSTFLAGS environment, usually a target-cpu.
ARG rust_flags
ENV RUSTFLAGS=$rust_flags

WORKDIR /usr/src/calling-service

# Create a stub version of the project to cache dependencies.
RUN cargo new common
RUN cargo new backend
RUN cargo new frontend

COPY Cargo.toml Cargo.lock rust-toolchain ./
COPY common/Cargo.toml ./common/
COPY backend/Cargo.toml ./backend/

# Do the initial stub build.
RUN cargo build --bin calling_backend --release

# Copy the source and build the project normally.
COPY . .
RUN cargo build --bin calling_backend --release

# Create a minimal container to deploy and run the calling backend.
FROM debian:${debian_ver}-slim AS run-stage

# Update system packages.
RUN apt-get update \
    && apt-get upgrade -y \
    # Install curl for ip detection.
    && apt-get install -y --no-install-recommends --no-install-suggests curl \
    # Install jq for parsing gcp metadata.
    && apt-get install -y --no-install-recommends --no-install-suggests jq \
    # Cleanup unnecessary stuff.
    && rm -rf /var/lib/apt/lists/*

COPY --from=build-stage /usr/src/calling-service/target/release/calling_backend /usr/local/bin/
COPY backend/docker-entrypoint.sh /usr/local/bin/

USER nobody:nogroup

# Expose http and udp server access ports to this container.
EXPOSE 8080
EXPOSE 10000/udp

ENTRYPOINT ["docker-entrypoint.sh"]
