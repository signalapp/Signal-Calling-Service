#
# Copyright 2022 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
#

# Use Debian stretch for now to ensure GLIBC < 2.28.
FROM debian:stretch-20220316 AS build-stage
RUN apt-get update \
    && apt-get install -y --no-install-recommends --no-install-suggests build-essential curl ca-certificates \
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
COPY frontend/Cargo.toml ./frontend/

# Do the initial stub build.
RUN cargo build --bin calling_frontend --release

# Copy the source and build the project normally.
COPY . .
RUN cargo build --bin calling_frontend --release

# Export the calling_frontend executable if the '-o' option is specified.
FROM scratch AS export-stage

COPY --from=build-stage /usr/src/calling-service/target/release/calling_frontend calling_frontend

# Create a minimal container to deploy and run the calling_frontend.
FROM debian:stretch-slim AS run-stage

RUN apt-get update \
    && apt-get install -y --no-install-recommends --no-install-suggests ca-certificates \
    && update-ca-certificates

# Expose http server access ports to this container.
EXPOSE 8090

COPY --from=build-stage /usr/src/calling-service/target/release/calling_frontend .
USER 1000

ENTRYPOINT ["./calling_frontend"]
