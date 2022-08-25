#
# Copyright 2019-2022 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
#

# Use the current rust environment for building.
FROM rust:1.58.1-buster AS build-stage
RUN apt-get update \
    && apt-get install -y --no-install-recommends --no-install-suggests protobuf-compiler

# Take in a build argument to specify RUSTFLAGS environment, usually a target-cpu.
ARG rust_flags
ENV RUSTFLAGS=$rust_flags

WORKDIR /usr/src/calling-service

# Create a stub version of the project to cache dependencies.
RUN cargo new common
RUN cargo new backend

COPY Cargo.toml Cargo.lock rust-toolchain ./
COPY common/Cargo.toml ./common/
COPY backend/Cargo.toml ./backend/

# Do the initial stub build.
RUN cargo build --bin calling_backend --release

# Copy the source and build the project normally.
COPY . .
RUN cargo build --bin calling_backend --release

# Export the calling_backend executable if the '-o' option is specified.
FROM scratch AS export-stage

COPY --from=build-stage /usr/src/calling-service/target/release/calling_backend calling_backend

# Create a minimal container to deploy and run the calling_backend.
FROM debian:buster-slim AS run-stage

# Expose http and udp server access ports to this container.
EXPOSE 8080
EXPOSE 10000/udp

COPY --from=build-stage /usr/src/calling-service/target/release/calling_backend .
USER 1000

ENTRYPOINT ["./calling_backend"]
