#
# Copyright 2019-2021 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
#

# Use the current rust environment for building.
FROM rust:1.58.1-buster AS build-stage
RUN apt-get update

WORKDIR /usr/src

# Create a stub version of the project to cache dependencies.
RUN USER=root cargo new calling-server
WORKDIR /usr/src/calling-server
COPY Cargo.toml Cargo.lock ./

# Take in a build argument to specify RUSTFLAGS environment, usually a target-cpu.
ARG rust_flags
ENV RUSTFLAGS=$rust_flags

# Do the initial stub build.
RUN cargo build --release

# Copy the source and build the calling-server proper.
COPY src ./src
COPY protobuf ./protobuf
COPY build.rs ./
RUN cargo build --release

# Export the calling-server executable if the '-o' option is specified.
FROM scratch AS export-stage

COPY --from=build-stage /usr/src/calling-server/target/release/calling_server calling_server

# Create a minimal container to deploy and run the calling-server.
FROM debian:buster-slim AS run-stage

# Expose http and udp server access ports to this container.
EXPOSE 8080
EXPOSE 10000/udp

COPY --from=build-stage /usr/src/calling-server/target/release/calling_server .
USER 1000

ENTRYPOINT ["./calling_server"]
