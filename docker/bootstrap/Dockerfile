#
# Copyright 2022 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
#

ARG debian_ver=bullseye

FROM debian:${debian_ver}

# Update system packages.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends --no-install-suggests curl build-essential ca-certificates \
    && update-ca-certificates

WORKDIR /usr/src/bootstrap

COPY rust-toolchain ./

# Install Rust.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain $(cat rust-toolchain)
ENV PATH="/root/.cargo/bin:${PATH}"

COPY . .

RUN cargo build

ENTRYPOINT ["/usr/src/bootstrap/target/debug/bootstrap"]
