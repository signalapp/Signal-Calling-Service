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

# Install Rust.
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /usr/src/bootstrap

COPY . .

RUN cargo build

ENTRYPOINT ["/usr/src/bootstrap/target/debug/bootstrap"]
