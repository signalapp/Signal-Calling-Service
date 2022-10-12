#!/bin/bash

#
#
# Copyright 2022 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
#
#

if [[ -z "${EXTERNAL_IP}" ]]; then
  EXTERNAL_IP="$(curl -Ss "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip" -H "Metadata-Flavor: Google")"
  if [[ -z "${EXTERNAL_IP}" ]]; then
    echo "Error: EXTERNAL_IP not defined!"
    exit 1
  fi
fi

if [[ -z "${INTERNAL_IP}" ]]; then
  INTERNAL_IP="$(curl -Ss "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/ip" -H "Metadata-Flavor: Google")"
  if [[ -z "${INTERNAL_IP}" ]]; then
    echo "Error: INTERNAL_IP not defined!"
    exit 1
  fi
fi

set -- calling_backend \
  --ice-candidate-ip "$EXTERNAL_IP" \
  --signaling-ip "$INTERNAL_IP" \
  "$@"

"$@"
