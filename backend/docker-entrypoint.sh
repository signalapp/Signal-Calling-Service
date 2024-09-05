#!/bin/bash

#
#
# Copyright 2022 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
#
#

CERT_PATH="/etc/calling_server/cert.pem"
PKEY_PATH="/etc/calling_server/pkey.pem"

TOKEN="$(curl -Ss "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google" | jq '.access_token')"

curl -Ss "https://secretmanager.googleapis.com/v1/projects/$SECRET_PROJECT/secrets/$CERT_NAME/versions/latest:access" -H "Metadata-Flavor: Google" -H "authorization: Bearer $TOKEN" | jq -r '.payload.data' | base64 --decode > $CERT_PATH
curl -Ss "https://secretmanager.googleapis.com/v1/projects/$SECRET_PROJECT/secrets/$PRIVATE_KEY_NAME/versions/latest:access" -H "Metadata-Flavor: Google" -H "authorization: Bearer $TOKEN" | jq -r '.payload.data' | base64 --decode > $PKEY_PATH


if [[ -z "${EXTERNAL_IP}" ]]; then
  EXTERNAL_IP="$(curl -Ss "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip" -H "Metadata-Flavor: Google")"
  if [[ -z "${EXTERNAL_IP}" ]]; then
    echo "Error: EXTERNAL_IP not defined!"
    exit 1
  fi
fi

if [[ -z "${EXTERNAL_IPV6}" ]]; then
  EXTERNAL_IPV6="$(curl -f -Ss "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/ipv6s" -H "Metadata-Flavor: Google")"
fi
if [[ -z "${EXTERNAL_IPV6}" ]]; then
  IPV6_ICE=()
else
  IPV6_ICE=(--ice-candidate-ip "$EXTERNAL_IPV6")
fi

if [[ -z "${INTERNAL_IP}" ]]; then
  INTERNAL_IP="$(curl -Ss "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/ip" -H "Metadata-Flavor: Google")"
  if [[ -z "${INTERNAL_IP}" ]]; then
    echo "Error: INTERNAL_IP not defined!"
    exit 1
  fi
fi

calling_backend \
  --ice-candidate-ip "$EXTERNAL_IP" \
  "${IPV6_ICE[@]}" \
  --signaling-ip "$INTERNAL_IP" \
  --certificate-file-path "$CERT_PATH" \
  --key-file-path "$PKEY_PATH" \
  "$@"
