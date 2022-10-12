#!/bin/bash

#
#
# Copyright 2022 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
#
#

if [[ -z "${REGION}" ]]; then
  ZONE="$(curl -Ss "http://metadata.google.internal/computeMetadata/v1/instance/zone" -H "Metadata-Flavor: Google")"
  REGION=$(echo "$ZONE" | awk -F/ '{ print $NF }' | awk -F- '{OFS="-"; NF--; print $0}')
  if [[ -z "${REGION}" ]]; then
    echo "Error: REGION not defined!"
    exit 1
  fi
fi

if [[ -z "${CALLING_AUTH_KEY}" ]]; then
  if [[ -z "${SECRET_PROJECT}" ]]; then
    echo "Error: SECRET_PROJECT not defined but needed to get calling-auth-key!"
    exit 1
  fi
  if [[ -z "${AUTH_SECRET_NAME}" ]]; then
    echo "Error: AUTH_SECRET_NAME not defined but needed to get calling-auth-key!"
    exit 1
  fi 
  TOKEN="$(curl -Ss "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google" | jq '.access_token')"
  CALLING_AUTH_KEY="$(curl -Ss "https://secretmanager.googleapis.com/v1/projects/$SECRET_PROJECT/secrets/$AUTH_SECRET_NAME/versions/latest:access" -H "Metadata-Flavor: Google" -H "authorization: Bearer $TOKEN" | jq -r '.payload.data' | base64 --decode)"

  if [[ -z "${CALLING_AUTH_KEY}" ]]; then
    echo "Error: CALLING_AUTH_KEY not defined!"
    exit 1
  fi
fi

set -- calling_frontend \
  --region "$REGION" \
  --authentication-key "$CALLING_AUTH_KEY" \
  "$@"

"$@"
