#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# This shell script instantiates a MinIO instance using Docker and ensures it is
# healthy. This is intended for development and testing use only. 
set -eo pipefail

function die() {
  echo "$@"
  exit 1
}

# create_service_account is a function that creates a MinIO service account.
# While this is not used by default in the main script, it is here as a helper
# function should you want to automate that part of the process too.
function create_service_account() {
  command -v awk >/dev/null 2>&1 || die 'required 'awk' command not found, exiting.'

  echo 'Logging into MinIO instance...'
  login_payload=$(
    jq -crn \
    --arg accessKey "$minio_root_user" \
    --arg secretKey "$minio_root_pw" \
    '$ARGS.named'
  )

  token_header=$(curl -f \
    -d "$login_payload" \
    -H "Content-Type: application/json" \
    -w '%header{Set-Cookie}' \
    http://127.0.0.1:9090/api/v1/login)
  if [ -z "${token_header}" ]; then
    die 'empty token header on login response'
  fi

  # The token header comes in form of a cookie, including path, expiration, etc.
  # We only need the actual token here.
  token=$(echo "$token_header" | awk '{print $1}')
  token=${token::-1} # Each cookie property is delimited by a ';'. Remove it.
  echo 'Done!'

  echo 'Creating MinIO Service Account...'
  service_account_payload=$(
    jq -crn \
    --arg accessKey '' \
    --arg secretKey '' \
    '$ARGS.named'
  )

  service_account_json=$(curl -fs \
    -H "Content-Type: application/json" \
    -H "Cookie: $token" \
    -d "$service_account_payload" \
    http://127.0.0.1:9090/api/v1/service-account-credentials | jq -r)

  MINIO_ACCESS_KEY=$(echo "$service_account_json" | jq -r '.accessKey')
  if [ -z "${MINIO_ACCESS_KEY}" ]; then
    echo 'unable to create service account: empty access key from MinIO response.'
  fi

  MINIO_SECRET_KEY=$(echo "$service_account_json" | jq -r '.secretKey')
  if [ -z "${MINIO_SECRET_KEY}" ]; then
    echo 'unable to create service account: empty secret key from MinIO response.'
  fi
  echo 'Done!'
}

command -v docker >/dev/null 2>&1 || die 'required 'docker' command not found, exiting.'
command -v curl >/dev/null 2>&1 || die 'required 'curl' command not found, exiting.'
command -v jq >/dev/null 2>&1 || die 'required 'jq' command not found, exiting.'

echo 'Creating MinIO Docker container...'
container_name='boundary-minio'
minio_root_user='minio'
minio_root_pw='minio1234567890'
docker run -dt --rm \
  -p '9000:9000' -p '9090:9090' \
  -e "MINIO_ROOT_USER=$minio_root_user" \
  -e "MINIO_ROOT_PASSWORD=$minio_root_pw" \
  -e "MINIO_ADDRESS=:9000" \
  -e "MINIO_CONSOLE_ADDRESS=:9090" \
  -e 'MINIO_VOLUMES=/mnt/data' \
  --name "$container_name" \
  minio/minio server
echo -e 'Done!'

echo 'Waiting for MinIO instance to be healthy...'
healthcheck_retries=10
healthcheck_interval=1 # seconds
healthy=false
for i in $(seq 1 $healthcheck_retries);
do
  if [ $((i % 5)) = 0 ]; then
    echo '  Still waiting...'
  fi
  if [ $(curl -Is -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9000/minio/health/live) == '200' ]; then
    healthy=true
    break
  fi
  sleep $healthcheck_interval
done
if [ "$healthy" = false ]; then
  die "minio instance not healthy after $healthcheck_retries retries"
fi
echo 'Done!'

echo '###########################################################'
echo 'MinIO instance information:'
echo "  Container Name:      $container_name"
echo "  Root Login Username: $minio_root_user"
echo "  Root Login Password: $minio_root_pw"
if [ -n "${MINIO_ACCESS_KEY}" ]; then 
  echo "  Service Account Access Key: $MINIO_ACCESS_KEY"
fi
if [ -n "${MINIO_SECRET_KEY}" ]; then
  echo "  Service Account Secret Key: $MINIO_SECRET_KEY"
fi
echo 'You can use the root username and password as'
echo 'access key and secret key respectively.'
echo '###########################################################'
