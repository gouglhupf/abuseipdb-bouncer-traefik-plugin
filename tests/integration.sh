#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
compose() { docker compose -p abuseipdb-integration -f compose.yml -f tests/compose.yml "$@"; }
cleanup() {
  result=$?
  trap - EXIT
  if [ "$result" -ne 0 ]; then compose logs --no-color; fi
  compose down -v --remove-orphans
  exit "$result"
}
trap cleanup EXIT
compose up -d --wait traefik whoami
compose --profile test run --rm probe
