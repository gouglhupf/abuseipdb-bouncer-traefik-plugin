#!/bin/sh
set -eu
check() {
  expected=$1; ip=$2; path=$3
  code=$(curl --silent --show-error --max-time 10 -D /tmp/headers -o /tmp/body -w '%{http_code}' -H "X-Forwarded-For: $ip" "http://traefik$path")
  if [ "$code" != "$expected" ]; then
    echo "Expected $expected for $ip $path, got $code"; cat /tmp/headers /tmp/body; exit 1
  fi
  if grep -q 'integration-secret' /tmp/headers /tmp/body; then echo 'Secret leaked'; exit 1; fi
}
check 200 203.0.113.1 /
check 403 203.0.113.2 /
check 200 10.1.2.3 /
check 403 8.8.8.8 /
check 403 8.8.8.8 /
check 200 1.1.1.1 /
check 200 9.9.9.9 /
check 200 2606:4700:4700::1111 /
check 200 4.4.4.4 /
check 403 4.4.4.4 /closed
check 200 7.7.7.7 /
check 403 7.7.7.7 /closed
check 200 5.5.5.5 /
check 403 6.6.6.6 /category
stats=$(curl --silent --show-error --fail http://stub:8080/stats)
echo "$stats"
echo "$stats" | grep -q '"8.8.8.8":1'
echo "$stats" | grep -q '"4.4.4.4":2'
echo 'Traefik/Yaegi integration passed'