#!/usr/bin/env bash

set -e -o pipefail

git rm -rf --ignore-unmatch \
  .github \
  tests \
  **/*_test.go \
  conn/bindtest \
  tun/netstack \
  tun/tuntest \
  tun/testdata \
  tun/checksum.go \
  tun/operateonfd.go \
  tun/tcp_offload_linux.go \
  tun/tun_*.go \
  *.go \
  *.md

go mod tidy
git add go.mod go.sum
git commit -m "Remove unused"
