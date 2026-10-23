#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"

log_info() { printf "\033[1;34m[INFO]\033[0m %s\n" "$*"; }

log_info "Cleaning up sample kind clusters ..."
kind delete cluster --name cluster-a 2>/dev/null || true
kind delete cluster --name cluster-b 2>/dev/null || true

log_info "Cleaning up generated certificates ..."
rm -f "$DIR"/certs/ca-*.pem
