#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"

log_info() { printf "\033[1;34m[INFO]\033[0m %s\n" "$*"; }
log_debug() { printf "\033[0;37m[DEBUG]\033[0m %s\n" "$*"; }

: "${CONTEXT:?CONTEXT must be set}"
: "${NAMESPACE:?NAMESPACE must be set}"

log_info "Deploying mTLS server in $CONTEXT (namespace: $NAMESPACE)"

kubectl --context "$CONTEXT" apply -f "$DIR/manifests/server-pod.yaml"

log_debug "Waiting for server pod (may take up to 5 minutes due to kubelet backoff)..."
kubectl --context "$CONTEXT" -n "$NAMESPACE" wait --for=condition=Ready pod/mtls-server --timeout=300s

log_info "Server running."
