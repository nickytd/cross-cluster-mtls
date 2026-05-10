#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"

log_info() { printf "\033[1;34m[INFO]\033[0m %s\n" "$*"; }
log_debug() { printf "\033[0;37m[DEBUG]\033[0m %s\n" "$*"; }

: "${CONTEXT:?CONTEXT must be set}"
: "${NAMESPACE:?NAMESPACE must be set}"
: "${SERVER_IP:?SERVER_IP must be set}"

log_info "Deploying mTLS client in $CONTEXT (namespace: $NAMESPACE)"

sed "s/SERVER_IP_PLACEHOLDER/$SERVER_IP/" "$DIR/manifests/client-pod.yaml" | \
  kubectl --context "$CONTEXT" apply -f -

log_debug "Waiting for client pod (may take up to 5 minutes due to kubelet backoff)..."
kubectl --context "$CONTEXT" -n "$NAMESPACE" wait --for=condition=Ready pod/mtls-client --timeout=300s

log_debug "Waiting for client to complete at least 2 successful requests..."
for i in $(seq 1 30); do
  count=$(kubectl --context "$CONTEXT" -n "$NAMESPACE" logs mtls-client 2>/dev/null | grep -c "response \[200\]" || true)
  if [ "$count" -ge 2 ]; then
    break
  fi
  sleep 1
done

log_info "Client running."
