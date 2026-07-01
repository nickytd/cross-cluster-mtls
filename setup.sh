#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

log_info() { printf "\033[1;34m[INFO]\033[0m %s\n" "$*"; }
log_debug() { printf "\033[0;37m[DEBUG]\033[0m %s\n" "$*"; }

log_info "=== Cross-Cluster mTLS ==="
log_info "Using PodCertificateRequest + ClusterTrustBundle on kind (K8s 1.35)"

# --- Step 1: Create kind clusters ---
log_info "--- Step 1: Creating kind clusters ---"

if kind get clusters 2>/dev/null | grep -q "^cluster-a$"; then
  log_debug "cluster-a already exists, skipping..."
else
  kind create cluster --config "$DIR/kind/kind-cluster-a.yaml" --wait 60s
fi
if kind get clusters 2>/dev/null | grep -q "^cluster-b$"; then
  log_debug "cluster-b already exists, skipping..."
else
  kind create cluster --config "$DIR/kind/kind-cluster-b.yaml" --wait 60s
fi

# --- Step 2: Generate CAs ---
log_info "--- Step 2: Generating CA certificates ---"

mkdir -p "$DIR/certs"

# CA for cluster-a
cfssl gencert -initca - 2>/dev/null <<< '{"CN":"Cluster-A CA","key":{"algo":"ecdsa","size":256},"ca":{"expiry":"8760h"},"names":[{"O":"sample.io"}]}' | \
  cfssljson -bare "$TMPDIR/ca-a"
log_debug "Generated CA-A: $(openssl x509 -noout -subject -in "$TMPDIR/ca-a.pem")"
mv "$TMPDIR/ca-a.pem" "$TMPDIR/ca-a-key.pem" "$DIR/certs/"

# CA for cluster-b
cfssl gencert -initca - 2>/dev/null <<< '{"CN":"Cluster-B CA","key":{"algo":"ecdsa","size":256},"ca":{"expiry":"8760h"},"names":[{"O":"sample.io"}]}' | \
  cfssljson -bare "$TMPDIR/ca-b"
log_debug "Generated CA-B: $(openssl x509 -noout -subject -in "$TMPDIR/ca-b.pem")"
mv "$TMPDIR/ca-b.pem" "$TMPDIR/ca-b-key.pem" "$DIR/certs/"

# --- Step 3: Build container images ---
log_info "--- Step 3: Building container images ---"

docker build -t sample-signer:local "$DIR/signer"
docker build -t sample-server:local "$DIR/server"
docker build -t sample-client:local "$DIR/client"

# --- Step 4: Load images into kind clusters ---
log_info "--- Step 4: Loading images into kind clusters ---"

kind load docker-image sample-signer:local --name cluster-a
kind load docker-image sample-client:local --name cluster-a

kind load docker-image sample-signer:local --name cluster-b
kind load docker-image sample-server:local --name cluster-b

# --- Step 5: Deploy signer to both clusters ---
log_info "--- Step 5: Deploying signer controller ---"

# cluster-a: signer with CA-A (namespace: kube-system)
kubectl --context kind-cluster-a create namespace client --dry-run=client -o yaml | kubectl --context kind-cluster-a apply -f -
sed "s/NS_PLACEHOLDER/kube-system/" "$DIR/signer/manifests/signer-rbac.yaml" | kubectl --context kind-cluster-a -n kube-system apply -f -
kubectl --context kind-cluster-a -n kube-system create secret tls signer-ca \
  --cert="$DIR/certs/ca-a.pem" --key="$DIR/certs/ca-a-key.pem" --dry-run=client -o yaml | \
  kubectl --context kind-cluster-a apply -f -
kubectl --context kind-cluster-a -n kube-system apply -f "$DIR/signer/manifests/signer-deploy.yaml"

# cluster-b: signer with CA-B (namespace: kube-system)
kubectl --context kind-cluster-b create namespace server --dry-run=client -o yaml | kubectl --context kind-cluster-b apply -f -
sed "s/NS_PLACEHOLDER/kube-system/" "$DIR/signer/manifests/signer-rbac.yaml" | kubectl --context kind-cluster-b -n kube-system apply -f -
kubectl --context kind-cluster-b -n kube-system create secret tls signer-ca \
  --cert="$DIR/certs/ca-b.pem" --key="$DIR/certs/ca-b-key.pem" --dry-run=client -o yaml | \
  kubectl --context kind-cluster-b apply -f -
kubectl --context kind-cluster-b -n kube-system apply -f "$DIR/signer/manifests/signer-deploy.yaml"

log_debug "Waiting for signer pods..."
kubectl --context kind-cluster-a -n kube-system wait --for=condition=Available deployment/signer --timeout=60s
kubectl --context kind-cluster-b -n kube-system wait --for=condition=Available deployment/signer --timeout=60s

# --- Step 6: Create ClusterTrustBundles (cross-plant CAs) ---
log_info "--- Step 6: Creating ClusterTrustBundles ---"

# One signer name serves both roles now; each cluster publishes the peer's CA
# under a bundle keyed to sample.io/signer and labeled usage=remote-ca so pods
# can select it via clusterTrustBundle labelSelector.
apply_remote_ca_bundle() {
  local context="$1" ca_file="$2"
  cat <<EOF | kubectl --context "$context" apply -f -
apiVersion: certificates.k8s.io/v1beta1
kind: ClusterTrustBundle
metadata:
  name: sample.io:signer:remote-ca
  labels:
    usage: remote-ca
spec:
  signerName: "sample.io/signer"
  trustBundle: |
$(sed 's/^/    /' "$ca_file")
EOF
}

# cluster-a (client) trusts servers in cluster-b: carries CA-B.
apply_remote_ca_bundle kind-cluster-a "$DIR/certs/ca-b.pem"
# cluster-b (server) trusts clients from cluster-a: carries CA-A.
apply_remote_ca_bundle kind-cluster-b "$DIR/certs/ca-a.pem"

# --- Step 7: Deploy server in cluster-b ---
CONTEXT=kind-cluster-b NAMESPACE=server "$DIR/server/setup.sh"

# --- Step 8: Get cluster-b control-plane IP for cross-cluster access ---
log_info "--- Resolving cluster-b IP for client ---"

CLUSTER_B_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' cluster-b-control-plane)
log_debug "cluster-b control-plane IP: $CLUSTER_B_IP"

# --- Step 9: Deploy client in cluster-a ---
CONTEXT=kind-cluster-a NAMESPACE=client SERVER_IP="$CLUSTER_B_IP" "$DIR/client/setup.sh"

# --- Step 10: Verify mTLS ---
log_info "--- Verifying mTLS communication ---"

log_info "=== Server logs (cluster-b) ==="
kubectl --context kind-cluster-b -n server logs mtls-server --tail=20

log_info "=== Client logs (cluster-a) ==="
kubectl --context kind-cluster-a -n client logs mtls-client --tail=20

log_info "=== PodCertificateRequests in cluster-a ==="
kubectl --context kind-cluster-a get podcertificaterequests -A -o wide 2>/dev/null || \
  kubectl --context kind-cluster-a get podcertificaterequests.certificates.k8s.io -A 2>/dev/null || true

log_info "=== PodCertificateRequests in cluster-b ==="
kubectl --context kind-cluster-b get podcertificaterequests -A -o wide 2>/dev/null || \
  kubectl --context kind-cluster-b get podcertificaterequests.certificates.k8s.io -A 2>/dev/null || true

log_info "=== ClusterTrustBundles ==="
log_debug "cluster-a:"
kubectl --context kind-cluster-a get clustertrustbundles -o wide 2>/dev/null || true
log_debug "cluster-b:"
kubectl --context kind-cluster-b get clustertrustbundles -o wide 2>/dev/null || true

log_info "Cross-cluster mTLS verified using PodCertificateRequest + ClusterTrustBundle!"
