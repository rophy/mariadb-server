#!/bin/bash
# Set up a Kind cluster with ServiceAccounts for auth_k8s MTR tests.
#
# Prerequisites: kind, kubectl
#
# This creates:
#   - A Kind cluster (default name: auth-k8s-test)
#   - Namespace: mariadb-auth-test
#   - SA: mariadb-tokenreview (with system:auth-delegator for TokenReview API)
#   - SA: user1, user2 (test client identities)
#
# After running this script, you can run the MTR tests:
#   cd mysql-test && ./mtr --suite=auth_k8s

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLUSTER_NAME="${1:-auth-k8s-test}"

echo "Setting up Kind cluster '$CLUSTER_NAME' for auth_k8s tests"
echo ""

# Check prerequisites
for cmd in kind kubectl; do
  if ! command -v "$cmd" > /dev/null 2>&1; then
    echo "Error: $cmd not found"
    exit 1
  fi
done

# Create cluster if it doesn't exist
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  echo "Cluster '$CLUSTER_NAME' already exists"
else
  echo "Creating cluster '$CLUSTER_NAME'..."
  kind create cluster --name "$CLUSTER_NAME" --wait 5m
  echo "Cluster created"
fi

# Switch context
kubectl config use-context "kind-${CLUSTER_NAME}" > /dev/null

# Apply manifests
echo "Applying Kubernetes manifests..."
kubectl apply -f "$SCRIPT_DIR/k8s/namespace.yaml"
kubectl apply -f "$SCRIPT_DIR/k8s/rbac.yaml"
kubectl apply -f "$SCRIPT_DIR/k8s/test-clients.yaml"

echo ""
echo "Verifying setup..."
kubectl get sa -n mariadb-auth-test

echo ""
echo "Setup complete. Run the MTR tests with:"
echo "  cd mysql-test && ./mtr --suite=auth_k8s"
echo ""
echo "To destroy the cluster:"
echo "  kind delete cluster --name $CLUSTER_NAME"
