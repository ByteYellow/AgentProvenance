#!/usr/bin/env bash
set -euo pipefail
# Add passive Pod attribution to the in-guest systemd collector. Both use the
# same node-local store; do not deploy a second ingesting sensor for this store.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ "$EUID" == 0 ]] || { echo 'run as root on the K3s node' >&2; exit 2; }
AGENTPROV="${AGENTPROV:?set AGENTPROV to the static Linux CLI binary}"
IMAGE="${AGENTPROV_CONTROLLER_IMAGE:-agentprov-controller:local}"
systemctl is-active --quiet agentprov-sensor.service
k3s kubectl wait --for=condition=Ready nodes --all --timeout=90s
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT
cp "$AGENTPROV" "$BUILD/agentprov"
cp "$ROOT_DIR/deploy/k8s/Dockerfile.controller" "$BUILD/Dockerfile"
docker build -q -t "$IMAGE" "$BUILD"
docker save "$IMAGE" | k3s ctr images import - >/dev/null
sed "s#image: agentprov-controller:latest#image: $IMAGE#" \
  "$ROOT_DIR/deploy/k8s/agentprov-attribution-controller.yaml" >"$BUILD/controller.yaml"
k3s kubectl apply -f "$BUILD/controller.yaml"
k3s kubectl rollout status daemonset/agentprov-attribution-controller -n agentprov --timeout=90s
echo 'K3s attribution controller ready; annotate workloads with agentprov.io/run'
