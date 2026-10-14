#!/usr/bin/env bash
# "From scratch" test: really deletes the k3d cluster, then replays the full
# installation from zero to prove the suite rebuilds itself in one command.
# To run after EACH phase (project rule): make test-clean
set -euo pipefail
cd "$(dirname "$0")/.."

DOMAIN="${CEFFIO_TEST_DOMAIN:-demo.local}"
PROFILE="${CEFFIO_TEST_PROFILE:-small}"

# Start marker (to prove the cluster is recreated FROM SCRATCH, not reused).
TEST_MARKER="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "test started at $TEST_MARKER"

echo "==> TEARDOWN: deleting the k3d cluster ceffio-dev"
if k3d cluster list 2>/dev/null | grep -qw "ceffio-dev"; then
  k3d cluster delete ceffio-dev
  # Verify the cluster is really gone (otherwise we would replay on the old one).
  if k3d cluster list 2>/dev/null | grep -qw "ceffio-dev"; then
    echo "ERROR: ceffio-dev still exists after teardown — test aborted." >&2
    exit 1
  fi
fi
echo "  cluster absent: OK"

echo "==> BUILD CLI"
make build

echo "==> FULL INSTALL FROM ZERO (domain=$DOMAIN profile=$PROFILE)"
./bin/ceffio install --domain "$DOMAIN" --profile "$PROFILE"

echo "==> FROM-SCRATCH PROOF"
OLDEST="$(kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.creationTimestamp}{"\n"}{end}' 2>/dev/null | sort | head -1)"
echo "  oldest pod: $OLDEST"
if [[ "$OLDEST" < "$TEST_MARKER" ]]; then
  echo "ERROR: cluster not recreated from scratch (pod older than the test start)" >&2
  exit 1
fi
echo "  every pod is newer than the test start: OK"

echo "==> FINAL STATE"
echo "-- nodes --"
kubectl get nodes
echo "-- pods (all namespaces) --"
kubectl get pods -A
echo "-- keycloak realms --"
kubectl exec -c postgres -n ceffio-data ceffio-pg-1 -- psql -U postgres -d keycloak -tAc "SELECT name||'/'||enabled FROM realm ORDER BY name;" 2>/dev/null | grep -v Defaulted || true

echo "==> FROM-SCRATCH TEST: OK"
