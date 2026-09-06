#!/usr/bin/env bash
# Test "from scratch" : supprime le cluster k3d, puis rejoue l'install complète
# depuis zéro pour prouver que la suite se reconstruit en une seule commande.
# À lancer après CHAQUE phase (règle projet) : make test-clean
set -euo pipefail
cd "$(dirname "$0")/.."

DOMAIN="${CEFFIO_TEST_DOMAIN:-demo.local}"
PROFILE="${CEFFIO_TEST_PROFILE:-small}"

echo "==> TEARDOWN : suppression du cluster k3d ceffio-dev"
k3d cluster delete ceffio-dev --force 2>/dev/null || true

echo "==> BUILD CLI"
make build

echo "==> INSTALL COMPLET DEPUIS ZÉRO (domain=$DOMAIN profile=$PROFILE)"
./bin/ceffio install --domain "$DOMAIN" --profile "$PROFILE"

echo "==> ÉTAT FINAL"
echo "-- nodes --"
kubectl get nodes
echo "-- pods (tous namespaces) --"
kubectl get pods -A
echo "-- realms keycloak --"
kubectl exec -c postgres -n ceffio-data ceffio-pg-1 -- psql -U postgres -d keycloak -tAc "SELECT name||'/'||enabled FROM realm ORDER BY name;" 2>/dev/null | grep -v Defaulted || true

echo "==> TEST FROM-SCRATCH : OK"