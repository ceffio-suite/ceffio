#!/usr/bin/env bash
# Test "from scratch" : supprime réellement le cluster k3d, puis rejoue l'install
# complète depuis zéro pour prouver que la suite se reconstruit en une commande.
# À lancer après CHAQUE phase (règle projet) : make test-clean
set -euo pipefail
cd "$(dirname "$0")/.."

DOMAIN="${CEFFIO_TEST_DOMAIN:-demo.local}"
PROFILE="${CEFFIO_TEST_PROFILE:-small}"

# Marqueur de début (pour prouver que le cluster est recréé À NEUF, pas réutilisé).
TEST_MARKER="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "début du test à $TEST_MARKER"

echo "==> TEARDOWN : suppression du cluster k3d ceffio-dev"
if k3d cluster list 2>/dev/null | grep -qw "ceffio-dev"; then
  k3d cluster delete ceffio-dev
  # Vérifie que le cluster est réellement parti (sinon on rejouerait sur l'ancien).
  if k3d cluster list 2>/dev/null | grep -qw "ceffio-dev"; then
    echo "ERREUR: ceffio-dev existe encore après teardown — test annulé." >&2
    exit 1
  fi
fi
echo "  cluster absent : OK"

echo "==> BUILD CLI"
make build

echo "==> INSTALL COMPLET DEPUIS ZÉRO (domain=$DOMAIN profile=$PROFILE)"
./bin/ceffio install --domain "$DOMAIN" --profile "$PROFILE"

echo "==> PREUVE FROM-SCRATCH"
OLDEST="$(kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.creationTimestamp}{"\n"}{end}' 2>/dev/null | sort | head -1)"
echo "  pod le plus ancien : $OLDEST"
if [[ "$OLDEST" < "$TEST_MARKER" ]]; then
  echo "ERREUR: cluster non recréé à neuf (pod plus ancien que le début du test)" >&2
  exit 1
fi
echo "  tous les pods sont postérieurs au début du test : OK"

echo "==> ÉTAT FINAL"
echo "-- nodes --"
kubectl get nodes
echo "-- pods (tous namespaces) --"
kubectl get pods -A
echo "-- realms keycloak --"
kubectl exec -c postgres -n ceffio-data ceffio-pg-1 -- psql -U postgres -d keycloak -tAc "SELECT name||'/'||enabled FROM realm ORDER BY name;" 2>/dev/null | grep -v Defaulted || true

echo "==> TEST FROM-SCRATCH : OK"