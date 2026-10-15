#!/bin/bash
# Surveillance TURN pendant un test d'appel.
#
# A LANCER DEPUIS LE MAC, puis faire l'appel depuis l'entreprise.
#
# Ce script repond a UNE question, et c'est la seule qui compte quand un appel
# echoue derriere un NAT restrictif : est-ce que le navigateur essaie le relais
# TURN, oui ou non ?
#
#   - Des ALLOCATIONS apparaissent  -> le relais fonctionne. Si l'appel echoue
#     quand meme, la cause est ailleurs (plage de relais, ou media).
#   - RIEN n'apparait               -> le navigateur n'a jamais demande de
#     relais : le blocage est en amont (entreprise, ou ce que Talk annonce).
#
# Ces deux cas demandent des corrections OPPOSEES, d'ou l'interet de les
# distinguer avant de changer quoi que ce soit.

set -u
NS="ceffio-video"
DUREE="${1:-300}"

COTURN=$(kubectl --context ceffio-val get pods -n "$NS" -l app=coturn \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null | tail -1)
SIG=$(kubectl --context ceffio-val get pods -n "$NS" -l app=talk-signaling \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null | tail -1)

if [ -z "$COTURN" ]; then
  echo "ERREUR: pod coturn introuvable. Le cluster est-il joignable (VPN) ?"
  exit 1
fi

echo "=========================================================="
echo " Surveillance TURN — $DUREE secondes"
echo " Fais ton appel MAINTENANT depuis l'entreprise."
echo "=========================================================="
echo ""
echo "  coturn  : $COTURN"
echo "  signaling: ${SIG:-?}"
echo ""
echo "  Etat AVANT (le navigateur essaie-t-il le relais ?) :"
echo "    allocations actives : $(kubectl --context ceffio-val exec -n "$NS" "$COTURN" -c coturn -- sh -c 'ss -tuna 2>/dev/null | grep -c 4915' 2>/dev/null || echo 0)"
echo ""
echo "--- DEBUT (Ctrl-C pour arreter) ---"
echo ""

# On suit les deux sources en parallele. Chaque ligne est horodatee pour
# pouvoir la rapprocher du moment de l'appel.
# Horodatage PORTABLE : "awk strftime" est une extension GNU absente du BSD awk
# de macOS — le premier essai n'affichait RIEN a cause de ca ("calling undefined
# function strftime"). On prefixe avec date, appele ligne par ligne.
kubectl --context ceffio-val logs -n "$NS" "$COTURN" -c coturn -f --since=1s 2>&1 \
  | while IFS= read -r ligne; do printf '[%s] TURN %s\n' "$(date +%H:%M:%S)" "$ligne"; done &

COTURN_PID=$!
if [ -n "$SIG" ]; then
  kubectl --context ceffio-val logs -n "$NS" "$SIG" -c signaling -f --since=1s 2>&1 \
    | grep -viE "capabilities|Capabilities" \
    | while IFS= read -r ligne; do printf '[%s] SIG  %s\n' "$(date +%H:%M:%S)" "$ligne"; done &
  SIG_PID=$!
fi

sleep "$DUREE"

kill $COTURN_PID 2>/dev/null
[ -n "${SIG_PID:-}" ] && kill $SIG_PID 2>/dev/null
wait 2>/dev/null

echo ""
echo "=========================================================="
echo " BILAN"
echo "=========================================================="
echo ""
echo " 1. Allocations TURN recues :"
kubectl --context ceffio-val logs -n "$NS" "$COTURN" -c coturn --since="${DUREE}s" 2>&1 \
  | grep -iE "allocation|create perm|channel bind|session [0-9]" | tail -10
echo "    (vide = aucun relais demande)"
echo ""
echo " 2. Erreurs coturn :"
kubectl --context ceffio-val logs -n "$NS" "$COTURN" -c coturn --since="${DUREE}s" 2>&1 \
  | grep -iE "error|denied|unauthor|fail" | tail -6
echo "    (vide = rien de rejete)"
echo ""
echo " 3. Cote signaling — salles et appels :"
kubectl --context ceffio-val logs -n "$NS" "$SIG" -c signaling --since="${DUREE}s" 2>&1 \
  | grep -viE "capabilities|Capabilities" \
  | grep -iE "left call|joined|destroyed|error|fail" | tail -8
echo ""
echo "=========================================================="
echo " COMMENT LIRE"
echo "=========================================================="
echo "  allocation presente + appel OK    -> le relais marche"
echo "  allocation presente + appel KO    -> plage 49152-49200/UDP a verifier"
echo "  aucune allocation                 -> blocage en amont du relais"