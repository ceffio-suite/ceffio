# Ceffio — Migration vers Nextcloud Talk + HPB

**Remplacement de la pile Matrix/Element + Jitsi par Nextcloud Talk avec
High Performance Backend.**

Décision du 2026-10-09. Statut : plan validé, exécution non commencée.

---

## 1. Décision et justification

Ceffio devient un **produit Nextcloud**, pas un produit Matrix : tout vit dans
Nextcloud, avec **un seul login** (Keycloak, déjà branché sur Nextcloud).

| | Avant | Après |
|---|---|---|
| Fichiers / bureautique | Nextcloud | Nextcloud |
| SSO | Keycloak | Keycloak |
| Chat | Synapse + Element | **Talk** |
| Visio | Jitsi | **Talk + HPB** |
| Édition | ONLYOFFICE | ONLYOFFICE |

**6 briques, 2 messageries → 4 briques, 1 messagerie.**

Motif : le pont d'authentification Matrix↔Jitsi (adaptateur OIDC, UVS, jetons)
a coûté des heures de maintenance et n'a jamais été satisfaisant. Talk
s'authentifie **nativement** via Nextcloud, donc le problème disparaît par
construction plutôt que d'être contourné.

### Ce qu'on perd, assumé

- Fédération Matrix (parler à d'autres serveurs Matrix)
- E2EE textuel par défaut (Talk chiffre le transport et fait de l'E2EE **en appel**)
- Passerelles Matrix (Slack, IRC, Telegram, WhatsApp)
- Maturité/écosystème d'Element

Non bloquant pour la cible (petites PME, usage interne, simplicité, pas
d'abonnement). Ce sont des capacités perdues, pas des besoins.

---

## 2. Composants

Relevés dans `docker/docker-compose.yml` du dépôt officiel
`strukturag/nextcloud-spreed-signaling` — **5 services, pas 4**.

| Service | Rôle | Licence | Origine |
|---|---|---|---|
| **Talk** (`spreed`) | App Nextcloud : chat + visio | AGPL-3.0 | Déjà présente, à activer |
| **signaling** | Coordination (léger, Go) | AGPL-3.0 | Image officielle Docker Hub `strukturag/nextcloud-spreed-signaling` |
| **Janus** 1.3.0 | SFU : transport du média | GPL-3.0 | **Compilé depuis les sources** (Dockerfile officiel) |
| **NATS** 2.10 | Messagerie inter-signaling (scalabilité) | Apache-2.0 | `nats:2.10` |
| **coturn** 4.6 | Relais TURN (réseaux restrictifs) | BSD | `coturn/coturn:4.6` |

Correspondance avec Jitsi (pour qui connaît) :

```
Interface        Jitsi Meet        →  Talk
Coordination     Prosody (XMPP)   →  signaling + NATS
Transport média  JVB (SFU)        →  Janus (SFU)
Chef d'orchestre Jicofo           →  signaling
TURN             coturn (intégré) →  coturn (séparé)
```

⚠️ **coturn n'est pas optionnel** : présent dans le compose officiel. Sans lui,
un participant derrière un réseau d'entreprise ou en 4G filtrée n'a **aucun**
chemin média.

---

## 3. Architecture cible

```
                        Caddy (OPNsense)  :443
                                 │
                        Traefik (k3s, VM 310)
                                 │
              ┌──────────────────┴──────────────────┐
              │                                     │
      cloud.<domaine>                       spreed.<domaine>
      (Nextcloud)                           (signaling, HTTPS + WS)
              │                                     │
        App Talk ─── appel HTTP interne ──► signaling server
        (navigateur)                                │
                                          ┌─────────┴─────────┐
                                        NATS               Janus
                                                              │
                                                           coturn
                                                    (relais, si nécessaire)
```

Le média WebRTC **ne passe pas par un proxy L7** : il emprunte les redirections
NAT vers Janus. Même principe que JVB et AgenTorch.

---

## 4. Réseau — ports à ouvrir (OPNsense)

**Ceffio a ses ports DÉDIÉS** — décision : isolation complète d'AgenTorch
(même raisonnement que « deux LiveKit séparés »). Aucun service partagé, aucun
secret commun, aucune règle NAT commune.

```
spreed.<domaine>      443/tcp       via Caddy — déjà routé par *.ceffio
20000-20100/udp       média Janus                 ← À OUVRIR
3479/udp              TURN coturn (Ceffio)        ← À OUVRIR (3478 = AgenTorch)
5349/tcp              TURN-over-TLS               ← À OUVRIR
49152-49200/udp       relais coturn               ← À OUVRIR
```

Répartition des ports TURN dans l'infrastructure :

```
3478/udp       AgenTorch — NE PAS TOUCHER
3479/udp       Ceffio                 (choix lisible : voisin du standard)
```

Le numéro de port TURN est **libre** (ce n'est pas un standard figé comme le
443). Le seul impératif : **le même numéro des deux côtés** (config coturn ↔
règle NAT), sinon le relais est injoignable.

Vérifié sur la VM 310 : `3479`, `5349`, `49152-49200`, `20000-20100` sont
**tous libres** (aucun conflit local). Le conflit avec AgenTorch n'existe que
sur l'IP publique, via les règles NAT — et il est résolu par le port dédié.

La plage Janus par défaut est `20000-40000` (lue dans
`conf/janus.jcfg.sample.in`). On la **réduit à 100 ports** : largement suffisant
pour une PME, et ça évite d'ouvrir 20 000 ports.

Réglage à poser (`rtp_port_range` dans `janus.jcfg`) :
```
rtp_port_range = "20000-20100"
```

### Pièges réseau (déjà rencontrés, à ne pas refaire)

1. **Pour une plage, le champ « port local » de la règle OPNsense doit rester
   VIDE** — renseigné, pf rabat toute la plage sur un seul port. Erreur déjà
   commise pour AgenTorch, documentée dans le wiki.
2. **Vérifier les chevauchements** : AgenTorch occupe `50000-60000/udp`,
   `30000-40000/udp`, `3478/udp`. Réglé : Ceffio utilise des plages et un port
   TURN **entièrement distincts** (voir ci-dessus), et une VM différente
   (192.168.1.48 contre 10.9.1.113). Aucune règle NAT n'est partagée.
3. Les pods k3s ne lisent pas `/etc/hosts` du nœud : `hostAliases` ou CoreDNS
   pour résoudre par nom public.

---

## 4bis. Isolation réseau — décision de traçabilité

**Décision : Ceffio et AgenTorch ne partagent AUCUNE ressource réseau.**

Motif : une entreprise n'héberge pas plusieurs services critiques sur les mêmes
ports, avec le même secret et la même règle NAT. Partager le TURN voudrait dire
qu'une panne d'un relais coupe les visios des deux produits, qu'un changement de
config pour l'un casse l'autre, et que les identifiants TURN d'AgenTorch
ouvriraient le relais Ceffio. C'est exactement le raisonnement appliqué aux deux
instances LiveKit séparées.

```
                    VM                  ports média       TURN
AgenTorch   10.9.1.113  (at-livekit)   50000-60000/udp   3478/udp
                                      30000-40000/udp
Ceffio      192.168.1.48 (VM 310)     20000-20100/udp   3479/udp
                                      49152-49200/udp
```

Aucun chevauchement. Aucune règle NAT partagée. Aucun secret commun.

Réserve honnête : le TURN n'est **pas obligatoire au démarrage**. Janus
fonctionne sans, tant que les utilisateurs sont sur des réseaux autorisant l'UDP
direct. Le coturn sert à ceux qui sont bloqués (4G d'entreprise, réseaux
d'hôtel). On peut donc déployer Talk **sans** coturn d'abord, et l'ajouter
seulement si des utilisateurs se plaignent — c'est un test qui ne coûte rien.

## 5. Ce qu'il faut automatiser dans `ceffio install`

```
1.  Générer les secrets        hash_key, block_key, shared_secret,
                               turn_static_secret  (jamais en Git)
2.  Construire/pousser Janus   image bâtie depuis les sources → registry GitLab
3.  Déployer NATS              Deployment + Service
4.  Déployer Janus             Deployment + Service + ConfigMap (port réduit)
5.  Déployer coturn            Deployment + Service + secret statique
6.  Déployer le signaling      Deployment + Service + ConfigMap server.conf
7.  Activer Talk               occ app:enable spreed
8.  Raccorder Nextcloud ↔ HPB  occ config:app:set spreed signaling_server_url
                               + shared secret (via occ, JAMAIS à la main)
9.  Exposer spreed.<domaine>   ingress + DNS + handler Caddy (ceffio expose)
```

**Point de conception — image Janus.** Le Dockerfile officiel **compile Janus
depuis les sources** (le compose fait `build:`). Dans un k3s sans toolchain :
- **recommandé** : bâtir l'image une fois, la pousser dans le registry GitLab,
  épingler le tag — cohérent avec la règle « versions épinglées, jamais
  `latest` » ;
- alternative : image Janus publique préconstruite (moins reproductible).

---

## 6. Retrait — l'inventaire COMPLET

Un `kubectl apply` ne supprime **jamais** ce qu'il ne connaît plus, et les
variables d'environnement posées par un patch **survivent** aux
redéploiements. Il faut un nettoyage explicite, comme `internal/media/sans_sso.go`
l'a fait pour le SSO Jitsi.

### 6.1 Matrix (Synapse + Element)

```
workloads    deploy/synapse, deploy/element, svc correspondants
ingress      chat.<domaine>, matrix.<domaine>
secrets      synapse-db, synapse-secrets, synapse-oidc
base         PostgreSQL `synapse`   (DROP DATABASE)
volume       PVC synapse-media
Keycloak     client OIDC `synapse`  (+ secret k8s synapse-oidc)
code         internal/chat/         (chat.go, ConfigureOIDC, ensureSynapseDB…)
             cmd/ceffio/install.go  → retirer l'appel chat.Deploy + ConfigureOIDC
             cmd/ceffio/redeploy.go → idem
backup       retirer `synapse` de la liste des bases du backup
status       retirer la couche `chat` de la console d'admin
```

### 6.2 Jitsi

```
workloads    deploy/web, prosody, jicofo, jvb + services
loadbalancer celui qui porte UDP 10000 / TCP 4443
ingress      meet.<domaine>
secrets      jitsi-secrets
volume       PVC jitsi-config
code         internal/media/media.go (le Deploy Jitsi)
             internal/media/sans_sso.go (nettoyage SSO, devenu inutile)
NAT          règles OPNsense UDP 10000 + TCP 4443
registry     images ghcr.io/jitsi/* dans internal/version
config.json  Element : la clé "jitsi" (l'objet disparaît avec Element)
```

### 6.3 Divers liés

```
Keycloak     webOrigins + frame-ancestors posés pour le widget Jitsi
             (déjà neutralisés au retrait du SSO — vérifier qu'ils partent)
console      entrées `chat` et `meet` de internal/console/status.go
doc          docs/sso-office-ingress-fixes.md mentionne Jitsi/Matrix
```

---

## 7. Ordre d'exécution

```
Phase 0   Mesurer les ressources de la VM 310              ← BLOQUANT
Phase 1   Bâtir + pousser l'image Janus (registry GitLab)
Phase 2   Déployer NATS, Janus, coturn, signaling           sans toucher au reste
Phase 3   Activer Talk + raccorder au HPB
Phase 4   Tests réels (voir §8)
Phase 5   Retrait de Jitsi          SEULEMENT si phase 4 OK
Phase 6   Retrait de Synapse/Element SEULEMENT si phase 4 OK
Phase 7   Nettoyage OPNsense (ports), DNS, docs, console
```

**Les phases 5 et 6 sont dissociées exprès** : on ne coupe l'existant qu'après
preuve que le nouveau fonctionne. Jitsi et Element restent l'option de repli
pendant toute la migration.

---

## 8. Tests qui valent (pas « ça a l'air de marcher »)

```
1.  Appel 1:1 dans Talk                    → 2 participants, son + image
2.  Appel de groupe (5-6)                  → passe par Janus, pas en P2P
    Preuve : logs Janus montrant les flux, ou `chrome://webrtc-internals`
3.  Invité externe par lien                → sans compte Nextcloud
4.  Réseau restrictif (4G / partage)       → coturn fait son travail
    Preuve : logs coturn montrant l'allocation
5.  SSO : l'appel utilise le login Nextcloud → aucun prompt supplémentaire
6.  Enregistrement (si activé)             → fichier dans Nextcloud Files
7.  Charge : mesurer à 10-15 participants   → CPU/RAM de Janus
8.  Ports ouverts depuis l'extérieur        → règle NAT effective
    Rappel : un test UDP par paquet vide renvoie TOUJOURS un timeout
    (faux négatif) — capturer avec tcpdump, ne pas conclure sur le timeout
```

---

## 9. Points à trancher avant de commencer

1. ~~Ressources VM 310~~ — **MESURÉ, LARGEMENT SUFFISANT** (2026-10-09) :

   ```
   machine        8 coeurs · 31 Gi RAM · 96 G disque (23 % utilisé)
   disponible     26 Gi RAM · ~7.9 coeurs · 75 G disque
   pods actuels   0.45 coeur demandé · 6.8 Gi demandés (8.3 Gi de limite)
   besoin HPB     ~3.8 Gi (Janus 2 + coturn 1 + signaling 0.5 + NATS 0.25)
   après déploiement   > 20 Gi de RAM libre
   ```

   Ces chiffres sont ceux d'une VM **au repos** : ils prouvent qu'il y a la
   place d'installer sans dégrader Nextcloud/Keycloak/ONLYOFFICE, mais pas la
   tenue en charge réelle (qui dépend de la **bande passante**, ~1.5 Mbps par
   participant dans les deux sens — non mesurable sans appel en cours).
2. ~~Conflit TURN 3478/udp avec AgenTorch~~ — **RÉSOLU** : port dédié 3479
   pour Ceffio, isolation complète.
3. **Image Janus** — bâtir et versionner (recommandé) ou image publique ?
4. **Le flag `--video`** — devient la visio Talk. Renommer, ou Talk par défaut ?
5. **Transcription** — Talk a une app `live_transcription` mais elle exige un
   backend IA à héberger. **Hors périmètre**, décision séparée.
6. **Migration des données** — les historiques de chat Matrix et les
   enregistrements Jitsi existants : à exporter, ou à abandonner ?

---

## 10. Règles à respecter (leçons déjà payées)

- **Tout en une commande** : `ceffio install` doit déployer ET configurer sans
  intervention. Un produit auto-portant ne demande pas de « puis fais ceci à la
  main ».
- **`occ` pour configurer Nextcloud**, jamais de modification manuelle en base.
- **Versions épinglées**, jamais `latest` ; images dans le registry GitLab.
- **Secrets jamais en Git** ; générés au déploiement.
- **Vérifier un tag par un pull**, pas par « il existe ».
- **tmux** pour tout travail long sur VM.
- **Un contrôle qui ne distingue pas l'avant de l'après ne vérifie rien** :
  le test final est un vrai appel, pas un `kubectl get pods`.