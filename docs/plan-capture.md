# Plan de faisabilité — capture par participant et transcription des enregistrements

Statut : phase 1 livrée — le module `capture` et son déploiement existent
(`internal/capture`, `internal/modules/capture`), et l'image est publiée par son
propre dépôt ([ceffio-suite/ceffio-capture](https://github.com/ceffio-suite/ceffio-capture)),
versionnée indépendamment (`ghcr.io/ceffio-suite/ceffio-capture:v0.1.0`, épinglée
dans `internal/version`).

## 1. Objectif

Quand un participant lance un enregistrement dans un appel Talk :

1. une **piste audio par participant** est captée dès le démarrage ;
2. à l'arrêt, une transcription **nommée** (qui parle) est produite ;
3. le `.srt` et les pistes `.opus` sont déposés **à côté du `.webm`**, dans les
   fichiers de celui qui a lancé l'enregistrement ;
4. les sous-titres sont **incrustés dans le `.webm`**, pour que « Partager dans
   la conversation » partage l'enregistrement avec sa transcription.

Hors périmètre v1 : transcription en direct (c'est `live-transcription`, déjà
en place), résumé automatique, traduction.

## 2. Acquis (prototype validé)

| Élément | État |
|---|---|
| Client signaling + WebRTC, une piste par participant | validé (2 pistes réelles, 29 s et 49 s) |
| Démarrage sur l'état d'enregistrement Talk (`call_recording`) | validé |
| Langue : sélecteur de la salle + détection par piste | validé (`fr` détecté à 0,93 et 0,97) |
| Transcription CPU | faster-whisper int8, **×7–11 temps réel** mesuré |
| Noms des participants | reconstruits depuis le journal du signaling |
| Recalage des sous-titres sur le `.webm` | mesure par corrélation (6,4 s et 11,2 s selon la piste) |
| Pistes Opus 32 kbit/s | ×11 à ×19 plus léger que le WAV |
| Sous-titres incrustés | piste WebVTT, copie de flux, +683 octets |

Ce qui n'existe pas encore : tout est dans des `/tmp` (pod et hôte), aucun
script n'est dans le dépôt, rien n'est versionné ni testé.

## 3. Architecture : trois options

### Option A — image dédiée + nouveau module `capture` (recommandée)

Une image `ghcr.io/ceffio-suite/ceffio-capture`, **publiée par son propre dépôt**
(sa pile Python et son cycle de publication sont indépendants du binaire
Ceffio), déployée par un module `capture` qui déclare `Requires: ["recording"]`.
La version d'image est épinglée dans `internal/version`, comme janus.

- **Pour** : réutilise le client aiortc et faster-whisper déjà éprouvés ; le
  module reste facultatif et indépendant du binaire Go ; on peut livrer d'abord
  sans toucher au cœur.
- **Contre** : une deuxième image (Python) à maintenir, ~1,2 Go avec les modèles.

### Option B — tout en Go dans l'image existante

Le client WebRTC en Go (pion), whisper via whisper.cpp (cgo), muxage avec
ffmpeg embarqué.

- **Pour** : une seule image, binaire statique, pas de Python.
- **Contre** : réécriture complète du client signaling (1 450 lignes éprouvées
  en Python, protocole non documenté), cgo dans une image `FROM scratch`,
  deux à trois mois de travail pour un résultat moins sûr.

### Option C — nouvel ExApp (HaRP + AppAPI)

Comme `live-transcription`, enregistré dans Nextcloud.

- **Pour** : bénéficie de l'infrastructure ExApp (déploiement, secrets, mise à
  jour), et l'app peut exposer des réglages dans Nextcloud.
- **Contre** : un ExApp n'a pas d'accès naturel aux fichiers des utilisateurs,
  et il faudrait un second client AppAPI pour écrire les `.srt` ; ça ajoute une
  dépendance (AppAPI) pour un service qui n'a rien à faire dans Nextcloud.

**Décision proposée : A**, avec le client Python actuel. Le jour où Go devient
nécessaire, le module n'a pas à changer : seule l'image change.

## 4. Composants déployés par le module

Namespace `ceffio-video` (à côté du recorder, qui y vit déjà).

| Objet | Rôle |
|---|---|
| `Deployment ceffio-capture` (1 réplique) | le service : veille, capture, finalisation |
| `Service ceffio-capture` (port 8080, `/healthz`, `/metrics`) | supervision |
| `ServiceAccount ceffio-capture` + `Role`/`RoleBinding` | droits stricts (voir ci-dessous) |
| `PersistentVolumeClaim ceffio-capture-models` (2 Gi) | modèles Vosk + whisper, téléchargés à l'installation |
| `ConfigMap ceffio-capture` | salons suivis, modèle, options |
| Réglages du module (contrat `module.Configurable`) | visibles dans la console |

Droits nécessaires, et rien de plus :

- `ceffio-files` : `pods/exec` sur le pod Nextcloud (dépôt des fichiers +
  `occ files:scan`) ;
- `ceffio-data` : lecture des tables Talk (`oc_talk_rooms` pour l'état
  d'enregistrement et la langue) ;
- `ceffio-video` : `pods/log` sur le signaling, pour la correspondance
  session → utilisateur (à remplacer par le roster, cf. §6.2) ;
- pas d'accès au volume Nextcloud : on écrit par `exec`, pas par montage.

## 5. Flux

```
Talk                          ceffio-capture                    Nextcloud
 │                                  │                               │
 │ modérateur lance l'enregistrement│                               │
 │──── call_recording = 3 ─────────▶│ (veille, 1 s)                 │
 │                                  │── rejoint l'appel (client ────│
 │                                  │   interne, aiortc)            │
 │   une piste par participant ◀────│                               │
 │                                  │                               │
 │   arrêt (call_recording = 0) ───▶│                               │
 │                                  │── whisper int8 (CPU) ────┐    │
 │                                  │── Opus 32k par piste ────┤    │
 │                                  │── .srt nommé, recalé ────┘    │
 │                                  │── incrustation WebVTT ────────│
 │                                  │──── dépôt + files:scan ──────▶│
```

Détection de l'état : lecture de `oc_talk_rooms.call_recording`
(0 aucun, 1 vidéo, 2 audio, 3/4 démarrage, 5 échec). Un enregistrement qui
redémarre (entrée/sortie d'un participant) crée un nouveau `.webm` : la
transcription doit être découpée aux frontières de chaque fichier, en
s'appuyant sur son nom (heure de démarrage) et sa durée.

## 6. Points durs et solutions

### 6.1 Décalage des pistes

Chaque abonnement WebRTC arrive à un instant différent (mesuré : 6,4 s et
11,2 s après le début du `.webm`). **Solution retenue** : horodater l'ouverture
de chaque piste (epoch) et calculer chaque sous-titre en temps absolu, puis le
ramener au temps du `.webm`. C'est déjà implémenté et validé.

### 6.2 Noms des participants

Trois sources possibles :

1. **journal du signaling** (`Register user X … <session>`) — utilisé par le
   prototype, mais fragile (niveau de log, rotation) ;
2. **roster du signaling** : le client reçoit les participants avec
   `nextcloudSessionId` et `sessionId` — à condition de vérifier que le
   descripteur porte bien l'identité (patch à finir) ;
3. **base Talk** : `oc_talk_sessions` joint à `oc_talk_attendees` donne le nom
   d'affichage à partir de la session Nextcloud.

**Décision proposée** : 2 pour la correspondance session HPB → session
Nextcloud, 3 pour le nom. Aucune dépendance aux journaux.

### 6.3 Écriture dans les fichiers du lanceur

Le `.webm` est écrit par Talk dans `/var/www/html/data/<lanceur>/files/…`. Le
capture n'a pas à monter ce volume : le dépôt se fait par `kubectl exec` dans le
pod Nextcloud (écriture + `chown www-data` + `occ files:scan`), comme le
prototype. Alternative à étudier : WebDAV avec un mot de passe d'application
tiré du coffre, mais l'écriture dans l'espace d'un autre utilisateur n'est pas
triviale.

### 6.4 Modèles et image

- **Vosk** (darija, français) : déjà sur le PVC de l'ExApp ; le module les
  télécharge dans son propre PVC au premier démarrage (idempotent, vérifié
  fichier par fichier).
- **whisper** : modèle `small` int8 (~250 Mo) téléchargé dans le PVC ; `medium`
  (~750 Mo) en option.
- **ffmpeg** : binaire statique **dans l'image** (77 Mo), pas dans un `/tmp`.

### 6.5 CPU et ressources

Mesuré : whisper `small` int8 ≈ ×7–11 temps réel sur 8 threads. Pour une
réunion d'une heure à trois participants : ~20–30 min de calcul après l'appel.
Demandes par défaut : `cpu: 500m`/`4`, `memory: 1Gi`/`4Gi` ; `nice`-like via
`cpu_threads` configurable pour ne pas étouffer le signaling pendant un appel.

### 6.6 Plusieurs `.webm` par réunion

Talk redémarre l'enregistrement quand la composition change. Le transcript doit
être découpé par fichier : on connaît l'heure de départ (nom du fichier) et la
durée (métadonnées), donc chaque segment tombe dans un et un seul `.webm`.

## 7. Découpage et estimation

| Phase | Contenu | Durée |
|---|---|---|
| 1 | Image `build/capture/Dockerfile`, module `capture` (Install/State/Uninstall), RBAC, Deployment, PVC, détection de l'état | 5–7 j |
| 2 | Capture + finalisation dans l'image (client aiortc, whisper, ffmpeg embarqué), réglages console (modèle, sous-titres, salons) | 5–7 j |
| 3 | Dépôt Nextcloud, incrustation, découpage multi-`.webm`, noms par roster + base | 4–6 j |
| 4 | CI multi-arch + publication, docs, tests de charge (3–5 participants), migration du prototype | 3–5 j |

**Total : 3 à 4 semaines** pour un développeur, dont la moitié est déjà
prototypée.

## 8. Risques

| Risque | Impact | Parade |
|---|---|---|
| Protocole signaling non documenté | élevé | le client Python est éprouvé ; on le fige et on le teste à chaque montée de version de Talk |
| Modèle whisper lourd sur CPU | moyen | int8 + threads bornés + `small` par défaut ; `medium` en option ; la transcription tourne après l'appel |
| Dépendance à `exec` dans le pod Nextcloud | moyen | chemin déjà utilisé par `occ` ailleurs dans Ceffio ; à défaut, WebDAV |
| Silence en cas d'échec | élevé | `/healthz`, métriques, et un état dans la console (« dernier enregistrement : transcrit / échec ») |
| Dialectes (darija) | moyen | détection par piste + modèle `medium` en option ; documenter la limite |

## 9. Décisions à prendre

1. **Module séparé `capture`** (recommandé) ou extension du module `recording`
   existant ?
2. Modèle par défaut : `small` (rapide, français correct) ou `medium` (meilleur
   en arabe/darija, ~3× plus lent) ?
3. Les pistes `.opus` sont-elles conservées indéfiniment, ou supprimées au bout
   de N jours ?
4. Transcription des enregistrements déjà présents (rétroactif) ou seulement
   des nouveaux ?
5. Faut-il exposer la transcription dans Nextcloud (application dédiée) ou
   seulement en fichiers à côté du `.webm` ?
