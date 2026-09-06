# Dossier de transfert complet — MySuite

## 0. État réel du projet au moment du transfert

Le projet **MySuite** a été conçu architecturalement et fonctionnellement en détail, mais **aucun dépôt Git complet ni code source exécutable n’a encore été produit dans cette conversation**.

Ce qui existe déjà :

- architecture cible détaillée ;
- choix de composants ;
- stratégie de packaging ;
- modèle de déploiement K3s/Kubernetes ;
- dimensionnement ;
- logique de CLI ;
- logique d’Operator Kubernetes ;
- CRD cible ;
- commandes utilisateur prévues ;
- profils de déploiement ;
- stratégie de backup / restore ;
- stratégie d’upgrade ;
- organisation du repository ;
- snippets YAML, shell et pseudo-code ;
- roadmap de développement ;
- benchmark de projets similaires.

Ce qui **n’existe pas encore sous forme de code réellement créé/testé** :

- binaire Go `mysuite` ;
- repository Git ;
- Operator Go ;
- CRDs compilées ;
- Helm charts fonctionnels ;
- scripts d’installation ;
- images OCI ;
- CI/CD ;
- Admin UI ;
- API backend ;
- bundle air-gap.

Le repreneur doit donc considérer ce document comme une **spécification technique complète de départ**, et non comme la documentation d’un produit déjà compilable.

---

# 1. Objectif du projet et problème résolu

MySuite vise à fournir une **suite collaborative souveraine, open source, auto-hébergée et packagée**, capable de remplacer une grande partie de Microsoft 365 / Teams.

Le produit doit permettre à une PME, administration ou organisation de déployer en une seule commande :

- identité et SSO ;
- fichiers ;
- documents collaboratifs ;
- chat ;
- visioconférence ;
- e-mail ;
- calendrier ;
- contacts ;
- supervision ;
- sauvegardes ;
- mises à jour.

L’expérience visée est :

```bash
curl -sfL https://install.mysuite.io | sudo sh
```

Le système doit pouvoir fonctionner :

- sur une seule VM avec K3s ;
- sur un cluster K3s multi-nœuds ;
- sur RKE2 ;
- sur Kubernetes existant ;
- à terme sur OpenShift, EKS, AKS et GKE.

La valeur du projet n’est pas de réécrire Nextcloud, Matrix, Keycloak ou Jitsi, mais de créer une **couche produit unifiée** autour de ces projets :

- installation ;
- configuration ;
- SSO ;
- provisioning ;
- lifecycle ;
- sécurité ;
- monitoring ;
- backup ;
- restore ;
- upgrade ;
- diagnostic ;
- packaging air-gap.

---

# 2. Positionnement produit

## 2.1 Expérience utilisateur cible

Installation :

```bash
curl -sfL https://install.mysuite.io | sudo sh
```

Puis :

```text
MySuite Installer

Domain:
company.fr

Profile:
Business 50

Mail:
Yes

Office:
Yes

Video:
Yes

Monitoring:
Yes
```

Résultat attendu :

```text
✓ K3s
✓ Storage
✓ Traefik
✓ TLS
✓ PostgreSQL
✓ Redis
✓ Keycloak
✓ Files
✓ Office
✓ Matrix
✓ Element
✓ Jitsi
✓ Mail
✓ Monitoring
✓ Backup

MySuite ready.
```

URLs produites :

```text
https://admin.company.fr
https://auth.company.fr
https://cloud.company.fr
https://office.company.fr
https://chat.company.fr
https://matrix.company.fr
https://meet.company.fr
https://mail.company.fr
```

---

# 3. Stack technique retenue

## 3.1 Langage principal

### Go

Go est le langage retenu pour :

- `mysuite` CLI ;
- `mysuite-operator` ;
- API backend éventuelle ;
- outils de diagnostic ;
- orchestration des installations ;
- génération de configuration ;
- logique de lifecycle.

Aucune version Go précise n’a encore été figée.

Recommandation de reprise :

```text
Go 1.24+ ou version stable supportée au moment de l’implémentation
```

Ne pas fixer cette version sans validation CI.

---

# 4. Runtime Kubernetes

## Défaut

```text
K3s
```

Utilisation :

- mode all-in-one ;
- petite entreprise ;
- edge ;
- appliance ;
- déploiement rapide.

## Alternative entreprise

```text
RKE2
```

Utilisation :

- HA ;
- exigences sécurité plus élevées ;
- environnement entreprise ;
- clusters plus importants.

## Bring Your Own Kubernetes

Prévoir :

```bash
mysuite install --existing-cluster
```

Cibles prévues :

```text
K3s
RKE2
kubeadm
OpenShift
EKS
AKS
GKE
```

---

# 5. Stack applicative

## 5.1 Identity

```text
Keycloak
```

Fonctions :

- SSO ;
- OIDC ;
- OAuth2 ;
- SAML ;
- MFA ;
- groupes ;
- rôles ;
- LDAP/AD à terme.

---

## 5.2 Base de données

```text
PostgreSQL
```

Gestion Kubernetes envisagée :

```text
CloudNativePG
```

Bases séparées :

```text
keycloak
nextcloud
synapse
mysuite
```

Éventuellement :

```text
sogo
```

si utilisé.

---

## 5.3 Cache

```text
Redis
```

Usage principal :

- cache ;
- sessions ;
- locking Nextcloud.

---

## 5.4 Fichiers

Provider v1 envisagé :

```text
Nextcloud
```

Alternative future :

```text
OpenCloud
```

---

## 5.5 Office

Provider principal :

```text
ONLYOFFICE
```

Alternatives futures :

```text
Collabora
CryptPad
```

---

## 5.6 Chat

Backend :

```text
Matrix Synapse
```

Frontend :

```text
Element Web
```

---

## 5.7 Visioconférence

```text
Jitsi
```

Composants :

```text
Jitsi Web
Prosody
Jicofo
Jitsi Videobridge
```

---

## 5.8 Mail

Deux candidats ont été discutés.

### Candidat préféré architecturalement

```text
Stalwart
```

Raisons :

- architecture moderne ;
- SMTP ;
- IMAP ;
- JMAP ;
- CalDAV ;
- CardDAV ;
- WebDAV ;
- simplification de la stack mail.

### Alternative mature Kubernetes

```text
Mailu
```

Un POC comparatif doit décider lequel est retenu en v1.

Ne pas intégrer les deux simultanément en première version.

---

# 6. Ingress / TLS / DNS

## Ingress

```text
Traefik
```

## TLS

```text
cert-manager
```

Providers prévus :

```text
Let's Encrypt HTTP-01
Let's Encrypt DNS-01
Private CA
```

## DNS futur

```text
ExternalDNS
```

optionnel.

---

# 7. Observabilité

## Metrics

```text
Prometheus
```

## Dashboards

```text
Grafana
```

## Alertes

```text
Alertmanager
```

## Logs

Préférence actuelle :

```text
Grafana Alloy
Loki
Grafana
```

---

# 8. GitOps

Option future :

```text
Argo CD
```

Activation envisagée :

```bash
mysuite install --gitops
```

---

# 9. Secrets

MVP :

```text
Kubernetes Secrets
```

Évolutions :

```text
Sealed Secrets
External Secrets
Vault
```

---

# 10. Stockage

Providers prévus :

```text
local-path
Longhorn
NFS
Synology
Ceph
external CSI
S3
MinIO
```

Le produit ne doit dépendre d’aucun backend unique.

---

# 11. Architecture générale

```text
                         INTERNET
                            │
                      Firewall / NAT
                            │
                         Traefik
                            │
                       cert-manager
                            │
        ┌───────────────────┼────────────────────┐
        │                   │                    │
        ▼                   ▼                    ▼
      Identity        Collaboration              Mail
        │                   │                    │
     Keycloak         ┌─────┼─────────┐       Stalwart
                      │     │         │
                      ▼     ▼         ▼
                  Nextcloud Office   Matrix
                           │          │
                       ONLYOFFICE   Element
                                      │
                                    Jitsi

                            │
                            ▼
                           Data
                            │
                 ┌──────────┼─────────┐
                 │          │         │
                 ▼          ▼         ▼
            PostgreSQL    Redis     Storage
                            │
                            ▼
                    Observability
                            │
                Prometheus / Grafana
                         / Loki
```

---

# 12. Architecture logique du produit

```text
                         MySuite
                            │
              ┌─────────────┴──────────────┐
              │                            │
         MySuite CLI                   Admin UI
              │                            │
              └─────────────┬──────────────┘
                            │
                     MySuite Operator
                            │
                      Kubernetes API
                            │
                   Helm / Kubernetes
                            │
                Applications upstream
```

---

# 13. Structure cible du repository

```text
mysuite/
│
├── cmd/
│   └── mysuite/
│
├── internal/
│   ├── bootstrap/
│   ├── cluster/
│   ├── config/
│   ├── doctor/
│   ├── backup/
│   ├── restore/
│   ├── upgrade/
│   ├── dns/
│   └── users/
│
├── api/
│   └── v1alpha1/
│
├── operator/
│   ├── controllers/
│   ├── reconciler/
│   └── main.go
│
├── charts/
│   ├── mysuite/
│   ├── identity/
│   ├── data/
│   ├── files/
│   ├── office/
│   ├── chat/
│   ├── video/
│   ├── mail/
│   └── observability/
│
├── manifests/
│
├── profiles/
│   ├── small.yaml
│   ├── business-50.yaml
│   ├── business-100.yaml
│   └── enterprise-ha.yaml
│
├── installer/
│   └── install.sh
│
├── airgap/
│
├── scripts/
│
├── tests/
│   ├── integration/
│   └── e2e/
│
├── docs/
│
├── Makefile
├── go.mod
├── go.sum
└── README.md
```

---

# 14. Description de chaque module

## `cmd/mysuite`

Entrée principale CLI.

Doit exposer :

```text
mysuite install
mysuite init
mysuite status
mysuite doctor
mysuite backup
mysuite restore
mysuite upgrade
mysuite users
mysuite dns
mysuite logs
mysuite uninstall
```

---

## `internal/bootstrap`

Responsable de :

- détection OS ;
- détection CPU ;
- détection RAM ;
- détection disque ;
- architecture `amd64` / `arm64` ;
- téléchargement des binaires ;
- checksums ;
- installation K3s ;
- préparation de la machine.

---

## `internal/cluster`

Responsable de :

- K3s ;
- RKE2 ;
- cluster existant ;
- kubeconfig ;
- détection StorageClass ;
- validation Kubernetes ;
- preflight.

---

## `internal/config`

Responsable de :

```text
/etc/mysuite/config.yaml
```

Lecture/écriture/validation.

---

## `internal/doctor`

Diagnostic de :

```text
system
kubernetes
storage
dns
tls
database
identity
files
office
matrix
video
mail
backup
```

---

## `internal/backup`

Orchestration des backups.

---

## `internal/restore`

Restore complet.

---

## `internal/upgrade`

Gestion de :

- versions ;
- compatibilité ;
- preflight ;
- upgrade ;
- rollback.

---

## `internal/dns`

Validation :

```text
A
AAAA
MX
TXT
SPF
DKIM
DMARC
PTR
```

---

## `internal/users`

Provisioning utilisateur :

```text
Keycloak
Nextcloud
Matrix
mailbox
```

---

# 15. Configuration principale

Chemin prévu :

```text
/etc/mysuite/config.yaml
```

Exemple :

```yaml
domain: company.fr

profile: business-50

runtime:
  type: k3s

features:
  mail: true
  office: true
  video: true
  monitoring: true
  gitops: false

identity:
  provider: keycloak

files:
  provider: nextcloud

office:
  provider: onlyoffice

chat:
  provider: matrix

video:
  provider: jitsi

mail:
  provider: stalwart

database:
  provider: cloudnativepg

cache:
  provider: redis

storage:
  provider: local
  class: local-path

tls:
  provider: letsencrypt
  email: admin@company.fr

backup:
  provider: local
```

---

# 16. CRD principale prévue

```yaml
apiVersion: platform.mysuite.io/v1alpha1
kind: Suite
metadata:
  name: production
spec:
  domain: company.fr

  profile: business-50

  identity:
    provider: keycloak

  files:
    provider: nextcloud

  office:
    provider: onlyoffice

  chat:
    provider: matrix

  video:
    provider: jitsi

  mail:
    provider: stalwart

  database:
    provider: cloudnativepg

  cache:
    provider: redis

  storage:
    provider: local

  monitoring:
    enabled: true

  backup:
    enabled: true
```

---

# 17. États de l’Operator

Le Controller doit exposer des conditions :

```text
Installing
Ready
Degraded
Upgrading
BackupRunning
RestoreRunning
Error
```

Principe :

```text
desired state
      │
      ▼
   reconcile
      │
      ▼
 actual state
```

Le reconcile doit être idempotent.

---

# 18. Namespace Kubernetes prévus

```text
mysuite-system
mysuite-identity
mysuite-data
mysuite-files
mysuite-office
mysuite-chat
mysuite-video
mysuite-mail
mysuite-observability
```

Ajouter :

- labels standards ;
- quotas ;
- LimitRange ;
- NetworkPolicies.

---

# 19. Labels Kubernetes

Standard envisagé :

```text
app.kubernetes.io/part-of=mysuite
app.kubernetes.io/managed-by=mysuite-operator
```

Compléter avec :

```text
app.kubernetes.io/name
app.kubernetes.io/component
app.kubernetes.io/version
```

---

# 20. Helm

Créer un umbrella chart :

```text
charts/mysuite
```

Structure :

```text
charts/mysuite/
├── Chart.yaml
├── values.yaml
├── templates/
└── charts/
```

Valeurs principales :

```yaml
global:
  domain: company.fr
  storageClass: local-path

identity:
  enabled: true

files:
  enabled: true

office:
  enabled: true

chat:
  enabled: true

video:
  enabled: true

mail:
  enabled: true

observability:
  enabled: true
```

---

# 21. Bootstrap d’installation

Commande publique cible :

```bash
curl -sfL https://install.mysuite.io | sudo sh
```

Le script shell doit rester minimal.

Flux :

```text
install.sh
    │
    ├── detect OS
    ├── detect arch
    ├── download mysuite CLI
    ├── verify checksum/signature
    │
    └── execute mysuite bootstrap
```

Le script ne doit pas contenir la logique métier complète.

---

# 22. Commandes CLI prévues

## Installation

```bash
mysuite install
```

ou :

```bash
mysuite install \
  --domain company.fr \
  --profile business-50
```

---

## K3s

```bash
mysuite install --runtime k3s
```

---

## RKE2

```bash
mysuite install --runtime rke2
```

---

## Cluster existant

```bash
mysuite install --existing-cluster
```

---

## État

```bash
mysuite status
```

Sortie cible :

```text
MySuite 1.0.0

Platform
✓ Kubernetes
✓ DNS
✓ Storage
✓ Certificates

Identity
✓ Keycloak

Data
✓ PostgreSQL
✓ Redis

Collaboration
✓ Nextcloud
✓ ONLYOFFICE
✓ Matrix
✓ Element
✓ Jitsi

Mail
✓ Stalwart

Observability
✓ Prometheus
✓ Grafana
✓ Loki

Status: HEALTHY
```

---

# 23. Diagnostic

Commande :

```bash
mysuite doctor
```

Modules :

```text
system
kubernetes
storage
dns
tls
database
identity
files
office
matrix
video
mail
backup
```

Support bundle :

```bash
mysuite doctor --bundle
```

Produit :

```text
mysuite-support-XXXXXXXX.tar.gz
```

Doit contenir :

- versions ;
- status Kubernetes ;
- events ;
- logs nettoyés ;
- ressources ;
- CRDs ;
- health checks.

Ne doit contenir aucun secret.

---

# 24. Provisioning utilisateur

Commande prévue :

```bash
mysuite users add jean@company.fr
```

Workflow :

```text
MySuite
  │
  ├── Keycloak
  ├── Nextcloud
  ├── Matrix
  └── Mailbox
```

Source de vérité prévue :

```text
Keycloak
```

---

# 25. Groupes

Groupes exemples :

```text
admins
users
direction
rh
finance
support
commercial
technique
```

Mapping futur :

```text
Keycloak Groups
      │
      ├── Nextcloud Groups
      ├── Matrix Spaces
      └── Mail aliases
```

---

# 26. Keycloak

Realm :

```text
mysuite
```

Clients :

```text
nextcloud
matrix
admin-ui
mail
grafana
```

Fonctions :

```text
OIDC
MFA
password policies
email verification
groups
roles
```

---

# 27. PostgreSQL / CloudNativePG

All-in-one :

```text
1 instance PostgreSQL
```

HA :

```text
pg-primary
pg-replica-1
pg-replica-2
```

Chaque application possède :

- sa DB ;
- son user ;
- son secret.

Exemple :

```text
nextcloud / nextcloud_user
keycloak / keycloak_user
synapse / synapse_user
mysuite / mysuite_user
```

---

# 28. Redis

MVP :

```text
1 instance
```

Usages :

```text
Nextcloud locking
cache
sessions
```

HA seulement pour profils enterprise.

---

# 29. Nextcloud

Composants :

```text
Nextcloud
PostgreSQL
Redis
PVC data
```

Configuration :

```text
trusted_domains
trusted_proxies
cron
OIDC
Redis locking
SMTP
ONLYOFFICE connector
```

Fonctions :

```text
Files
Calendar
Contacts
sharing
versioning
quotas
WebDAV
desktop sync
mobile sync
```

---

# 30. ONLYOFFICE

Configuration :

```text
JWT
Nextcloud connector
HTTPS
resource limits
```

Le secret JWT doit être généré automatiquement par MySuite.

Workflow :

```text
Nextcloud
   │
   ▼
document.docx
   │
   ▼
ONLYOFFICE
```

Tests :

```text
DOCX
XLSX
PPTX
multi-user editing
save
reload
```

---

# 31. Matrix / Synapse

Configuration :

```text
PostgreSQL
media PVC
OIDC Keycloak
```

Default :

```yaml
matrix:
  federation: false
```

Option :

```yaml
matrix:
  federation: true
```

Registration publique désactivée par défaut.

---

# 32. Element

Configuration générée :

```json
{
  "default_server_config": {
    "m.homeserver": {
      "base_url": "https://matrix.company.fr"
    }
  }
}
```

Prévoir branding :

```text
logo
product name
support URL
colors
```

---

# 33. Jitsi

Composants :

```text
Jitsi Web
Prosody
Jicofo
Jitsi Videobridge
```

Port critique :

```text
UDP 10000
```

Options envisagées :

```text
LoadBalancer
hostNetwork
IP dédiée
```

À éviter autant que possible :

```text
hostNetwork
```

sauf si nécessaire.

---

# 34. Mail

## POC 1 — Stalwart

Ports :

```text
25
465
587
993
```

Protocoles :

```text
SMTP
IMAP
JMAP
CalDAV
CardDAV
WebDAV
```

Besoin :

- PVC mail ;
- TLS ;
- DNS ;
- PTR ;
- SPF ;
- DKIM ;
- DMARC.

---

## POC 2 — Mailu

Critères comparatifs :

```text
Kubernetes maturity
upgrade
backup
SSO
admin UI
webmail
anti-spam
resource usage
observability
```

Décision finale toujours à prendre.

---

# 35. DNS mail

Commande prévue :

```bash
mysuite mail dns
```

ou :

```bash
mysuite dns status
```

Doit vérifier :

```text
A
AAAA
MX
PTR
SPF
DKIM
DMARC
```

---

# 36. Traefik

Entrées :

```text
:80
:443
```

Routes :

```text
admin.company.fr
auth.company.fr
cloud.company.fr
office.company.fr
chat.company.fr
matrix.company.fr
meet.company.fr
mail.company.fr
```

Sécurité envisagée :

```text
HTTPS redirect
HSTS
trusted proxies
rate limiting
access logging
```

---

# 37. cert-manager

Configuration prévue :

```yaml
tls:
  provider: letsencrypt
  email: admin@company.fr
```

Modes :

```text
HTTP-01
DNS-01
Private CA
```

---

# 38. Monitoring

Prometheus doit collecter :

```text
node metrics
pod metrics
kube-state-metrics
PostgreSQL metrics
Keycloak metrics
Jitsi metrics
application health
```

Dashboards Grafana :

```text
Overview
Kubernetes
Storage
Database
Users
Mail
Video
Backup
```

---

# 39. Logs

Pipeline :

```text
Pods
  │
  ▼
Grafana Alloy
  │
  ▼
Loki
  │
  ▼
Grafana
```

Labels :

```text
namespace
app
pod
severity
tenant
```

Rétention proposée :

```text
small: 7 jours
business: 30 jours
enterprise: 90 jours
```

---

# 40. Alerting

Alertes minimum :

```text
disk > 80%
certificate expiry
PostgreSQL down
pod CrashLoopBackOff
SMTP unavailable
Jitsi unavailable
backup failure
node NotReady
```

Canaux :

```text
email
webhook
Matrix
```

---

# 41. Backup

Commande :

```bash
mysuite backup
```

Contenu :

```text
PostgreSQL
Nextcloud data
Matrix media
Mail
Keycloak config
MySuite config
CRDs
critical secrets
```

Destinations :

```text
local
NFS
NAS
S3
MinIO
```

Objet Kubernetes envisagé :

```yaml
apiVersion: platform.mysuite.io/v1alpha1
kind: SuiteBackup
metadata:
  name: backup-example
spec:
  destination: s3
```

---

# 42. Restore

Commande :

```bash
mysuite restore <backup>
```

Ordre :

```text
validate backup
↓
maintenance/read-only mode
↓
restore DB
↓
restore PVC/data
↓
restore config
↓
restart applications
↓
health checks
```

---

# 43. Upgrade

Version manifest :

```yaml
mysuite: 1.0.0

kubernetes:
  k3s: "<version-validée>"

components:
  keycloak: "<version-validée>"
  nextcloud: "<version-validée>"
  onlyoffice: "<version-validée>"
  matrix: "<version-validée>"
  element: "<version-validée>"
  jitsi: "<version-validée>"
  stalwart: "<version-validée>"
```

Important :

**aucune version précise n’a encore été figée dans le projet.**

Ne pas inventer de versions.

Commande :

```bash
mysuite upgrade
```

Ordre :

```text
compatibility check
↓
preflight
↓
backup
↓
CRD/operator
↓
database migrations
↓
applications
↓
health checks
```

---

# 44. Rollback

Commande prévue :

```bash
mysuite rollback
```

Attention :

```text
helm rollback
```

ne suffit pas lorsqu’une migration DB a été appliquée.

Le système doit versionner :

```text
application version
database schema version
backup restore point
```

---

# 45. Profils matériels

## Small

10 à 20 utilisateurs :

```text
8 vCPU
24–32 Go RAM
500 Go stockage
```

---

## Business 50

Configuration recommandée :

```text
16 vCPU
64 Go RAM
500 Go NVMe système
2 To données
1 Gb/s réseau
```

---

## Business 100

```text
24 vCPU
96 Go RAM
4 To données
```

---

## Enterprise HA

```text
3+ nodes
HA PostgreSQL
distributed storage
multiple ingress replicas
multiple JVB
anti-affinity
PDB
```

---

# 46. All-in-One

Architecture cible pour 50 utilisateurs :

```text
1 VM
└── Linux
    └── K3s
        ├── Traefik
        ├── cert-manager
        ├── Keycloak
        ├── PostgreSQL
        ├── Redis
        ├── Nextcloud
        ├── ONLYOFFICE
        ├── Matrix
        ├── Element
        ├── Jitsi
        ├── Stalwart/Mailu
        ├── Prometheus
        ├── Grafana
        └── Loki
```

---

# 47. Répartition RAM indicative Business 50

Ces chiffres sont des **budgets de conception**, pas des mesures de benchmark.

```text
K3s + Linux                 ~3 Go
PostgreSQL                  ~6 Go
Redis                       ~1–2 Go
Keycloak                    ~2 Go
Nextcloud                   ~6–8 Go
ONLYOFFICE                  ~6 Go
Matrix / Element            ~3–4 Go
Jitsi                       ~8 Go
Mail                        ~4–6 Go
Observability               ~4–6 Go
Marge/cache                 ~10 Go
```

---

# 48. Stockage All-in-One

Prévoir deux classes logiques.

## `fast`

NVMe :

```text
PostgreSQL
Redis
Keycloak
```

## `data`

Disque data :

```text
Nextcloud
Matrix media
Mail
documents
backups locaux
```

---

# 49. NetworkPolicy

Principe :

```text
default deny
```

Puis autorisations.

Exemples :

```text
Nextcloud → PostgreSQL
Nextcloud → Redis
Nextcloud → ONLYOFFICE

Keycloak → PostgreSQL

Synapse → PostgreSQL

Admin UI → MySuite API
```

---

# 50. Pod Security

Cible :

```text
restricted
```

Exceptions seulement si nécessaires.

Éviter :

```text
privileged
hostPath
hostNetwork
```

---

# 51. Supply-chain security

Chaque release doit :

```text
pin image digests
generate SBOM
scan images
sign images
verify signatures
```

Outils envisagés :

```text
Syft
Grype
Trivy
Cosign
```

---

# 52. Air-gap

Bundle cible :

```text
mysuite-1.0.0-airgap-amd64.tar.zst
```

et :

```text
mysuite-1.0.0-airgap-arm64.tar.zst
```

Contenu :

```text
bin/
  k3s
  mysuite
  helm

images/
  *.tar

charts/

manifests/

checksums/

sbom/

docs/
```

Installation :

```bash
tar xf mysuite-1.0.0-airgap-amd64.tar.zst
cd mysuite-1.0.0
sudo ./install.sh
```

---

# 53. Registry locale

Pour multi-node air-gap :

```text
registry.mysuite.local
```

K3s doit être configuré via :

```text
/etc/rancher/k3s/registries.yaml
```

---

# 54. Admin UI

Pas encore développée.

Fonctions prévues :

```text
status
health
users
groups
storage
backup
restore
updates
DNS
mail health
certificates
logs
alerts
```

URL :

```text
admin.company.fr
```

---

# 55. API MySuite

Pas encore développée.

API prévue :

```text
GET /api/v1/status
GET /api/v1/users
POST /api/v1/users
DELETE /api/v1/users/{id}

GET /api/v1/backups
POST /api/v1/backups

POST /api/v1/restore
POST /api/v1/upgrade

GET /api/v1/doctor
GET /api/v1/dns
```

Authentification :

```text
Keycloak OIDC
```

Rôles :

```text
admin
operator
auditor
```

---

# 56. Benchmark externe étudié

Projets considérés comme références :

```text
openDesk
Mothertree OSS
Nextcloud AIO
Nextcloud Helm
OpenCloud
ownCloud oCIS
CryptPad Helm
Mailu Helm
Stalwart
Jitsi Kubernetes
Matrix Helm
Sovereign Cloud Stack
```

---

# 57. Inspirations principales

## openDesk

À étudier pour :

- suite souveraine ;
- Kubernetes ;
- intégration multi-app ;
- Helm/Helmfile ;
- packaging institutionnel.

## Mothertree

À étudier pour :

- multi-tenancy ;
- Keycloak ;
- Matrix ;
- Nextcloud ;
- Jitsi ;
- mail ;
- namespaces tenant.

## Mailu Helm

À étudier pour :

- mail Kubernetes natif.

## Stalwart

À étudier pour :

- mail moderne ;
- réduction du nombre de composants.

## OpenCloud

À étudier pour :

- alternative moderne à Nextcloud ;
- architecture microservices.

---

# 58. Décisions architecturales et raisons

## Décision : Kubernetes comme couche centrale

Pourquoi :

- reproductibilité ;
- portability ;
- déclaratif ;
- self-healing ;
- packaging ;
- Helm ;
- Operator ;
- montée vers HA.

---

## Décision : K3s par défaut

Pourquoi :

- léger ;
- simple ;
- bon pour single-node ;
- bon pour appliance ;
- Kubernetes compatible.

---

## Décision : RKE2 en mode entreprise

Pourquoi :

- sécurité ;
- HA ;
- positionnement enterprise.

---

## Décision : Go pour CLI et Operator

Pourquoi :

- écosystème Kubernetes ;
- binaire statique ;
- performance ;
- distribution simple ;
- Kubebuilder/controller-runtime.

---

## Décision : ne pas forker toutes les applications

Pourquoi :

Forker :

```text
Nextcloud
Keycloak
Matrix
Jitsi
Stalwart
```

créerait une charge de maintenance énorme.

MySuite doit être la couche :

```text
integration
automation
lifecycle
security
UX
```

---

## Décision : Operator + Helm

Helm :

- packaging ;
- templating ;
- installation.

Operator :

- lifecycle ;
- reconciliation ;
- état ;
- automatisation ;
- health.

---

## Décision : Keycloak source de vérité identité

Pourquoi :

- SSO ;
- OIDC ;
- MFA ;
- groupes ;
- extensibilité LDAP/AD.

---

## Décision : CloudNativePG

Pourquoi :

- PostgreSQL natif Kubernetes ;
- backup ;
- HA ;
- opérateur mature.

---

## Décision : séparation provider

Exemples :

```yaml
files:
  provider: nextcloud
```

ou :

```yaml
files:
  provider: opencloud
```

Même logique pour :

```text
mail
office
storage
```

Objectif :

ne pas bloquer MySuite sur un fournisseur.

---

# 59. Ce qui n’est PAS encore décidé définitivement

À trancher par POC :

```text
Stalwart vs Mailu
Nextcloud vs OpenCloud à long terme
ONLYOFFICE vs autre provider futur
storage local-path vs Longhorn en défaut multi-node
Traefik natif K3s vs Traefik géré explicitement
mode de déploiement JVB
framework Admin UI
framework CLI exact : Cobra ou autre
framework Operator : Kubebuilder recommandé
```

---

# 60. Fichiers exacts à créer en premier

## 60.1 `go.mod`

À créer :

```go
module github.com/<organisation>/mysuite

go 1.24
```

La version devra être ajustée à la version stable choisie.

---

# 61. `cmd/mysuite/main.go`

Première base :

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func execute() error {
	fmt.Println("MySuite")
	return nil
}
```

Ce code n’a pas encore été exécuté ni validé.

---

# 62. CLI recommandée avec Cobra

Ajouter comme dépendance :

```bash
go get github.com/spf13/cobra
```

Structure :

```text
cmd/
├── root.go
├── install.go
├── status.go
├── doctor.go
├── backup.go
├── restore.go
├── upgrade.go
├── users.go
└── dns.go
```

---

# 63. `cmd/mysuite/root.go`

Base proposée :

```go
package main

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "mysuite",
	Short: "MySuite collaborative platform manager",
}

func execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(
		installCmd,
		statusCmd,
		doctorCmd,
		backupCmd,
		restoreCmd,
		upgradeCmd,
	)
}
```

---

# 64. `cmd/mysuite/install.go`

Structure de départ :

```go
package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	domain  string
	profile string
	runtime string
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install MySuite",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf(
			"Installing MySuite domain=%s profile=%s runtime=%s\n",
			domain,
			profile,
			runtime,
		)

		return nil
	},
}

func init() {
	installCmd.Flags().StringVar(&domain, "domain", "", "Base domain")
	installCmd.Flags().StringVar(&profile, "profile", "small", "Deployment profile")
	installCmd.Flags().StringVar(&runtime, "runtime", "k3s", "Kubernetes runtime")
}
```

---

# 65. `installer/install.sh`

Première version proposée :

```bash
#!/usr/bin/env sh

set -eu

INSTALL_URL="${MYSUITE_RELEASE_URL:-https://releases.mysuite.io}"

ARCH="$(uname -m)"

case "$ARCH" in
  x86_64)
    ARCH="amd64"
    ;;
  aarch64|arm64)
    ARCH="arm64"
    ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"

if [ "$OS" != "linux" ]; then
  echo "Only Linux is currently supported." >&2
  exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

BIN="$TMP_DIR/mysuite"

curl -fsSL \
  "$INSTALL_URL/latest/mysuite-linux-$ARCH" \
  -o "$BIN"

chmod +x "$BIN"

install -m 0755 "$BIN" /usr/local/bin/mysuite

exec /usr/local/bin/mysuite install "$@"
```

Important :

- ce script n’a pas encore de checksum ;
- pas de signature ;
- pas de version pinning ;
- pas de retry ;
- pas de proxy support ;
- pas de air-gap.

À compléter avant production.

---

# 66. `profiles/business-50.yaml`

```yaml
name: business-50

capacity:
  users: 50

requirements:
  cpu: 16
  memory: 64Gi
  systemDisk: 500Gi
  dataDisk: 2Ti

resources:
  keycloak:
    memory: 2Gi

  postgres:
    memory: 6Gi

  redis:
    memory: 2Gi

  nextcloud:
    memory: 8Gi

  onlyoffice:
    memory: 6Gi

  matrix:
    memory: 4Gi

  jitsi:
    memory: 8Gi

  mail:
    memory: 6Gi

  observability:
    memory: 6Gi
```

Ces valeurs restent des budgets initiaux à benchmarker.

---

# 67. `profiles/small.yaml`

```yaml
name: small

capacity:
  users: 20

requirements:
  cpu: 8
  memory: 32Gi
  systemDisk: 500Gi
```

---

# 68. `profiles/business-100.yaml`

```yaml
name: business-100

capacity:
  users: 100

requirements:
  cpu: 24
  memory: 96Gi
  dataDisk: 4Ti
```

---

# 69. `config/example.yaml`

```yaml
domain: company.fr

profile: business-50

runtime:
  type: k3s

features:
  mail: true
  office: true
  video: true
  monitoring: true

identity:
  provider: keycloak

files:
  provider: nextcloud

office:
  provider: onlyoffice

chat:
  provider: matrix

video:
  provider: jitsi

mail:
  provider: stalwart

storage:
  provider: local

tls:
  provider: letsencrypt
```

---

# 70. CRD à créer

Chemin :

```text
api/v1alpha1/suite_types.go
```

Modèle conceptuel :

```go
type SuiteSpec struct {
	Domain  string `json:"domain"`
	Profile string `json:"profile"`

	Identity ProviderSpec `json:"identity"`
	Files    ProviderSpec `json:"files"`
	Office   ProviderSpec `json:"office"`
	Chat     ProviderSpec `json:"chat"`
	Video    ProviderSpec `json:"video"`
	Mail     ProviderSpec `json:"mail"`
}

type ProviderSpec struct {
	Provider string `json:"provider"`
}
```

Statut :

```go
type SuiteStatus struct {
	Phase      string      `json:"phase,omitempty"`
	Conditions []Condition `json:"conditions,omitempty"`
}
```

Recommandation :

utiliser Kubebuilder plutôt que coder les CRDs entièrement à la main.

---

# 71. Operator

Commandes de bootstrap recommandées :

```bash
kubebuilder init \
  --domain mysuite.io \
  --repo github.com/<organisation>/mysuite
```

Puis :

```bash
kubebuilder create api \
  --group platform \
  --version v1alpha1 \
  --kind Suite
```

---

# 72. Helm chart

Initialisation :

```bash
helm create charts/mysuite
```

Puis remplacer les templates générés par la structure réelle.

---

# 73. `charts/mysuite/Chart.yaml`

Base proposée :

```yaml
apiVersion: v2

name: mysuite

description: MySuite collaborative platform

type: application

version: 0.1.0

appVersion: "0.1.0"
```

---

# 74. `charts/mysuite/values.yaml`

Base :

```yaml
global:
  domain: example.com
  storageClass: local-path

identity:
  enabled: true
  provider: keycloak

files:
  enabled: true
  provider: nextcloud

office:
  enabled: true
  provider: onlyoffice

chat:
  enabled: true
  provider: matrix

video:
  enabled: true
  provider: jitsi

mail:
  enabled: false
  provider: stalwart

observability:
  enabled: true
```

---

# 75. Makefile initial

```make
.PHONY: build test lint helm-lint

build:
	go build -o bin/mysuite ./cmd/mysuite

test:
	go test ./...

lint:
	go vet ./...

helm-lint:
	helm lint charts/mysuite
```

---

# 76. Commandes de démarrage développeur

## Prérequis

Installer :

```text
Go
Git
Docker
kubectl
Helm
K3d ou K3s
Kubebuilder
```

---

# 77. Initialisation repo

```bash
git init mysuite
cd mysuite
```

---

# 78. Initialisation Go

```bash
go mod init github.com/<organisation>/mysuite
```

---

# 79. Dépendance Cobra

```bash
go get github.com/spf13/cobra
```

---

# 80. Build

```bash
go build -o bin/mysuite ./cmd/mysuite
```

---

# 81. Run

```bash
./bin/mysuite --help
```

Puis :

```bash
./bin/mysuite install \
  --domain example.local \
  --profile business-50
```

---

# 82. Tests Go

```bash
go test ./...
```

---

# 83. Helm lint

```bash
helm lint charts/mysuite
```

---

# 84. Helm template

```bash
helm template mysuite charts/mysuite
```

---

# 85. Cluster local de développement

Option rapide :

```bash
k3d cluster create mysuite-dev
```

Vérifier :

```bash
kubectl get nodes
```

---

# 86. Installation locale Helm

```bash
helm upgrade \
  --install \
  mysuite \
  charts/mysuite \
  --namespace mysuite-system \
  --create-namespace
```

---

# 87. Tests E2E prévus

À mettre dans :

```text
tests/e2e
```

Scénarios :

```text
create user
login Keycloak
login Nextcloud
upload file
open ONLYOFFICE doc
save document
login Element
send Matrix message
create Jitsi meeting
send email
receive email
create calendar event
backup
restore
upgrade
```

Framework envisagé :

```text
Playwright
```

pour la partie navigateur.

---

# 88. CI/CD cible

Pipeline :

```text
lint
↓
unit tests
↓
helm lint
↓
YAML validation
↓
build CLI
↓
build operator
↓
build images
↓
security scan
↓
SBOM
↓
integration cluster
↓
E2E
↓
sign
↓
publish
```

---

# 89. Registry OCI

Prévu :

```text
ghcr.io/<organisation>/mysuite-cli
ghcr.io/<organisation>/mysuite-operator
ghcr.io/<organisation>/mysuite-admin
```

Charts :

```text
oci://ghcr.io/<organisation>/charts/mysuite
```

---

# 90. Variables d’environnement nécessaires

Aucun secret réel n’a été défini.

Variables possibles pour l’installateur :

```text
MYSUITE_RELEASE_URL
MYSUITE_VERSION
MYSUITE_REGISTRY
MYSUITE_DOMAIN
MYSUITE_PROFILE
MYSUITE_RUNTIME
```

---

# 91. Secrets runtime à générer

Ne jamais mettre en clair dans Git :

```text
PostgreSQL passwords
Keycloak admin password
Nextcloud DB password
Synapse DB password
ONLYOFFICE JWT
mail admin credentials
SMTP credentials
backup credentials
S3 keys
OIDC client secrets
TLS private keys
```

---

# 92. Variables potentielles pour S3

```text
S3_ENDPOINT
S3_BUCKET
S3_REGION
S3_ACCESS_KEY_ID
S3_SECRET_ACCESS_KEY
```

---

# 93. Variables TLS

```text
LETSENCRYPT_EMAIL
TLS_PROVIDER
DNS_PROVIDER
```

Si DNS-01 :

```text
CLOUDFLARE_API_TOKEN
```

ou secret équivalent du provider utilisé.

---

# 94. Variables registry

```text
REGISTRY_URL
REGISTRY_USERNAME
REGISTRY_PASSWORD
```

---

# 95. Sécurité des secrets

Recommandation :

```text
environment variable
→ Kubernetes Secret
→ mounted/injected into workload
```

Évolution enterprise :

```text
Vault
External Secrets Operator
```

---

# 96. Roadmap détaillée

## Phase 0 — Fondation repository

Créer :

```text
Git repo
Go module
Cobra CLI
Makefile
CI minimale
README
```

Résultat attendu :

```bash
mysuite --help
```

---

## Phase 1 — Bootstrap K3s

Implémenter :

```text
hardware detection
OS validation
K3s installation
kubeconfig
cluster health
```

Résultat :

```bash
mysuite install --runtime k3s
```

produit un cluster fonctionnel.

---

## Phase 2 — Helm platform

Installer :

```text
namespaces
Traefik
cert-manager
storage
```

---

## Phase 3 — Data

Installer :

```text
CloudNativePG
PostgreSQL
Redis
```

---

## Phase 4 — Identity

Installer Keycloak.

Créer :

```text
realm
clients
roles
groups
OIDC
```

---

## Phase 5 — Files

Installer Nextcloud.

Configurer :

```text
DB
Redis
OIDC
storage
cron
```

---

## Phase 6 — Office

Installer ONLYOFFICE.

Configurer :

```text
JWT
Nextcloud connector
```

---

## Phase 7 — Chat

Installer :

```text
Synapse
Element
OIDC
PostgreSQL
media
```

---

# 97. Premier MVP démontrable

Le premier MVP doit s’arrêter ici :

```text
K3s
Traefik
cert-manager
CloudNativePG
Redis
Keycloak
Nextcloud
ONLYOFFICE
Matrix
Element
```

Objectif :

un seul compte Keycloak permet de :

```text
se connecter
ouvrir Nextcloud
éditer un document
ouvrir Element
envoyer un message
```

Ne pas ajouter immédiatement mail + visio avant d’avoir stabilisé ce cœur.

---

# 98. Phase 8 — Operator minimal

Créer `Suite` CRD.

L’Operator doit commencer par gérer :

```text
status
health
configuration
reconciliation
```

Ne pas migrer toute la logique Helm dans l’Operator immédiatement.

---

# 99. Phase 9 — Doctor

Implémenter :

```bash
mysuite status
mysuite doctor
```

---

# 100. Phase 10 — Backup

Backup :

```text
PostgreSQL
Nextcloud
Matrix media
configuration
```

Puis test de restore complet.

---

# 101. Phase 11 — Jitsi

Installer et valider :

```text
Jitsi
JVB
UDP
screen sharing
10 participants
```

---

# 102. Phase 12 — Mail POC

Comparer :

```text
Stalwart
Mailu
```

Choisir un seul provider.

---

# 103. Phase 13 — Admin UI

Créer :

```text
mysuite-api
mysuite-admin
```

---

# 104. Phase 14 — Upgrade manager

Implémenter :

```bash
mysuite upgrade
mysuite rollback
```

---

# 105. Phase 15 — Air-gap

Produire :

```text
bundle amd64
bundle arm64
registry locale
```

---

# 106. Phase 16 — Multi-node

Tester :

```text
3 node K3s
distributed storage
HA PostgreSQL
HA ingress
```

---

# 107. Phase 17 — RKE2

Ajouter runtime abstraction :

```text
K3sProvider
RKE2Provider
ExistingClusterProvider
```

---

# 108. Phase 18 — Multi-tenancy

Ne pas commencer avant que le single-tenant soit stable.

Modèle envisagé :

```text
tenant-a namespaces
tenant-b namespaces
```

---

# 109. Phase 19 — Providers alternatifs

Ajouter :

```text
files=opencloud
office=collabora
office=cryptpad
mail=mailu
```

---

# 110. Priorité immédiate

L’ordre de travail à respecter :

```text
1. Repository
2. CLI
3. K3s
4. Helm
5. Traefik
6. cert-manager
7. PostgreSQL
8. Redis
9. Keycloak
10. Nextcloud
11. ONLYOFFICE
12. Matrix
13. Element
14. SSO E2E
15. Operator
16. Doctor
17. Backup
18. Monitoring
19. Jitsi
20. Mail
21. Admin UI
22. Upgrade
23. Air-gap
24. HA
25. Multi-tenant
```

---

# 111. Principes à ne pas casser lors de la reprise

1. **MySuite est une couche d’intégration**, pas un fork de tous les logiciels.

2. Toutes les versions applicatives doivent être **pinées**.

3. Ne jamais utiliser :

```text
latest
```

en production.

4. Tous les secrets doivent être générés ou injectés.

5. Le single-node doit utiliser la même architecture applicative que le cluster HA.

6. Le passage :

```text
single-node
→ 3 nodes
```

ne doit pas nécessiter de réécrire les applications.

7. Les providers doivent être abstraits.

8. Le CLI ne doit pas être un énorme script shell.

9. Le shell sert uniquement au bootstrap.

10. Le cerveau du produit est :

```text
CLI Go
+
Operator
+
Helm
+
CRDs
```

11. Le projet doit prévoir air-gap dès la conception même si la feature arrive plus tard.

12. Les migrations et upgrades doivent être testés comme une fonctionnalité produit.

13. Backup sans restore testé = backup non fiable.

14. Le mail doit être considéré comme un sous-projet sensible à cause de :

```text
DNS
PTR
SPF
DKIM
DMARC
reputation
TLS
ports
deliverability
```

15. Jitsi doit être traité séparément côté réseau, surtout `UDP/10000`.

---

# 112. Objectif de la première vraie release

La première release candidate réellement utile devrait faire :

```bash
curl -sfL https://install.mysuite.io | sudo sh
```

et produire automatiquement :

```text
K3s
Traefik
TLS
PostgreSQL
Redis
Keycloak
Nextcloud
ONLYOFFICE
Matrix
Element
```

avec :

```text
1 domaine
1 compte admin
1 compte utilisateur
SSO fonctionnel
upload fichier
édition collaborative
chat
monitoring de base
backup fonctionnel
```

Cette release constituera le socle avant :

```text
Jitsi
Mail
Admin UI avancée
HA
Air-gap
Multi-tenancy
```

---

# 113. Résumé pour le prochain développeur / agent

Le projet ne doit pas commencer par coder toutes les applications.

Il faut commencer par fabriquer le **socle MySuite** :

```text
mysuite CLI
    │
    ▼
K3s bootstrap
    │
    ▼
Helm
    │
    ▼
Core platform
    │
    ├── ingress
    ├── TLS
    ├── DB
    ├── Redis
    └── Keycloak
    │
    ▼
Collaboration
    │
    ├── Nextcloud
    ├── ONLYOFFICE
    ├── Matrix
    └── Element
```

Une fois ce chemin E2E stable, intégrer l’Operator, puis les fonctionnalités avancées.

Le critère de succès n’est pas :

> « tous les pods tournent ».

Le critère de succès est :

> « une machine Linux vierge peut recevoir une commande unique et devenir une suite collaborative utilisable, testable, sauvegardable et maintenable ».

C’est le principe central à conserver pendant toute la reprise du projet.