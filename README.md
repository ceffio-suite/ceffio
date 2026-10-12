# Ceffio

Votre **suite collaborative souveraine**, open source et auto-hébergée.

Ceffio remplace Microsoft 365 / Teams pour une PME, une administration ou une
organisation : identité SSO, fichiers, documents collaboratifs, messagerie et
visioconférence — déployés sur Kubernetes **en une seule commande**, sans
abonnement, sans dépendance à un service tiers.

```bash
git clone https://github.com/ceffio-suite/ceffio.git
cd ceffio && make build
sudo ./bin/ceffio install --domain example.com
```

> Un script de bootstrap (`installer/install.sh`) est présent mais **encore
> incomplet** : il suppose des binaires publiés et une URL de releases qui
> n'existe pas encore. En attendant, on construit depuis les sources.

> « Ceffio » est un anagramme de « office ».

## Ce qu'est (et n'est pas) Ceffio

Ceffio **n'est pas un fork** des applications. C'est une **couche d'intégration
unifiée** (installation, configuration, SSO, provisioning, lifecycle, sécurité,
monitoring, backup/restore, upgrade, air-gap) autour de projets open source
éprouvés :

| Domaine       | Brique                          |
|---------------|---------------------------------|
| Identité/SSO  | Keycloak                        |
| Fichiers      | Nextcloud                       |
| Messagerie    | Nextcloud Talk                  |
| Visio         | Nextcloud Talk + Janus (HPB)    |
| Office        | ONLYOFFICE                      |
| Données       | PostgreSQL (CloudNativePG) + Redis |
| Ingress/TLS   | Traefik + cert-manager          |
| Console       | Console d'administration Ceffio |

### Pourquoi Talk plutôt qu'Element + Jitsi

Une version antérieure de Ceffio assemblait **Matrix (Synapse + Element)** pour
le chat et **Jitsi** pour la visio. Cette pile a été **retirée**, pour trois
raisons :

1. **Deux systèmes d'authentification à synchroniser.** Matrix et Jitsi ont
   chacun la leur ; il fallait les raccorder à Keycloak par des ponts dédiés
   (jetons OpenID, service de vérification d'utilisateur). Chaque pont est une
   source de panne, et une seule boucle d'authentification mal configurée suffit
   à rendre la visio inutilisable.
2. **Une surface d'exploitation double** pour l'administrateur : deux piles,
   deux cycles de vie, deux jeux de sauvegardes.
3. **Talk est natif dans Nextcloud** : l'authentification est celle de Nextcloud,
   elle-même branchée sur Keycloak. Il n'y a plus aucun pont à maintenir, et le
   chat comme la visio vivent dans le même outil que les fichiers.

C'est le choix qui rend le produit réellement « auto-portant en une commande » :
moins de pièces mobiles, donc moins de choses à casser.

## Architecture

```
CLI ceffio  +  Console d'administration
      │
  Ceffio Operator
      │
  Kubernetes API  →  Helm  →  applications upstream
```

Le cerveau du produit est : **CLI Go + Operator + Helm + CRDs**. Le shell ne sert
qu'au bootstrap.

## Les couches

Chaque couche est un package Go qui déploie et configure une partie de la pile.
Ce découpage est la raison pour laquelle la mise à niveau est possible : chaque
couche sait ce qu'elle fait tourner, donc on peut comparer avant et après.

| Couche | Package | Contenu |
|---|---|---|
| Plateforme | `internal/platform` | K3s, Ingress, cert-manager |
| Données | `internal/data` | CloudNativePG, PostgreSQL, Redis |
| Identité | `internal/identity` | Keycloak, realm, clients OIDC |
| Fichiers | `internal/files` | Nextcloud |
| Bureautique | `internal/office` | ONLYOFFICE + connecteur Nextcloud |
| **Talk + HPB** | `internal/talk` | Janus (SFU), signaling, coturn, NATS |
| Console | `internal/console` | Console d'administration |
| Ingress | `internal/ingress` | Routes et certificats |

### Le High Performance Backend de Talk

Talk fonctionne seul jusqu'à environ 4 à 6 participants, en connexions directes
entre navigateurs. Au-delà, il faut un **SFU** : un serveur qui reçoit chaque
flux une fois et le redistribue à tous. C'est le rôle de ce quatrième volet.

    Talk (app Nextcloud)   interface, chat, gestion des salles
    signaling              qui est présent, qui rejoint quoi
    Janus                  transport du média (le SFU)
    NATS                   coordination entre instances de signaling
    coturn                 relais TURN/STUN

Deux points de conception qui ont demandé une correction en conditions réelles :

- **`hostNetwork` sur Janus et coturn.** Un `Service` Kubernetes de type
  `NodePort` ne peut exposer qu'**un** port, jamais une plage — alors que le
  média WebRTC a besoin de toute une plage ouverte de bout en bout. Sans
  `hostNetwork`, tout apparaît « Running » et rien ne passe.
- **L'adresse publique doit être annoncée.** Derrière un NAT, Janus qui annonce
  ses adresses privées dans les candidats ICE produit un écran noir : le
  navigateur ne peut pas le joindre. Elle est **découverte automatiquement**,
  jamais fournie au déploiement : Janus et le relais TURN l'obtiennent eux-mêmes
  au démarrage par STUN, et le serveur de signalisation annonce un nom public
  (`talk.<domaine>`), qui survit à un changement d'adresse là où une valeur
  figée cesserait de fonctionner sans rien dire.

## Installation

Depuis les sources, pour l'instant :

```bash
make build
sudo ./bin/ceffio install --domain example.com
```

Le déploiement est **idempotent** : le relancer ne casse rien, il met à jour ce
qui doit l'être. C'est ce qui rend une réinstallation après incident sûre.

## La CLI

| Commande | Rôle |
|---|---|
| `ceffio install` | Déploie la pile complète |
| `ceffio status` | État des services déployés |
| `ceffio doctor` | Diagnostic (prérequis, cohérence, santé) |
| `ceffio backup` | Sauvegarde (bases, secrets, volumes) |
| `ceffio restore` | Restauration depuis une sauvegarde |
| `ceffio upgrade --plan` | Montre ce qui changerait avant de changer |
| `ceffio users` | Provisionne les comptes (Keycloak + applications) |
| `ceffio console` | Console d'administration en ligne de commande |
| `ceffio dns` | Vérifie la configuration DNS (A, AAAA, MX, SPF, DKIM, DMARC, PTR) |
| `ceffio expose` | Publie la suite derrière le pare-feu |
| `ceffio uninstall` | Désinstalle et détruit le cluster |

## La console d'administration

Une interface web pour l'exploitation quotidienne : état des services,
certificats avec leur date d'expiration, gestion des comptes SSO. Elle lit
l'état réel du cluster, elle ne le devine pas.

Voir `internal/console/README.md`.

## Prérequis

- Go 1.24+
- Un hôte Linux pour la cible (K3s est installé par Ceffio)
- Les ports média ouverts sur le pare-feu **et** redirigés : voir la section
  « Média et pare-feu » ci-dessous

## Développement

```bash
make build            # build ./bin/ceffio
./bin/ceffio --help   # liste des commandes
make test             # tests
make vet              # analyse statique
```

## Média et pare-feu

C'est la partie qui se rate le plus souvent, parce qu'elle dépend de la
topologie réseau et non du code. Trois familles de ports doivent être joignables
**depuis Internet** :

| Ports | Protocole | Rôle |
|---|---|---|
| `20000-20100` | UDP | Média Janus (la vidéo elle-même) |
| `3479` | UDP + TCP | Relais TURN — indispensable aux réseaux restrictifs |
| `5349` | TCP | TURN sécurisé (repli quand l'UDP est bloqué) |

Ces plages sont **propres à Ceffio** : elles ne chevauchent pas celles d'une
autre instance LiveKit ou Janus sur le même réseau, pour qu'une panne de l'une
n'affecte pas l'autre.

Deux pièges vérifiés :

- **Sur un pare-feu qui gère des plages, laisser le port interne vide.** pf
  (OpenBSD/OPNsense) interprète `rdr-to IP port N` comme « tout ramener sur N » :
  remplir ce champ avec un port unique effondre silencieusement toute la plage
  sur ce port, tout en répondant « enregistré ».
- **Rediriger depuis le bon équipement.** Si la VM est derrière un routeur qui
  lui-même se trouve derrière la box, les règles posées sur le routeur ne
  peuvent pas fonctionner : il faut les poser sur la box. Testez toujours depuis
  Internet, jamais depuis le réseau local — un test interne ne prouve rien.

## Statut

Le produit est **déployé et fonctionnel** : Nextcloud, ONLYOFFICE, Keycloak,
Talk avec son High Performance Backend (appel audio et vidéo validés entre deux
participants), console d'administration, sauvegarde/restauration.

Points encore ouverts, dits franchement :

- **L'adresse publique n'est plus un paramètre.** Elle est découverte au
  démarrage par STUN, côté Janus comme côté relais TURN, et annoncée sous forme
  de nom public pour le serveur de signalisation. Rien d'infrastructure n'est
  figé dans l'installation.
- **La messagerie (Stalwart/Mailu) n'est qu'un POC** et n'est pas déployée par
  `ceffio install`.
- **Le script de bootstrap** suppose des binaires publiés qui n'existent pas
  encore : l'installation passe aujourd'hui par une construction depuis les
  sources.

## Licence

À définir (open source — licence en attente de décision).