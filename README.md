# Ceffio

Votre **suite collaborative souveraine**, open source et auto-hébergée.

Ceffio remplace Microsoft 365 / Teams pour une PME, une administration ou une
organisation : identité SSO, fichiers, documents collaboratifs, chat, visio et
messagerie — déployés sur Kubernetes en une seule commande.

```bash
curl -sfL https://install.ceffio.io | sudo sh
```

> « Ceffio » est un anagramme de « office ».

## Ce qu'est (et n'est pas) Ceffio

Ceffio **n'est pas un fork** des applications. C'est une **couche d'intégration
unifiée** (installation, configuration, SSO, provisioning, lifecycle, sécurité,
monitoring, backup/restore, upgrade, air-gap) autour de projets open source
éprouvés :

| Domaine       | Brique                |
|---------------|-----------------------|
| Identité/SSO  | Keycloak              |
| Fichiers      | Nextcloud             |
| Office        | ONLYOFFICE            |
| Chat          | Matrix + Element      |
| Visio         | Jitsi                 |
| Mail          | Stalwart ou Mailu (POC) |
| Données       | PostgreSQL + Redis    |
| Ingress/TLS   | Traefik + cert-manager|

## Architecture

```
CLI ceffio  +  Admin UI
      │
  Ceffio Operator
      │
  Kubernetes API  →  Helm  →  applications upstream
```

Le cerveau du produit est : **CLI Go + Operator + Helm + CRDs**. Le shell ne sert
qu'au bootstrap.

## Statut

**Phase 0** — fondation du repository (en cours) : module Go, CLI Cobra, Makefile,
README. Le bootstrap K3s et le déploiement Helm arrivent en Phases 1-2.

## Développement

Prérequis : Go 1.24+.

```bash
make build            # build ./bin/ceffio
./bin/ceffio --help   # liste des commandes
make test             # tests
make vet              # analyse statique
```

## Roadmap

Voir le wiki du projet : `entities/ceffio.md` (schéma, décisions, phases).

## Licence

À définir (open source — licence en attente de décision).
