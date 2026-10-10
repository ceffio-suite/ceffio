# Console d'administration Ceffio

Interface web d'exploitation de la pile Ceffio. Elle répond à une question que
la ligne de commande ne rend pas confortable : **« qu'est-ce qui tourne, et
est-ce que tout va bien ? »** — sans avoir à taper `kubectl` sur la VM.

    https://admin.ceffio.mandem-it.com

## Ce qu'elle montre

Trois vues, dérivées de l'état réel du cluster (jamais d'un cache ni d'une
liste écrite à la main) :

| Vue | Ce qu'elle expose |
|---|---|
| **Applications utilisateurs** | Chaque service rendu aux utilisateurs, avec son URL, son rôle, et l'état calculé de ses pods (prêts/total) |
| **Certificats** | Chaque certificat TLS, son hôte, sa date d'expiration et le nombre de jours restants |
| **Infrastructure** | Les couches techniques (données, identité, fichiers, bureautique, visio, système), pod par pod, avec le nombre de redémarrages |

Le statut d'un service n'est pas déclaré : il est **calculé** depuis les pods qui
le portent. Un service dont tous les pods sont prêts est vert ; un pod qui
redémarre en boucle se voit immédiatement, avec son compteur.

## Ce qu'elle permet de faire

- **Voir** l'état de la pile en une page (dashboard)
- **Gérer les comptes SSO** — lister, créer, désactiver, changer le mot de passe
  dans le realm Keycloak `ceffio`
- **Suivre l'expiration des certificats** avant qu'ils ne cassent un service

## Ce qu'elle NE fait PAS

À dire clairement, pour éviter les fausses attentes :

- Elle ne **redémarre** ni ne **déploie** rien (le déploiement passe par la CLI
  `ceffio install`)
- Elle ne gère **pas** les sauvegardes (voir `ceffio backup` / `ceffio restore`)
- Elle n'expose **aucune** donnée utilisateur : ni fichiers, ni messages, ni
  contenu de réunion

## Authentification

L'accès est protégé par une **clé unique** (jeton), stockée dans un Secret
Kubernetes :

    kubectl get secret ceffio-console-key -n ceffio-system -o jsonpath='{.data.key}' | base64 -d

La page publique (`/`) est servie sans authentification — c'est elle qui demande
la clé en JavaScript, puis l'envoie en en-tête `Authorization: Bearer` sur
chaque appel `/api/*`. Autrement dit : **aucune donnée n'est accessible sans la
clé**, la page nue ne contient rien.

> **Limite assumée :** c'est un jeton statique, pas un SSO. Le verrouillage SSO
> Keycloak complet est prévu en durcissement, mais n'est pas encore en place.
> Traiter cette clé comme un secret d'administration.

## API

Deux points d'entrée, tous deux derrière la clé :

    GET  /api/status          état complet : services, certificats, couches
    GET  /api/users           liste des comptes du realm
    POST /api/users           création (mot de passe non temporaire)
    POST /api/users/{id}/{action}
                              action = deactivate | password

Les réponses sont du JSON brut. Un appel sans clé valide répond `401` — jamais
partiel, jamais silencieux.

## Comment elle est construite

Le serveur tourne **dans le cluster** (`ceffio-system`), et c'est ce qui rend
l'implémentation simple : il parle à l'API Kubernetes avec le compte de service
`ceffio-admin`, et à Keycloak via son service interne. Aucun accès depuis
l'extérieur n'est nécessaire.

    internal/console/
      console.go    serveur HTTP, routes, authentification par clé
      status.go     collecte de l'état (pods, certificats, services)
      users.go      gestion des comptes Keycloak
      deploy.go     déploiement de la console elle-même dans le cluster
      web/
        index.html  page unique (HTML + CSS + JS, sans dépendance externe)

L'interface est **un seul fichier HTML**, sans framework ni CDN : il est
embarqué dans le binaire Go et servi tel quel. Pas de chaîne de build front, pas
de `node_modules`, rien à installer pour la modifier.

L'appel à Keycloak passe par `kcadm` (l'outil d'administration livré avec
Keycloak) : c'est la seule voie qui garantit un état que Keycloak considère comme
cohérent. Jamais d'écriture directe en base.

## Droits nécessaires

La console utilise un `ClusterRole` dédié (`ceffio-admin`), limité à la
**lecture** des pods, services, déploiements, ingress et certificats. Elle n'a
pas le droit d'écrire dans le cluster — le déploiement reste l'affaire de la CLI.

## Déploiement

Assuré par `ceffio install` (phase 11), qui construit l'image, la charge dans le
cluster et crée l'ingress `admin.<domaine>`. Pour la reconstruire seule :

    cd internal/console
    docker build -t localhost/ceffio-console:<version> .

Le secret Keycloakadmin est **copié** dans `ceffio-system` : un `secretKeyRef` ne
traverse pas les namespaces, donc la console lit sa propre copie.