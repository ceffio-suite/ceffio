# Console d'administration Ceffio

Interface web d'exploitation de la pile Ceffio. Elle répond à une question que
la ligne de commande ne rend pas confortable : **« qu'est-ce qui tourne, et
est-ce que tout va bien ? »** — sans avoir à taper `kubectl` sur la VM.

    https://admin.ceffio.example.com

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

| **Apps Nextcloud** | Les applications de collaboration, groupées par catégorie, avec leur licence, leur lien de documentation et un bouton pour les activer ou les désactiver |

## Ce qu'elle permet de faire

- **Voir** l'état de la pile en une page (dashboard)
- **Gérer les comptes SSO** — lister, créer, désactiver, changer le mot de passe
  dans le realm Keycloak `ceffio`
- **Gérer les applications Nextcloud** — activer ou désactiver les apps du
  catalogue (voir la section dédiée ci-dessous)
- **Suivre l'expiration des certificats** avant qu'ils ne cassent un service

## Gérer les applications Nextcloud

La page « Apps Nextcloud » présente deux listes **séparées, jamais mélangées** :

```
Applications installables      cases à cocher — un clic active ou désactive
Applications à dépendance      lecture seule — un service séparé est requis
externe
```

**Pourquoi cette séparation :** une application qui exige un serveur supplémentaire
(Whiteboard et son serveur WebSocket, Recognize et ses modèles IA, l'antivirus et
son serveur ClamAV) **ne fonctionne pas** après un simple clic. La présenter
cochable laisserait croire le contraire, et l'utilisateur chercherait ensuite
pourquoi la fonction ne marche pas. Elle est donc listée pour information, avec sa
dépendance écrite noir sur blanc, mais **non installable** depuis cette page.

Ce que fait un clic :

```
activer      → l'application devient disponible pour les utilisateurs
désactiver   → l'application disparaît de l'interface, mais reste sur le disque
                et peut être réactivée (aucune donnée n'est détruite)
```

**Comment ça marche techniquement :** la console appelle l'**API OCS de
Nextcloud** (`/ocs/v2.php/cloud/apps`), avec un compte de service dédié
(`ceffio-console`) et un mot de passe d'application révocable. Elle n'exécute
aucune commande dans le cluster et n'obtient aucun droit d'administration
Kubernetes : elle fait des appels HTTP authentifiés, rien d'autre.

> Une première version passait par des Jobs Kubernetes exécutant `occ` dans le pod
> Nextcloud. C'était beaucoup de pièces mobiles — ServiceAccount d'exécution,
> montage du PVC (qui ne traverse pas les namespaces), un pod par opération,
> lecture de logs — pour un résultat que l'API donne en un appel. L'API est la
> bonne approche ; les Jobs ont été retirés.

## Ce qu'elle NE fait PAS

À dire clairement, pour éviter les fausses attentes :

- Elle ne **redémarre** ni ne **déploie** rien (le déploiement passe par la CLI
  `ceffio install`)
- Elle ne **télécharge pas** d'application depuis l'app store : le catalogue est
  maîtrisé, pas ouvert
- Elle ne **supprime pas** définitivement une application ni ses données (la
  désactivation est réversible, la destruction ne l'est pas)
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

Points d'entrée, tous derrière la clé :

    GET  /api/status                     état complet : services, certificats, couches
    GET  /api/users                      liste des comptes du realm
    POST /api/users                      création (mot de passe non temporaire)
    POST /api/users/{id}/{action}        action = deactivate | password
    GET  /api/apps                       catalogue + état réel des applications
    POST /api/apps/{id}/install          active une application
    POST /api/apps/{id}/uninstall        désactive une application

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
      apps.go       gestion des applications Nextcloud (API OCS)
      deploy.go     déploiement de la console elle-même dans le cluster
      web/
        index.html  page unique (HTML + CSS + JS, sans dépendance externe)

L'interface est **un seul fichier HTML**, sans framework ni CDN : il est
embarqué dans le binaire Go et servi tel quel. Pas de chaîne de build front, pas
de `node_modules`, rien à installer pour la modifier.

La gestion des applications passe par **l'API OCS de Nextcloud**, avec un compte
de service dédié et un mot de passe d'application. Deux points pratiques : les
identifiants vivent dans le Secret `nextcloud-console-api`, et Nextcloud doit
autoriser les plages internes du cluster à opérer sans confirmation de mot de
passe (`allowed_no_password_confirmation_ranges`) — sans quoi toute modification
d'application est refusée avec « Password confirmation is required ».

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