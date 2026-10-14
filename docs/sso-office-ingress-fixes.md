# SSO + ONLYOFFICE via ingress : correctifs validés sur VM Proxmox

Documentation des correctifs nécessaires pour qu'une pile déployée par `ceffio install`
soit **utilisable depuis un navigateur** derrière l'ingress Traefik (TLS auto-signé via la
CA `ceffio-ca`) avec un **login unique Keycloak** (Nextcloud + Element) et l'**édition
ONLYOFFICE** dans Nextcloud.

Validé sur VM 310 `ceffio-val` (<cluster-ip>, k3s v1.36.4). Ces correctifs étaient posés
"à la main" au runtime — ce fichier les documente pour qu'ils soient reproduits dans le CLI.

## Principe réseau k3s
- Les **pods ne lisent PAS le `/etc/hosts` du nœud** (ils passent par CoreDNS).
- Le `NodeHosts` de k3s ne s'est **pas synchronisé** ici (vide) → l'ajout DNS au nœud
  n'atteint pas les pods.
- Conséquence : pour que les pods joignent les apps par leur **nom public** (`*.demo.local`),
  on ajoute un **`hostAliases` par pod** vers le Service ClusterIP de **Traefik**.
  Traefik SvcLB = `10.43.x.x` (à lire dynamiquement : `kubectl get svc traefik -n kube-system`).
- Alternative propre à faire plus tard : ConfigMap CoreDNS `coredns-custom` (hosts `*.demo.local`
  → IP Traefik) pour résoudre en cluster-wide sans hostAlias par pod.

## 1. Keycloak — hostname public (évite le 404 / `auth.ceffio.local` codé en dur)
Le déploiement Keycloak avait `KC_HOSTNAME=auth.ceffio.local` (le `--domain` n'y est pas threadé).
Ses redirections pointaient vers l'ancien hôte → `http://auth.ceffio.local/admin/` → 404.
Correctifs (`kubectl set env deploy/keycloak -n ceffio-identity`) :
```
KC_HOSTNAME=keycloak.<domain>
KC_HOSTNAME_URL=https://keycloak.<domain>
KC_HOSTNAME_STRICT=false
KC_PROXY_HEADERS=xforwarded
```
→ découvreur OIDC renvoie désormais l'issuer/endpoints publics `https://keycloak.<domain>`.

## 2. SSRF Nextcloud — `allow_local_remote_servers`
Le HttpClient de Nextcloud bloque par défaut les adresses **privées/locales** (protection SSRF).
Or Keycloak/ONLYOFFICE sont sur des IP privées de cluster → `user_oidc` échoue avec
`LocalServerException: Host ... violates local access rules` (« Impossible de joindre le
fournisseur OpenID Connect »).
```
occ config:system:set allow_local_remote_servers --type boolean --value true
occ config:system:set trusted_proxies 0 --value 10.42.0.0/16    # derrière le proxy
occ config:system:set overwritehost --value cloud.<domain>
occ config:system:set overwriteprotocol --value https
```
Aussi : purger le rate-limit après essais (429) :
```
php occ security:bruteforce:reset <ip>   # ou TRUNCATE oc_bruteforce_attempts en base
```

## 3. TLS auto-signé dans les apps (CA `ceffio-ca`)
Les calls serveur→serveur inter-pods en **https** (`https://cloud.demo.local`,
`https://office.demo.local`) échouent car la CA est auto-signée et non reconnue.
Fix par pod concerné (Nextcloud, Synapse, ONLYOFFICE) :
- monter la CA : ConfigMap `ceffio-ca-cm` → volume `/etc/ceffio-ca` ;
- **Nextcloud (PHP/cURL)** : `SSL_CERT_FILE=/etc/ceffio-ca/ceffio-ca.crt` NE suffit PAS pour PHP
  → installer la CA dans le store système (`cp ... /usr/local/share/ca-certificates/ceffio.crt`
  + `update-ca-certificates`) ;
- **Synapse (Python/requests)** : env `SSL_CERT_FILE` ;
- **ONLYOFFICE (Node.js)** : env `NODE_EXTRA_CA_CERTS=/etc/ceffio-ca/ceffio-ca.crt`
  (+ store système pour curl/Python).

## 4. Element / Synapse — SSO OIDC via l'ingress
Le plugin OIDC de Synapse exige :
- `x_forwarded: true` sur le listener 8008 (sinon Synapse voit http → « non canonique » → loop
  ERR_TOO_MANY_REDIRECTS, car `public_baseurl` https) ;
- bloc `oidc_providers` en **endpoints https** (issuer + auth + token + userinfo + jwks) ;
  `discover: false` + endpoints explicites est obligatoire car un token_endpoint **http**
  est refusé (`OidcMetadataError: token_endpoint MUST use https`) ;
- hostAlias `keycloak.<domain>` → Traefik + CA (cf. §3) pour que Synapse jointe ces https ;
- client OIDC `synapse` : **standard flow** activé, redirectUris couvrant
  `<public_baseurl>/_synapse/client/oidc/callback`, et **secret aligné** entre
  le k8s secret `synapse-oidc`, la config Synapse et Keycloak.

## 5. ONLYOFFICE — clés de config EXACTES du connecteur (casse sensible !)
L'app `onlyoffice` (Nextcloud) lit des clés **en casse CamelCase** ; les écrire en minuscules
= « L'application ONLYOFFICE n'est pas configuré » → docx téléchargé.
```
occ config:app:set onlyoffice DocumentServerUrl --value https://office.<domain>/
occ config:app:set onlyoffice DocumentServerInternalUrl --value https://office.<domain>/
occ config:app:set onlyoffice StorageUrl --value https://cloud.<domain>/
occ config:app:set onlyoffice secret --value <jwt>                          # clé = "secret" (JWT)
```
> NB : dans le code applicatif : `_documentserver = "DocumentServerUrl"`,
> `_documentserverInternal = "DocumentServerInternalUrl"`, `_cryptSecret = "secret"`.
> Vérifier la casse exacte au moment de l'implémentation CLI.

## 6. ONLYOFFICE : le serveur doit joindre Nextcloud (récupérer le doc)
Le serveur ONLYOFFICE (pod office) récupère le document via l'URL (`DocumentServerUrl` /
`StorageUrl` = public). Il faut donc :
- hostAlias `cloud.<domain>` (+ `office.<domain>`, `keycloak.<domain>`) → Traefik sur **office** ;
- confiance CA (cf. §3) ;
- JWT aligné entre Nextcloud (`secret`) et le serveur (`JWT_SECRET`).

## 7. Ouverture par défaut de TOUS les formats (OOXML + ODF) dans ONLYOFFICE
- Par défaut le connecteur n'affecte une **action d'ouverture** (`def`) qu'à
  docx/docxf/oform/xlsx/pptx/pdf → **les ODF (odt/ods/odp/odg) se téléchargent au clic simple**
  (ouverture seulement via « ⋮ → Ouvrir dans ONLYOFFICE »).
- Fix : configurer `defFormats` (map JSON `{format: true/false}`, clés = extensions) en activant
  TOUT : `occ config:app:set onlyoffice defFormats --value='{"docx":true,...,"odt":true,"ods":true,"odp":true,"odg":true,"odf":true,...}'`.
  NB : la valeur doit être un **JSON valide** (clés entre guillemets) — passer par un fichier pour
  éviter l'écrasement des quotes par la coquille.
- Redémarrer Nextcloud (cache config) puis le clic simple ouvre les ODF dans l'éditeur.

## 8. Secrets OIDC réconciliés
`EnsureOIDCClients` doit **réconcilier client ET secret** (le secret Keycloak auto-généré à la
création manuelle divergeait du k8s secret stocké → `unauthorized_client`). La création d'un
client confidential sans `-s secret=` lui fait générer un secret aléatoire.