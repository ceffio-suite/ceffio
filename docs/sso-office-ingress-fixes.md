# SSO + ONLYOFFICE via ingress: fixes validated on a Proxmox VM

Documentation of the fixes needed for a stack deployed by `ceffio install` to
be **usable from a browser** behind the Traefik ingress (self-signed TLS via
the `ceffio-ca` CA) with a **single Keycloak login** (Nextcloud + Element) and
**ONLYOFFICE editing** in Nextcloud.

Validated on VM 310 `ceffio-val` (<cluster-ip>, k3s v1.36.4). These fixes were
applied "by hand" at runtime — this file documents them so they are reproduced
in the CLI.

## k3s network principle
- **Pods do NOT read the node's `/etc/hosts`** (they go through CoreDNS).
- k3s's `NodeHosts` did **not sync** here (empty) → the DNS addition on the
  node does not reach the pods.
- Consequence: for the pods to reach the apps by their **public name**
  (`*.demo.local`), we add a **per-pod `hostAliases`** toward **Traefik**'s
  ClusterIP Service. Traefik SvcLB = `10.43.x.x` (to read dynamically:
  `kubectl get svc traefik -n kube-system`).
- Cleaner alternative to do later: CoreDNS `coredns-custom` ConfigMap (hosts
  `*.demo.local` → Traefik IP) to resolve cluster-wide without a per-pod
  hostAlias.

## 1. Keycloak — public hostname (avoids the 404 / hardcoded `auth.ceffio.local`)
The Keycloak deployment had `KC_HOSTNAME=auth.ceffio.local` (the `--domain` is
not threaded through to it). Its redirections pointed to the old host →
`http://auth.ceffio.local/admin/` → 404.
Fixes (`kubectl set env deploy/keycloak -n ceffio-identity`):
```
KC_HOSTNAME=https://keycloak.<domain>
KC_HOSTNAME_STRICT=false
KC_PROXY_HEADERS=xforwarded
```
→ the OIDC discoverer now returns the public issuer/endpoints
`https://keycloak.<domain>`.

## 2. Nextcloud SSRF — `allow_local_remote_servers`
Nextcloud's HttpClient blocks **private/local** addresses by default (SSRF
protection). But Keycloak/ONLYOFFICE are on cluster-private IPs → `user_oidc`
fails with `LocalServerException: Host ... violates local access rules`
(« Impossible de joindre le fournisseur OpenID Connect »).
```
occ config:system:set allow_local_remote_servers --type boolean --value true
occ config:system:set trusted_proxies 0 --value 10.42.0.0/16    # behind the proxy
occ config:system:set overwritehost --value cloud.<domain>
occ config:system:set overwriteprotocol --value https
```
Also: purge the rate-limit after attempts (429):
```
php occ security:bruteforce:reset <ip>   # or TRUNCATE oc_bruteforce_attempts in the DB
```

## 3. Self-signed TLS in the apps (`ceffio-ca` CA)
The inter-pod server→server calls over **https** (`https://cloud.demo.local`,
`https://office.demo.local`) fail because the CA is self-signed and not
recognized. Fix per concerned pod (Nextcloud, Synapse, ONLYOFFICE):
- mount the CA: ConfigMap `ceffio-ca-cm` → volume `/etc/ceffio-ca`;
- **Nextcloud (PHP/cURL)**: `SSL_CERT_FILE=/etc/ceffio-ca/ceffio-ca.crt` is
  NOT enough for PHP → install the CA in the system store
  (`cp ... /usr/local/share/ca-certificates/ceffio.crt` +
  `update-ca-certificates`);
- **Synapse (Python/requests)**: env `SSL_CERT_FILE`;
- **ONLYOFFICE (Node.js)**: env `NODE_EXTRA_CA_CERTS=/etc/ceffio-ca/ceffio-ca.crt`
  (+ system store for curl/Python).

## 4. Element / Synapse — OIDC SSO via the ingress
Synapse's OIDC plugin requires:
- `x_forwarded: true` on the 8008 listener (otherwise Synapse sees http →
  « non canonique » → loop ERR_TOO_MANY_REDIRECTS, because `public_baseurl`
  is https);
- an `oidc_providers` block with **https endpoints** (issuer + auth + token +
  userinfo + jwks); `discover: false` + explicit endpoints is mandatory
  because an **http** token_endpoint is refused
  (`OidcMetadataError: token_endpoint MUST use https`);
- hostAlias `keycloak.<domain>` → Traefik + CA (cf. §3) so Synapse can reach
  these https;
- OIDC client `synapse`: **standard flow** enabled, redirectUris covering
  `<public_baseurl>/_synapse/client/oidc/callback`, and **aligned secret**
  between the k8s secret `synapse-oidc`, the Synapse config and Keycloak.

## 5. ONLYOFFICE — EXACT config keys of the connector (case-sensitive!)
The `onlyoffice` app (Nextcloud) reads **CamelCase** keys; writing them in
lowercase = "L'application ONLYOFFICE n'est pas configuré" → docx downloaded.
```
occ config:app:set onlyoffice DocumentServerUrl --value https://office.<domain>/
occ config:app:set onlyoffice DocumentServerInternalUrl --value https://office.<domain>/
occ config:app:set onlyoffice StorageUrl --value https://cloud.<domain>/
occ config:app:set onlyoffice secret --value <jwt>                          # key = "secret" (JWT)
```
> NB: in the app code: `_documentserver = "DocumentServerUrl"`,
> `_documentserverInternal = "DocumentServerInternalUrl"`, `_cryptSecret = "secret"`.
> Check the exact case at CLI implementation time.

## 6. ONLYOFFICE: the server must reach Nextcloud (fetch the doc)
The ONLYOFFICE server (office pod) fetches the document via the URL
(`DocumentServerUrl` / `StorageUrl` = public). It therefore needs:
- hostAlias `cloud.<domain>` (+ `office.<domain>`, `keycloak.<domain>`) →
  Traefik on **office**;
- CA trust (cf. §3);
- JWT aligned between Nextcloud (`secret`) and the server (`JWT_SECRET`).

## 7. Opening ALL formats (OOXML + ODF) in ONLYOFFICE by default
- By default the connector only assigns an **open action** (`def`) to
  docx/docxf/oform/xlsx/pptx/pdf → **the ODF (odt/ods/odp/odg) download on a
  single click** (opening only via « ⋮ → Ouvrir dans ONLYOFFICE »).
- Fix: configure `defFormats` (JSON map `{format: true/false}`, keys =
  extensions) enabling EVERYTHING:
  `occ config:app:set onlyoffice defFormats --value='{"docx":true,...,"odt":true,"ods":true,"odp":true,"odg":true,"odf":true,...}'`.
  NB: the value must be **valid JSON** (keys quoted) — go through a file to
  avoid the shell eating the quotes.
- Restart Nextcloud (config cache) then a single click opens the ODF in the
  editor.

## 8. Reconciled OIDC secrets
`EnsureOIDCClients` must **reconcile client AND secret** (the auto-generated
Keycloak secret at manual creation diverged from the stored k8s secret →
`unauthorized_client`). Creating a confidential client without `-s secret=`
makes it generate a random secret.
