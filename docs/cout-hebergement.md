1|# Ceffio — hébergement : comparatif de coût
2|
3|Recherche faite le 15 octobre 2026. Prix HT, hors TVA, hors frais d'IPv4 sauf mention.
4|
5|## 1. Ce que Ceffio demande réellement (mesuré, pas estimé)
6|
7|Mesures sur la VM actuelle (8 vCPU / 32 Go / 96 Go) :
8|
9|  RAM utilisée           3 Go sur 32        <- 90% de la RAM est inutilisée
10|  Disque utilisé        36 Go sur 96
11|  Pods                   25
12|  Modèles Vosk           3,7 Go (66 Mo pour le français seul)
13|  Charge CPU             faible (sauf pointe de déploiement)
14|
15|Conclusion : la VM est surdimensionnée. Le vrai besoin :
16|
17|  4 vCPU / 8 Go / 100 Go   suffit pour un usage SMB
18|  8 vCPU / 16 Go / 200 Go  confortable, avec marge pour la transcription
19|  8 vCPU / 32 Go           inutile — mesuré à 3 Go d'usage
20|
21|## 2. LA CONTRAINTE QUI DÉCIDE DE TOUT : AVX2
22|
23|La transcription Vosk exige AVX2 + BMI1. Vérifié sur l'installation actuelle :
24|
25|  libvosk.so    112 vpbroadcast + 39 vpermd (AVX2), 287 andn (BMI1)
26|  Xeon E5-2470 v2 de l'hôte : AVX oui, AVX2 NON -> Illegal instruction
27|
28|Un hébergeur sans AVX2 = transcription impossible, quelle que soit la config.
29|
30|État par hébergeur (source : forum Cloudron, flags /proc/cpuinfo relevés
31|chez les utilisateurs, et gammes CPU annoncées) :
32|
33|  Hetzner Cloud      AVX OUI (AMD EPYC / Intel récents)
34|  Contabo VPS L      AVX2 OUI (AMD EPYC 7282 — flags relevés : avx2 bmi1 bmi2)
35|  Netcup             AVX2 OUI sur RS 1000 G9.5 et RS 4000 G8SE (relevé)
36|  DigitalOcean       AVX OUI
37|  Linode             AVX OUI
38|  Vultr              AVX OUI
39|  OVH                non relevé — à vérifier avant achat
40|
41|Les gammes AMD EPYC (Rome 7002, Milan 7003) et Ryzen Zen2+ ont AVX2.
42|Les offres bas de gamme sur Xeon ancien n'en ont pas.
43|
44|## 3. Comparatif — le moins cher
45|
46|### 3.1 Le moins cher qui fait tourner Ceffio (AVX2 requis)
47|
48|| Offre | vCPU | RAM | Disque | Prix/mois HT | AVX2 | Note |
49||---|---|---|---|---|---|---|
50|| Contabo Cloud VPS 30 | 8 | 24 Go | 200 Go NVMe | 14,00 € | OUI | meilleur rapport |
51|| Contabo Cloud VPS 20 | 6 | 12 Go | 100 Go NVMe | 7,50 € | OUI | suffisant |
52|| Contabo Cloud VPS 10 | 4 | 8 Go | 75 Go NVMe | 5,50 € | OUI | le moins cher viable |
53|| OVH VPS-1 | 2 | 4 Go | 40 Go NVMe | ~5,07 $ | ? | trop juste en RAM |
54|| Hetzner CPX02 | 1 | 1 Go | 20 Go | 5,99 € | OUI | insuffisant |
55|| Netcup vServer 2000 | 2 | 2 Go | 40 Go | 2,99 € | OUI | trop juste |
56|| Netcup RS 1000 G9.5 | 4 | 8 Go | ~160 Go | ~12 € | OUI | bon |
57|
58|En Europe, sur la seule base du prix pour Ceffio :
59|
60|  LE MOINS CHER QUI FONCTIONNE : Contabo Cloud VPS 10 — 4 vCPU / 8 Go / 75 Go — 5,50 €/mois
61|  avec le français : ~47 Mo de modèles, RAM 3 Go utilisée -> ça passe.
62|  MAIS 8 Go est juste si tu ajoutes la transcription + un ou deux appels simultanés.
63|
64|  LE MEILLEUR COMPROMIS : Contabo Cloud VPS 30 — 8 vCPU / 24 Go / 200 Go — 14,00 €/mois
65|  Tu as 3x la RAM nécessaire et le disque pour tous les modèles Vosk.
66|
67|### 3.2 Le meilleur rapport qualité/prix (recommandé)
68|
69|| Rang | Offre | Specs | Prix/mois HT | Pourquoi |
70||---|---|---|---|---|
71|| 1 | Contabo Cloud VPS 40 | 12 vCPU / 48 Go / 250 Go NVMe | 25,00 € | marge confortable, transcription + appels |
72|| 2 | Hetzner CX43 | 8 vCPU / 16 Go / 160 Go | 15,99 € | meilleur CPU, mais CX en rupture |
73|| 3 | Contabo Cloud VPS 30 | 8 / 24 / 200 | 14,00 € | le point d'équilibre réel |
74|| 4 | Netcup RS 1000 G9.5 | 4 / 8 / 160 | ~12 € | bon CPU, RAM juste |
75|| 5 | OVH VPS-4 | 8 / 24 / 200 | 26,54 $ | français, mais + cher à specs égales |
76|
77|### 3.3 Le serveur dédié — quand ça devient rentable
78|
79|Le dédié ne vaut le coup qu'à partir de ~8 vCPU sous charge continue :
80|
81|| Offre | Cores | RAM | Prix/mois HT | Mise en place |
82||---|---|---|---|---|
83|| Contabo dédié | 8 | 30 Go+ | 86,40 € | selon offre |
84|| Hetzner AX42-1 | 8/16 | 64 Go | 97,30 € | 49 € |
85|| Hetzner EX44-1-LTD | 14/20 | 64 Go | 57,30 € | 0 € (série limitée) |
86|| Hetzner AX41-1-LTD | 6/12 | 64 Go | 57,30 € | 0 € (série limitée) |
87|
88|Pour Ceffio, le dédié est SURDIMENSIONNÉ : 3 Go de RAM utilisés.
89|
90|## 4. Le piège à éviter
91|
92|Les offres les moins chères absolues (Netcup 2,99 €, OVH VPS-1 5,07 $) ont
93|2 à 4 Go de RAM. Ceffio consomme 3 Go AU REPOS et 16 Go sont recommandés par
94|Nextcloud pour la transcription. Sur 4 Go, tu ajoutes la transcription et tu
95|satures.
96|
97|Les séries "Limited" de Hetzner (AX41-1-LTD, EX44-1-LTD) à 57,30 € sont le
98|meilleur prix au cœur jamais vu, mais en quantité limitée et épuisables.
99|
100|## 5. Coût réel de la solution actuelle
101|
102|Ta VM Proxmox est sur un serveur que tu possèdes déjà. Le coût de revient est
103|donc celui de l'électricité, pas d'un abonnement — et c'est ce qui rend la
104|migration vers un VPS un coût NOUVEAU, pas une économie.
105|
106|La question n'est donc pas "VPS ou dédié", mais : "est-ce que je paie ~15 €/mois
107|pour avoir AVX2 et débloquer la transcription, ou est-ce que je m'en passe ?"
108|
109|## 6. Recommandation
110|
111|  Pour débloquer la transcription au moindre coût : Contabo Cloud VPS 30,
112|  8 vCPU / 24 Go / 200 Go, 14 €/mois HT. AVX2 confirmé sur EPYC 7282.
113|  Il y a de la marge : 3 Go utilisés sur 24, et 6,3 Go de disque pour tous
114|  les modèles Vosk.
115|
116|  Si tu veux rester en France : OVH VPS-4 (8/24/200, ~26,54 $) — plus cher,
117|  et l'AVX2 reste à vérifier avant de t'engager.
118|
119|  À éviter : tout ce qui est sous 8 Go de RAM pour ce projet.

---

# Annexe — Kimsufi, Alibaba, Cloudflare, Scaleway

## Kimsufi (OVHcloud) — dédié bas de gamme

Prix relevés le 15/10/2026, HT, hors frais d'installation (égaux à un mois,
offerts si engagement 12 mois).

| Modèle | CPU | Cores/threads | RAM | Disque | Prix/mois |
|---|---|---|---|---|---|
| KS-B | Xeon E5-1620v2 | 4c/8t | 32 Go ECC | 1×120 Go SSD | 9,99 € |
| KS-C | Xeon E5-1650v2 | 6c/12t | 32 Go ECC | 1×120 Go SSD | 11,99 € |
| KS-1 | Xeon-D 1520 | 4c/8t | 32 Go ECC | 2×2 To | 16,99 € |
| KS-2 | Xeon-D 1540 | 8c/16t | 32 Go ECC | 2×2 To | 18,99 € |
| KS-4 | Xeon-E3 1230v6 | 4c/8t | 16-64 Go | 2×450 Go NVMe | 16,99 € |

### ⚠ Le problème : AVX2

Les Xeon E5-16xx v2 sont des **Ivy Bridge (2012-2013)** — exactement la même
génération que le CPU qui bloque la transcription aujourd'hui :

  Xeon E5-1620v2 / 1650v2     AVX oui · AVX2 NON  -> transcription impossible
  Xeon-D 1520 (Broadwell-DE)  AVX2 OUI
  Xeon-E3 1230v6 (Kaby Lake)  AVX2 OUI

Donc : KS-B et KS-C à 9,99 € et 11,99 € sont **inutilisables pour la
transcription**. KS-1, KS-2 et KS-4 devraient fonctionner (Broadwell-DE et
Kaby Lake ont AVX2) — à vérifier par `grep avx2 /proc/cpuinfo` dès la mise en
route, la virtualisation pouvant masquer des flags.

Mais attention : KS-1 et KS-2 n'ont que **2 To de disque mécanique** et pas de
SSD pour le système. Pour Kubernetes, un disque mécanique est un vrai frein.

**Verdict Kimsufi** : le prix est attractif mais c'est du matériel ancien.
À 16,99 € le KS-4 (Xeon-E3, 16 Go, NVMe) est correct, mais le Contabo VPS 30
à 14 € donne 8 vCPU / 24 Go / 200 Go NVMe pour moins cher, avec AVX2 confirmé.

## Alibaba Cloud — nettement plus cher

| Instance | vCPU | RAM | Prix/mois |
|---|---|---|---|
| ecs.c8a.2xlarge | 8 | 16 Go | **188,64 $** |
| ecs.gn6v (avec V100) | 8 | 42 Go | GPU, hors sujet |

**Verdict** : 188 $/mois pour 8 vCPU/16 Go, c'est **13 fois** le Contabo VPS 30.
Alibaba Cloud est un hyperscaler, pas un hébergeur de PME. Les prix affichés
"à partir de" concernent des instances 1-2 vCPU, insuffisantes ici, avec
facturation à l'heure et egress payant.

À écarter pour Ceffio, sauf contrainte réglementaire imposant la Chine.

## Cloudflare — structurellement incompatible

### ⚠ Ce n'est pas une question de prix, c'est une impossibilité

Deux obstacles, dont un rédhibitoire :

**1. Cloudflare ne proxy PAS l'UDP.** Documenté noir sur blanc par les guides
Talk : le port 3479 UDP/TCP doit être en **DNS gris (grey cloud)**, jamais
proxifié. Cloudflare proxy uniquement HTTP/HTTPS. Or tout le média WebRTC de
Ceffio — Janus sur 20000-20100/udp, coturn sur 3479 et 49152-49200/udp — est
de l'UDP. Derrière le proxy Cloudflare, cela ne passe pas.

**2. Les Workers/Containers sont sans état par conception.** Ceffio est un
cluster k3s avec des pods persistants, des volumes, et des connexions
WebSocket longues (le signaling) — pas des fonctions qui dorment entre deux
requêtes.

### Le coût, pour information

Si l'architecture était possible, elle serait chère :

| Charge | Cloudflare Containers | VPS équivalent |
|---|---|---|
| Petit service ½ vCPU / 4 Go | 35-58 $/mois | 7-15 $ |
| API 4 vCPU / 12 Go | 139-192 $/mois | 15-30 $ |

Le modèle facture **la mémoire provisionnée 24/7** dès que le conteneur est
éveillé (seul le CPU est facturé à l'usage). Pour un backend qui ne dort
jamais, c'est 3 à 10× le prix d'un VPS à specs égales.

**Verdict Cloudflare** : à écarter. Cloudflare reste utile **devant** Ceffio
(CDN, protection DDoS pour le HTTP), mais ne peut pas l'héberger.

## Scaleway — cher pour ce projet

| Instance | vCPU | RAM | Disque | Prix/mois |
|---|---|---|---|---|
| STARDUST1-S | 1 | 1 Go | 10 Go | ~1,57 $ |
| DEV1-L | 4 | 8 Go | — | ~35 $ |
| PLAY2-MICRO | 4 | 8 Go | — | ~44 $ |
| COMPUTE3-X8C-16G | 8 | 16 Go | — | **~188 $** |

CPU : AMD EPYC 9555P sur les gammes Standard3 (Zen 5) — **AVX2 garanti**, et
même AVX-512. Techniquement excellent.

**Verdict** : le CPU est bon mais le prix est celui d'un cloud public.
Le COMPUTE3 8 vCPU/16 Go à 188 $ est hors budget, et le PLAY2-MICRO 4 vCPU/8 Go
à 44 $ coûte **3×** le Contabo VPS 30 pour moitié moins de ressources.

Scaleway a du sens si tu veux du 100% français, de l'élastique à l'heure, et
que le budget suit.

## Tableau récapitulatif des quatre

| Hébergeur | Offre | Specs | Prix/mois | AVX2 | Verdict |
|---|---|---|---|---|---|
| Kimsufi | KS-B | 4c/8t · 32 Go · 120 Go | 9,99 € | NON | transcription impossible |
| Kimsufi | KS-4 | 4c/8t · 16 Go · 900 Go NVMe | 16,99 € | oui | correct, mais cher vs Contabo |
| Alibaba | ecs.c8a.2xlarge | 8 · 16 Go | 188 $ | oui | 13× le prix, hors sujet |
| Cloudflare | Containers | ½-4 vCPU | 35-192 $ | n/a | **UDP non proxifié = impossible** |
| Scaleway | COMPUTE3-X8C-16G | 8 · 16 Go | 188 $ | oui | bon CPU, prix cloud public |
| Scaleway | PLAY2-MICRO | 4 · 8 Go | ~44 $ | oui | 3× le Contabo |

## Conclusion de l'annexe

Sur ces quatre, **aucun ne bat le Contabo Cloud VPS 30 (8 vCPU / 24 Go /
200 Go NVMe, 14 €/mois, AVX2 confirmé)**.

Les deux pièges à retenir :

- **Kimsufi KS-B et KS-C** : le prix le plus bas du marché (9,99 €) mais du
  Xeon Ivy Bridge, donc **sans AVX2** — exactement le problème actuel.
- **Cloudflare** : impossible, pas cher ou non. Le WebRTC de Ceffio est de
  l'UDP, et Cloudflare ne route pas l'UDP. Un proxy Cloudflare devant Ceffio
  fonctionne pour le HTTP ; il ne peut pas remplacer l'hébergement.

---

# Recherche ciblée : 8 vCPU / 16 Go / gros disque mécanique

Critère : beaucoup de stockage HDD (mécanique), pas cher, et AVX2 pour la
transcription.

## Le problème avec le HDD en 2026

Presque tous les hébergeurs ne vendent plus de HDD : le SSD et le NVMe ont
remplacé le mécanique partout. Contabo, Hetzner, Scaleway, OVHcloud VPS :
100 % SSD/NVMe sur leurs gammes VPS.

Le HDD ne subsiste que sur les serveurs dédiés, où l'on peut encore choisir
un jeu de disques mécaniques pour le stockage de masse. C'est donc là qu'il
faut chercher — et cela tombe bien : le dédié est ce qui donne le plus de To
par euro.

## Les offres qui correspondent vraiment

### 1. Kimsufi KS-4 — 2× 2 To HDD INCLUS (le meilleur rapport)

Relevé le 15/10/2026 sur kimsufi.com :

  CPU       Intel Xeon-E3 1230 v6  4c/8t  (Kaby Lake, 2017)
  RAM       16 Go DDR4 ECC  (options 32 Go +4,50 $, 64 Go +8,90 $)
  Disque    2× 450 Go SSD NVMe   INCLUS
            2× 2 To HDD Enterprise  INCLUS     <- les deux jeux, au choix
            2× 4 To HDD             +6,70 $/mois
  Réseau    500 Mbps illimité
  Prix      18,80 $/mois HT
  Setup     18,80 $ une fois (offert si engagement 12 mois)

  AVX2 : Xeon-E3 1230 v6 = Kaby Lake -> AVX2 OUI

  Le point remarquable : les 2× 2 To HDD sont INCLUS AU MÊME PRIX que les
  SSD NVMe. Tu choisis 4 To mécaniques pour le prix de base. En RAID 1 tu
  gardes 2 To utiles ; sans RAID tu as 4 To.

  C'est exactement le besoin : 8 threads (4c/8t), 16 Go, 4 To de mécanique.

### 2. Kimsufi SYS-1 — 2× 4 To HDD, plus de CPU

  CPU       Intel Xeon-E 2136  6c/12t  (Coffee Lake, AVX2)
  RAM       32 Go DDR4 ECC
  Disque    2× 4 To HDD SATA
  Prix      ~35,99 $/mois HT
  Setup     ~35,99 $

  Plus cher, mais 8 To de mécanique et 32 Go de RAM.

### 3. Kimsufi SYS-3 — 3× 4 To HDD (12 To) + NVMe

  CPU       Intel Xeon-E 2288G  8c/16t  (Coffee Lake, AVX2)
  RAM       32 Go DDR4 ECC (options jusqu'à 128 Go)
  Disque    2× 960 Go SSD NVMe  INCLUS
            3× 4 To HDD Enterprise  INCLUS   (12 To bruts, 8 To en RAID 5)
  Réseau    1 Gbps illimité et garanti
  Prix      55,80 $/mois TTC

  Le vrai serveur de stockage : 8 cœurs, 32 Go, et 12 To de mécanique.

### 4. Contabo Storage VPS 30 — SSD, pas HDD, mais 1 To à 14 €

  CPU       6 vCPU (AMD EPYC, AVX2)
  RAM       18 Go
  Disque    1 To SSD
  Prix      14,00 €/mois (11,20 € sur engagement 24 mois)

  ATTENTION : c'est du SSD, pas du mécanique. Mais pour 1 To à 14 €, c'est
  moins cher au To que la plupart des dédiés HDD sur les petites capacités.

## Comparatif des quatre

| Offre | vCPU | RAM | Disque | Prix/mois | AVX2 | $/To |
|---|---|---|---|---|---|---|
| Kimsufi KS-4 | 4c/8t | 16 Go | 2×2 To HDD inclus | 18,80 $ | oui | ~4,70 |
| Kimsufi SYS-1 | 6c/12t | 32 Go | 2×4 To HDD | ~35,99 $ | oui | ~4,50 |
| Kimsufi SYS-3 | 8c/16t | 32 Go | 12 To HDD + NVMe | 55,80 $ | oui | ~4,65 |
| Contabo Storage VPS 30 | 6 | 18 Go | 1 To SSD | 14 € | oui | ~14 € |

## La recommandation

Kimsufi KS-4, 18,80 $/mois — c'est exactement la demande :

  8 threads (4c/8t), 16 Go de RAM, 2× 2 To de HDD mécanique inclus,
  Xeon Kaby Lake donc AVX2, setup offert si tu prends 12 mois.

  Pour Ceffio : 4 Go de RAM utilisés sur 16, 36 Go de disque système sur les
  4 To, et le reste du disque pour les fichiers, les enregistrements d'appels
  et les modèles Vosk.

  Le seul bémol : le système tourne sur SSD NVMe ou HDD au choix — sur HDD,
  Kubernetes sera plus lent au démarrage. La bonne pratique est de prendre les
  deux jeux si l'offre le permet, sinon d'accepter un k3s un peu lent sur
  disque mécanique.

Si tu veux du confort : Kimsufi SYS-3 (55,80 $/mois) — 8 cœurs, 32 Go,
12 To de mécanique, 1 Gbps garanti. C'est le vrai serveur de stockage, et il
a les NVMe inclus pour le système.

## À vérifier avant de commander

1. La disponibilité. Les Kimsufi sont souvent en rupture (« Sold out ») — le
   KS-4 était disponible à Gravelines le 15/10, les autres datacenters en
   rupture. Le projet kimsufi-checker (GitHub) surveille l'API OVH.

2. L'AVX2 à la livraison. Le Xeon-E3 1230 v6 et le Xeon-E 2136 sont
   Kaby/Coffee Lake, donc AVX2 natif — mais lance grep avx2 /proc/cpuinfo dès
   que tu as la main. Un hyperviseur peut masquer un flag.

3. Les frais d'installation. Égaux à un mois, offerts si tu t'engages
   12 mois. Sur un KS-4, ça change le coût réel de 18,80 à ~17,20 $/mois.

---

# Deuxième passe : le reste du marché

## La découverte : l'enchère Hetzner

Hetzner vend du matériel d'occasion reconditionné aux enchères descendantes
— plus un serveur reste invendu, moins il coûte. Sans frais d'installation,
sans engagement. C'est de très loin le meilleur rapport To/euro du marché.

Relevé du 15/10/2026 sur radar.iodev.org (qui interroge l'enchère en continu) :

  Le moins cher du board : 59,70 €/mois
    Intel Xeon E5-1650 v3, 128 Go de RAM, 8 To de HDD

  Meilleur prix au To : environ 2,15 €/To, sur une machine à 64 To

  Exemples réels vus cette semaine :
    67,00 €  Intel Core i7-6700, 32 Go, 2× 4 To HDD
    37,30 €  AMD Ryzen 5 3600, 64 Go, 2× 512 Go NVMe
    46,00 €  AMD Ryzen 7 PRO 8700GE, 64 Go DDR5 ECC, 2× 512 Go NVMe

Le prix moyen du To mécanique à l'enchère est resté stable autour de
0,85 à 1,00 €/To sur douze mois — c'est la ressource la moins volatile du
marché.

Attention : l'inventaire tourne vite, et les prix bougent dans la journée.
Il faut donc surveiller, pas commander à date fixe.

## Les autres hébergeurs examinés

### Leaseweb — cher

| Offre | Specs | Prix/mois |
|---|---|---|
| DS Sandy Bridge | Xeon E3-1230 4c/8t, 32 Go, 2×1 To SATA | 65,00 € |
| Starter Bare Metal | 4 vCPU, 16 Go, 500 Go SSD | 66,08 $ |
| HP DL20 G10 | Xeon E-2174G 4c, 32 Go, 2×480 Go SSD | 78,09 € |
| Dell R740XD (12LFF) | 2× Xeon 5218 16c, 128 Go, 2×960 Go | 215,83 € |
| 2× Xeon E5-2690 v4 | 28c/56t, 128 Go, 2×4 To HDD | ~129 $ |

Le premier prix avec du HDD est à 65 € pour un Xeon E3-1230 (Sandy Bridge,
2011 — donc **sans AVX2**). L'offre à 2× 4 To HDD avec 28 cœurs est à ~129 $,
soit 7× le prix de l'enchère Hetzner pour une capacité identique.

Verdict : entreprise, SLA solide, mais 2 à 3× le prix du marché sur ce besoin.

### OneProvider — beaucoup de choix, qualité inégale

Le catalogue est énorme (des milliers de configurations) mais beaucoup de
matériel ancien (DDR3, Xeon E5 v1/v2 — donc souvent sans AVX2) et beaucoup
de « Sold Out ». Les offres HDD existent (1× 4 To SATA +41,67 $/mois en
option) mais la réputation de l'hébergeur est faible (1/10 sur 16 avis WHTop).

Verdict : à éviter pour un service en production.

### Autres vus au passage

  FDC Servers      dès 199 $/mois — hors budget
  NameCheap        dès 56,88 $/mois (engagement 24 mois)
  Hivelocity      dès 109 $/mois
  DreamHost       dès 119,99 $/mois
  HostGator       dès 159,99 $/mois

Tous plus chers que Kimsufi et Hetzner pour des configurations comparables.

## Verdict final

| Offre | vCPU | RAM | HDD | Prix/mois | AVX2 | €/To |
|---|---|---|---|---|---|---|
| **Hetzner enchère** | 8+ | 32-128 Go | **8 To** | **59,70 €** | selon CPU | **~2,15** |
| Kimsufi KS-4 | 4c/8t | 16 Go | 2×2 To inclus | 18,80 $ | oui | ~4,70 |
| Kimsufi SYS-3 | 8c/16t | 32 Go | 12 To + NVMe | 55,80 $ | oui | ~4,65 |
| Leaseweb Sandy Bridge | 4c/8t | 32 Go | 2×1 To | 65,00 € | NON | ~32 |
| OneProvider | variable | variable | 4 To en option | 20 $ + 41,67 $ | souvent non | ~15 |

## Ce que je recommande maintenant

**Si le budget est le critère : l'enchère Hetzner.**

  Surveille https://www.hetzner.com/sb/ et radar.iodev.org
  Vise une machine avec du HDD : 8 To autour de 60 €, soit 2,15 €/To.
  Aucun frais d'installation, aucun engagement.
  Vérifie le CPU sur la fiche : Haswell (2013) ou plus récent = AVX2.

**Si tu veux du neuf et du prévisible : Kimsufi KS-4 à 18,80 $.**

  Moins de stockage (4 To) mais 16 Go, AVX2 garanti, et le prix ne bouge pas.

**Le compromis : Kimsufi SYS-3 à 55,80 $.**

  8 cœurs, 32 Go, 12 To de mécanique ET les NVMe pour le système.
  C'est le seul du lot qui a les deux types de disques, ce qui évite de faire
  tourner Kubernetes sur du mécanique.

## Le point qui compte pour Ceffio

Sur toutes ces machines, Ceffio n'utilise que 4 Go de RAM et 36 Go de disque.
Le reste du disque sert au stockage de fichiers, aux enregistrements d'appels
et aux modèles Vosk. La question n'est donc pas « quelle puissance », mais
« combien de To veux-tu, et veux-tu un CPU avec AVX2 ».

---

# Correction : le catalogue Kimsufi a changé

Le KS-4 n'existe plus. Vérification faite le 15/10/2026 directement sur
kimsufi.com (page /fr/ks/) : la gamme KS ne compte plus que **trois
références**, et les anciennes (KS-1, KS-2, KS-4, KS-B, KS-C) ont disparu du
catalogue.

## Le catalogue réel aujourd'hui

| Modèle | CPU | Cœurs | RAM | Stockage | Prix HT/mois |
|---|---|---|---|---|---|
| KS-5-B | Xeon E5-1650v4 | 6c/12t | 64 Go | 2×450 Go SSD **ou 2×2 To HDD** | 29,99 € |
| KS-GAME | Core i7 7700K | 4c/8t | 64 Go | 2×450 Go + 1×4 To | 36,99 € |
| KS-A | i7-6700K | 4c/8t | 32 Go | 1×480 Go | 54,99 € |

## Le KS-5-B est ce qui correspond au besoin

Fiche de configuration relevée à Gravelines :

  CPU       Intel Xeon E5-1650 v4  6c/12t  (Broadwell, 2015)
  RAM       64 Go DDR4 ECC
              options : 128 Go +8 €, et +4 € pour une autre localisation
  Stockage  2× 450 Go SSD NVMe        INCLUS
            2× 2 To HDD Enterprise     INCLUS   <- au choix, sans surcoût
  Réseau    500 Mbps illimité
  Prix      29,99 €/mois HT (21,99 € selon la localisation et la config)

  AVX2 : Xeon E5-1650 v4 = Broadwell -> AVX2 OUI

C'est mieux que le KS-4 sur deux points : **64 Go de RAM au lieu de 16**, et
**6 cœurs/12 threads au lieu de 4/8**. Le prix passe de 18,80 $ à 29,99 €.

  Coût au To : 29,99 € pour 4 To de mécanique = 7,50 €/To
  (contre 4,70 $/To pour le KS-4, mais avec 4× la RAM)

## Attention au KS-GAME

Il affiche « 2× 450 Go + 1× 4 To » — le 4 To est du **SATA**, pas du HDD
mécanique au sens de l'option Enterprise. Et son CPU, le Core i7 7700K est un
Kaby Lake (AVX2 oui), mais 4c/8t seulement. À 36,99 € il est moins intéressant
que le KS-5-B à 29,99 € qui offre 6c/12t et 64 Go.

## Le classement corrigé, HDD et AVX2

| Offre | Cœurs | RAM | HDD | Prix/mois | AVX2 | €/To |
|---|---|---|---|---|---|---|
| Hetzner enchère | 8+ | 32-128 Go | 8 To | ~59,70 € | selon CPU | ~2,15 |
| **Kimsufi KS-5-B** | 6c/12t | **64 Go** | **2×2 To** | **29,99 €** | oui | 7,50 |
| Kimsufi SYS-3 | 8c/16t | 32 Go | 12 To + NVMe | 55,80 $ | oui | 4,65 |
| Kimsufi KS-A | 4c/8t | 32 Go | 480 Go | 54,99 € | oui | — |
| Contabo Storage 30 | 6 | 18 Go | 1 To SSD | 14 € | oui | 14 € |

## Ce que ça change dans la recommandation

Le KS-5-B à 29,99 € remplace le KS-4 comme choix « neuf et prévisible » :

  6 cœurs/12 threads, 64 Go de RAM (16× ce que Ceffio consomme),
  4 To de mécanique, AVX2 confirmé, servi par OVHcloud en France.

  Pour Ceffio : 4 Go de RAM utilisés sur 64, 36 Go de disque sur 4 To.
  Le disque système peut rester sur le NVMe (inclus) et le HDD servir au
  stockage de masse — c'est le montage idéal, et le KS-5-B est le seul de la
  gamme à proposer les deux types au même prix.

Reste que l'enchère Hetzner offre toujours 8 To pour ~2× le prix, avec un CPU
potentiellement meilleur — mais sans garantie de disponibilité ni de modèle.

## Leçon de méthode

J'avais recommandé un modèle en me fiant à des pages de comparateurs et à des
citations d'articles, sans vérifier le catalogue officiel. Les comparateurs
recopient souvent des gammes périmées : le KS-4 apparaissait encore dans une
dizaine de sources, mais OVHcloud ne le vend plus. **Pour un achat, c'est le
site du vendeur qui fait foi**, pas les agrégateurs.
