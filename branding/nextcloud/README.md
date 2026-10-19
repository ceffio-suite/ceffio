# Thème Nextcloud de Ceffio

Habille Nextcloud aux couleurs de Ceffio : nom, slogan, couleurs, logo, icône d'onglet et fond d'écran. Tout passe par l'application **Theming** intégrée à Nextcloud (`occ theming:config`) : pas de dossier de thème, pas de CSS maison, rien qu'une mise à jour de Nextcloud puisse écraser.

## Ce que contient le thème

| Fichier | Clé Theming | Où il apparaît |
|---|---|---|
| `logo.svg` | `logo` | Page de connexion, en-tête des e-mails. Version claire, pour fond sombre. |
| `logoheader.svg` | `logoheader` | En haut à gauche de chaque page. Le symbole seul. |
| `favicon.png` | `favicon` | Onglet du navigateur, icône d'application. 512 × 512. |
| `background.jpg` | `background` | Fond de la page de connexion et de l'en-tête. 2560 × 1440. |
| `logo-ink.svg` | — | Variante foncée pour fond clair (documents, site). Non utilisée par Nextcloud. |
| `background.svg`, `favicon.svg` | — | Sources vectorielles des fichiers ci-dessus. |
| `build-assets.py` | — | Régénère les SVG depuis la police Sora (le mot « ceffio » est vectorisé : aucune police à charger côté navigateur). |

| Réglage | Valeur | Rôle |
|---|---|---|
| `name` | Ceffio | Titre des pages, e-mails, notifications |
| `slogan` | La suite collaborative souveraine | Sous le logo de la page de connexion |
| `url` | https://github.com/ceffio-suite/ceffio | Lien du pied de page |
| `primary_color` | `#2B4FD8` | Boutons, liens, focus (contraste 6,5:1 sur blanc) |
| `background_color` | `#12151C` | Teinte de fond derrière l'image |

Les utilisateurs gardent le choix du thème clair ou sombre dans leurs paramètres.

## Appliquer le thème à la main

Sur une installation qui tourne :

```bash
./apply-theming.sh
```

Variables facultatives : `CEFFIO_URL`, `CEFFIO_SLOGAN`, `CEFFIO_PRIMARY`, `CEFFIO_BACKGROUND`, `CEFFIO_IMPRINT_URL`, `CEFFIO_PRIVACY_URL` (mentions légales et politique de confidentialité, affichées en pied de page de la connexion).

Pour revenir au thème d'origine : `kubectl -n ceffio-files exec deploy/nextcloud -c nextcloud -- php occ theming:config <clé> --reset`, clé par clé.

## Régénérer les images

```bash
npm i @fontsource/sora && pip install fonttools brotli
python3 build-assets.py node_modules/@fontsource/sora/files/sora-latin-600-normal.woff2 .
```

`background.jpg` et `favicon.png` se rendent ensuite depuis leurs SVG (navigateur sans interface, Inkscape ou rsvg-convert).
