package expos

import (
	"encoding/json"
	"fmt"
	"os"
)

// LireConfig charge la configuration de publication depuis un fichier JSON.
//
// Pourquoi un fichier plutôt que des options : la configuration contient le
// chemin d'un fichier d'identifiants, et rassembler les deux sur une ligne de
// commande invite à écrire un secret dans l'historique du shell.
//
// Le fichier est cherché dans ce programme-ci, jamais dans le dépôt : il décrit
// l'infrastructure locale (adresse du pare-feu, IP interne), pas l'application.
func LireConfig(chemin string) (Config, error) {
	b, err := os.ReadFile(chemin)
	if err != nil {
		return Config{}, fmt.Errorf("configuration %s illisible : %w\n\n"+
			"Exemple de fichier :\n%s", chemin, err, exemple)
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, fmt.Errorf("configuration %s invalide : %w", chemin, err)
	}

	// Valeurs par défaut : l'installation de référence porte *.ceffio.mandem-it.com.
	if cfg.Domaine == "" {
		cfg.Domaine = "ceffio.mandem-it.com"
	}
	if cfg.PortInterne == "" {
		cfg.PortInterne = "80"
	}
	if len(cfg.SousDomaines) == 0 {
		cfg.SousDomaines = []string{"cloud", "keycloak", "office", "admin"}
	}
	return cfg, nil
}

const exemple = `{
  "hoteAPI": "opn.datalock.mandem-it.com",
  "fichierCle": "~/.config/opnsense/apikey.txt",
  "domaine": "ceffio.mandem-it.com",
  "ipInterne": "192.168.1.48",
  "portInterne": "80",
  "sousDomaines": ["cloud", "keycloak", "office", "admin"]
}`
