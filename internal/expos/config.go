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

	// Valeurs par défaut : l'installation de référence porte *.ceffio.example.com.
	if cfg.Domaine == "" {
		cfg.Domaine = "ceffio.example.com"
	}
	if cfg.PortInterne == "" {
		cfg.PortInterne = "80"
	}
	if len(cfg.SousDomaines) == 0 {
		// « bao » fait partie de la suite au même titre que les autres : le coffre
		// a besoin d'une adresse PUBLIQUE parce que l'authentification OIDC
		// renvoie le navigateur vers une adresse de retour. Sans cette entrée, le
		// DNS répond et le certificat est valide, mais rien n'arrive au cluster :
		// le pare-feu rend une réponse vide, ce qui ressemble à une panne du
		// service alors que seule la route manque.
		cfg.SousDomaines = []string{"cloud", "keycloak", "office", "admin", "bao"}
	}
	return cfg, nil
}

// L'exemple porte des ESPACES RESERVES, jamais une adresse réelle : un dépôt
// public n'est pas un carnet d'infrastructure — une IP y est de la
// reconnaissance, elle situe le réseau de celui qui l'a publiée.
const exemple = `{
  "hoteAPI": "firewall-api.example.com",
  "fichierCle": "~/.config/opnsense/apikey.txt",
  "domaine": "ceffio.example.com",
  "ipInterne": "IP-INTERNE-DU-CLUSTER",
  "portInterne": "80",
  "sousDomaines": ["cloud", "keycloak", "office", "admin"]
}`
