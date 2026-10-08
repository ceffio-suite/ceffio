package main

import (
	"fmt"
	"os"

	"github.com/ceffio-suite/ceffio/internal/expos"
	"github.com/spf13/cobra"
)

func newExposeCmd() *cobra.Command {
	var cfgFichier string
	var oui bool

	c := &cobra.Command{
		Use:   "expose",
		Short: "Publier la suite derrière le pare-feu (OPNsense + os-caddy)",
		Long: `Déclare les domaines publics de Ceffio côté pare-feu et les route vers la VM.

Déployer ne suffit pas à rendre la suite joignable : le pare-feu termine le TLS
public et doit connaître chaque domaine. Sans cette étape, le DNS répond mais
rien n'arrive au cluster.

Ordre complet d'une publication :
  1. l'enregistrement DNS public existe          (créé par l'exploitant)
  2. le certificat wildcard existe sur le pare-feu (créé par l'exploitant)
  3. les domaines + handlers sont déclarés         <- cette commande
  4. les hôtes publics sont ajoutés aux Ingress Traefik (fait par install/upgrade)

La configuration est lue dans un fichier (--config) : identifiants du pare-feu,
domaine, cible interne. Aucune valeur n'est écrite dans le dépôt.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := expos.LireConfig(cfgFichier)
			if err != nil {
				return err
			}

			fmt.Println("Ceffio — publication derrière le pare-feu")
			fmt.Println()
			fmt.Printf("Pare-feu : %s\n", cfg.HoteAPI)
			fmt.Printf("Domaine  : %s\n", cfg.Domaine)
			fmt.Printf("Cible    : %s:%s\n", cfg.IPInterne, cfg.PortInterne)
			fmt.Println()

			if !oui {
				fmt.Println("Les domaines suivants seront déclarés :")
				for _, s := range cfg.SousDomaines {
					fmt.Printf("  %s.%s\n", s, cfg.Domaine)
				}
				fmt.Print("\nConfirmer (tapez « oui ») : ")
				var rep string
				fmt.Scanln(&rep)
				if rep != "oui" {
					fmt.Println("Annulé.")
					return nil
				}
				fmt.Println()
			}

			res, err := expos.Publier(cmd.Context(), cfg, func(e string) {
				fmt.Printf("  · %s\n", e)
			})
			if err != nil {
				if res != nil && len(res.Creés) > 0 {
					fmt.Println()
					for _, d := range res.Creés {
						fmt.Printf("  ✓ %s\n", d)
					}
				}
				return err
			}

			fmt.Println()
			for _, d := range res.Existants {
				fmt.Printf("  = %s (déjà déclaré)\n", d)
			}
			for _, d := range res.Creés {
				fmt.Printf("  + %s\n", d)
			}
			fmt.Println()
			fmt.Printf("✓ %d domaine(s) publié(s), certificat %s\n", len(res.Creés), res.Certificat)
			fmt.Println()
			fmt.Println("Vérifiez depuis l'extérieur :")
			for _, d := range cfg.SousDomaines {
				fmt.Printf("  curl -sI https://%s.%s/\n", d, cfg.Domaine)
			}
			return nil
		},
	}

	c.Flags().StringVar(&cfgFichier, "config", "ceffio-expose.json", "Fichier de configuration de publication")
	c.Flags().BoolVar(&oui, "yes", false, "Ne pas demander de confirmation")

	return c
}

var _ = os.Getenv
