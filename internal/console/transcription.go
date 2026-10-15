// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/exapps"
)

// La transcription en direct, vue depuis la console d'administration.
//
// POURQUOI ELLE EST ICI ET PAS SEULEMENT A L'INSTALLATION. C'est une
// fonctionnalite lourde (~9 Go de disque, ~16 Go de RAM) dont la configuration
// n'est PAS revisable en place : la documentation Nextcloud precise qu'il faut
// desinstaller puis reinstalle l'app pour changer ses variables. La poser a
// l'installation sans etre demande engagerait l'exploitant sur un choix qu'il
// ne pourrait plus defaire simplement.
//
// D'ou deux actions distinctes, exposees ici : installer, et desinstaller
// COMPLETEMENT (charge de travail, service et volume compris).

type etatTranscription struct {
	Installe bool   `json:"installed"`
	Etat     string `json:"state"` // "installed", "absent", "unknown"
	Detail   string `json:"detail,omitempty"`
	Poids    string `json:"weightNote"`
}

type demandeTranscription struct {
	Action string `json:"action"` // "install" | "uninstall"
}

// handleTranscription sert GET (etat) et POST (installer/desinstaller).
//
// Les deux passent par le meme point d'entree : l'etat et l'action portent sur
// la meme ressource, et les separer ferait diverger la lecture de l'etat de ce
// que l'action produit.
func (s *Server) handleTranscription(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.repondreEtatTranscription(w, r)

	case http.MethodPost:
		var d demandeTranscription
		if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
			apiErr(w, http.StatusBadRequest, "corps illisible : "+err.Error())
			return
		}

		var err error
		switch d.Action {
		case "install":
			err = exapps.TranscriptionDeploye(r.Context(), s.Domain)
		case "uninstall":
			err = exapps.TranscriptionSupprime(r.Context())
		default:
			apiErr(w, http.StatusBadRequest,
				"action inconnue : "+d.Action+" (attendu : install ou uninstall)")
			return
		}

		if err != nil {
			// L'erreur est remontee TELLE QUELLE : elle nomme la cause reelle
			// (HaRP absent, coffre injoignable, app deja presente…). La
			// reformuler ici la rendrait moins precise, et c'est exactement le
			// genre de message ou l'on perd du temps a chercher au mauvais
			// endroit.
			apiErr(w, http.StatusInternalServerError, err.Error())
			return
		}

		// On relit l'etat APRES l'action plutot que de le deduire du succes de
		// la commande : c'est le seul temoignage qui distingue « la commande a
		// rendu 0 » de « l'app est effectivement dans cet etat ».
		s.repondreEtatTranscription(w, r)

	default:
		apiErr(w, http.StatusMethodNotAllowed, "methode non autorisee")
	}
}

// repondreEtatTranscription interroge AppAPI, jamais un fichier ni une
// supposition : c'est le seul endroit qui sait ce qui est reellement installe.
func (s *Server) repondreEtatTranscription(w http.ResponseWriter, r *http.Request) {
	etat := etatTranscription{
		Poids: "Environ 9 Go de disque (image et modeles) et 16 Go de RAM pour un ou deux appels simultanes.",
	}

	sortie, err := kubeCombined("exec", "-n", "ceffio-files", "deploy/nextcloud", "-c", "nextcloud",
		"--", "php", "occ", "app_api:app:list")
	if err != nil {
		// On ne conclut PAS « absente » sur un echec : on dit que l'etat est
		// inconnu. Confondre les deux ferait proposer une installation alors
		// qu'une app tourne peut-etre deja.
		etat.Etat = "unknown"
		etat.Detail = "AppAPI injoignable : " + strings.TrimSpace(err.Error())
		writeJSON(w, http.StatusOK, etat)
		return
	}

	if ligne := ligneAppareillee(sortie, "live_transcription"); ligne != "" {
		etat.Installe = true
		etat.Etat = "installed"
		etat.Detail = ligne
	} else {
		etat.Etat = "absent"
	}
	writeJSON(w, http.StatusOK, etat)
}

// ligneAppareillee renvoie la premiere ligne qui MENTIONNE l'app, ou "".
//
// On travaille ligne par ligne plutot que par un « contains » sur toute la
// sortie : le nom apparait aussi dans les libelles, et un contains global
// declarerait installee une app seulement citee.
func ligneAppareillee(texte, app string) string {
	for _, l := range strings.Split(texte, "\n") {
		prop := strings.TrimSpace(l)
		if prop == "" || strings.HasPrefix(prop, "Command") {
			continue
		}
		if strings.Contains(prop, app) {
			return prop
		}
	}
	return ""
}
