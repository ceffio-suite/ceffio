// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/exapps"
	"github.com/ceffio-suite/ceffio/internal/k8sapi"
)

// Les applications externes (ExApps), vues depuis la console.
//
// DEUX CHOSES DISTINCTES, et les confondre etait l'erreur de la premiere
// version. Le deployeur (HaRP) est de l'INFRASTRUCTURE : sans lui, Nextcloud ne
// peut installer aucune ExApp. L'application de transcription est un USAGE, qui
// depend du premier. On expose donc deux ressources separees, avec chacune son
// etat et ses actions, plutot qu'un seul ecran qui melangeait les deux et ne
// disait pas lequel manquait.

type etatDeployeur struct {
	Installe bool   `json:"installed"`
	Etat     string `json:"state"` // "running", "absent", "degraded", "unknown"
	Registry bool   `json:"registered"`
	Detail   string `json:"detail,omitempty"`
}

// handleExapps sert l'etat du deployeur (GET) et ses actions (POST).
func (s *Server) handleExapps(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.repondreEtatDeployeur(w, r)
	case http.MethodPost:
		var d demandeTranscription
		if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
			apiErr(w, http.StatusBadRequest, "corps illisible : "+err.Error())
			return
		}
		switch d.Action {
		case "install":
			if err := exapps.Deploy(r.Context(), s.Domain); err != nil {
				apiErr(w, http.StatusInternalServerError, err.Error())
				return
			}
		case "uninstall":
			if err := exapps.Remove(r.Context()); err != nil {
				apiErr(w, http.StatusInternalServerError, err.Error())
				return
			}
		default:
			apiErr(w, http.StatusBadRequest, "action inconnue : "+d.Action)
			return
		}
		s.repondreEtatDeployeur(w, r)
	default:
		apiErr(w, http.StatusMethodNotAllowed, "methode non autorisee")
	}
}

// repondreEtatDeployeur lit l'etat REEL du deployeur : le pod, et son
// enregistrement dans AppAPI. Les deux sont necessaires — un HaRP qui tourne
// mais que Nextcloud ne connait pas n'installe rien, et c'est exactement l'etat
// ou l'on retombe quand l'enregistrement echoue.
func (s *Server) repondreEtatDeployeur(w http.ResponseWriter, r *http.Request) {
	etat := etatDeployeur{}

	cli, err := k8sapi.Nouveau()
	if err != nil {
		etat.Etat = "unknown"
		etat.Detail = "Kubernetes injoignable : " + err.Error()
		writeJSON(w, http.StatusOK, etat)
		return
	}
	nomHarp, nsHarp := exapps.NomsHarp()
	etat.Installe = cli.DeploiementPret(r.Context(), nsHarp, nomHarp)

	sortie, err := s.occScript(r.Context(), "php occ app_api:daemon:list")
	if err == nil {
		etat.Registry = strings.Contains(strings.ToLower(sortie), nomHarp)
	}

	switch {
	case etat.Installe && etat.Registry:
		etat.Etat = "running"
	case etat.Installe && !etat.Registry:
		// The subtlest of the three: HaRP is up and usable, but Nextcloud does
		// not know it. ExApps then install and never enable, with nothing in
		// the logs pointing at the registration. Saying it here saves the hunt.
		etat.Etat = "degraded"
		etat.Detail = "HaRP tourne mais n'est pas enregistre dans Nextcloud : les applications s'installeraient sans jamais s'activer."
	case !etat.Installe && etat.Registry:
		etat.Etat = "degraded"
		etat.Detail = "Enregistre dans Nextcloud, mais le pod HaRP est absent."
	default:
		etat.Etat = "absent"
	}
	writeJSON(w, http.StatusOK, etat)
}
