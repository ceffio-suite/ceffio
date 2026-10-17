// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package k8sapi

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// LE TEST QUI COMPTE : un objet identique à son manifeste ne doit déclencher
// AUCUNE écriture.
//
// Le clic « Deploy the deployer » échouait sur
//
//	updating Namespace/ceffio-exapps: namespaces is forbidden:
//	User "…:ceffio-admin" cannot update resource "namespaces"
//
// alors que le namespace existait déjà, avec les bons labels. Le code écrivait
// sans comparer, et l'API refusait une opération qui ne changeait rien.
func TestObjetIdentiqueNeDeclenchePasDEcriture(t *testing.T) {
	actuel := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata": map[string]interface{}{
			"name": "ceffio-exapps",
			"labels": map[string]interface{}{
				"app.kubernetes.io/part-of": "ceffio",
				"ceffio.io/role":            "exapps",
			},
			// Champs ajoutés par l'API, absents du manifeste : ils ne doivent
			// PAS faire croire à une différence.
			"resourceVersion": "12345",
			"uid":             "abc-def",
		},
		"status": map[string]interface{}{"phase": "Active"},
	}}
	voulu := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata": map[string]interface{}{
			"name": "ceffio-exapps",
			"labels": map[string]interface{}{
				"app.kubernetes.io/part-of": "ceffio",
				"ceffio.io/role":            "exapps",
			},
		},
	}}

	if !equivalent(actuel, voulu) {
		t.Error("un objet identique est vu comme différent — le code réécrirait " +
			"et redemanderait des droits d'écriture inutiles")
	}
}

// Un vrai changement doit être détecté : sinon le correctif serait pire que le
// bug, en rendant le déploiement incapable de mettre à jour quoi que ce soit.
func TestChangementDetecte(t *testing.T) {
	actuel := &unstructured.Unstructured{Object: map[string]interface{}{
		"metadata": map[string]interface{}{
			"name":   "x",
			"labels": map[string]interface{}{"a": "1"},
		},
	}}
	cas := []struct {
		quoi  string
		voulu map[string]interface{}
	}{
		{"label modifié", map[string]interface{}{
			"metadata": map[string]interface{}{
				"name": "x", "labels": map[string]interface{}{"a": "2"}}}},
		{"label ajouté", map[string]interface{}{
			"metadata": map[string]interface{}{
				"name": "x", "labels": map[string]interface{}{"a": "1", "b": "2"}}}},
		{"champ nouveau", map[string]interface{}{
			"metadata": map[string]interface{}{
				"name": "x", "labels": map[string]interface{}{"a": "1"}},
			"spec": map[string]interface{}{"replicas": int64(2)}}},
	}
	for _, c := range cas {
		if equivalent(actuel, &unstructured.Unstructured{Object: c.voulu}) {
			t.Errorf("%s vu comme identique — la mise à jour ne serait jamais appliquée", c.quoi)
		}
	}
}

// Les listes sont comparées sans tenir compte de l'ordre : l'API réordonne
// certains tableaux, et une comparaison par index signalerait une différence
// là où le contenu est identique.
func TestListesCompareesSansOrdre(t *testing.T) {
	actuel := &unstructured.Unstructured{Object: map[string]interface{}{
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{"name": "b"},
				map[string]interface{}{"name": "a"},
			},
		},
	}}
	voulu := &unstructured.Unstructured{Object: map[string]interface{}{
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{"name": "a"},
				map[string]interface{}{"name": "b"},
			},
		},
	}}
	if !equivalent(actuel, voulu) {
		t.Error("même contenu dans un autre ordre vu comme différent")
	}
}

// Une liste plus courte ou plus longue est un vrai changement.
func TestListeDeTailleDifferente(t *testing.T) {
	actuel := &unstructured.Unstructured{Object: map[string]interface{}{
		"spec": map[string]interface{}{
			"containers": []interface{}{map[string]interface{}{"name": "a"}},
		},
	}}
	voulu := &unstructured.Unstructured{Object: map[string]interface{}{
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{"name": "a"},
				map[string]interface{}{"name": "b"},
			},
		},
	}}
	if equivalent(actuel, voulu) {
		t.Error("une liste plus longue vue comme identique")
	}
}
