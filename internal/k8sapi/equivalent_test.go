// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package k8sapi

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// THE TEST THAT COUNTS: an object identical to its manifest must
// trigger NO write.
//
// The "Deploy the deployer" click failed on
//
//	updating Namespace/ceffio-exapps: namespaces is forbidden:
//	User "…:ceffio-admin" cannot update resource "namespaces"
//
// while the namespace already existed, with the right labels. The code
// wrote without comparing, and the API refused an operation that changed nothing.
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
			// Fields added by the API, absent from the manifest: they must NOT
			// make one believe in a difference.
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

// A real change must be detected: otherwise the fix would be worse
// than the bug, by making the deployment incapable of updating anything.
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

// Lists are compared without regard to order: the API reorders some
// arrays, and an index-based comparison would report a difference
// where the content is identical.
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

// A shorter or longer list is a real change.
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
