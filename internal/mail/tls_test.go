// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Guards on the TLS step: Stalwart must serve the certificate of the `mail-tls`
// Secret, the object it declares must point at the mounted FILES, and a replay
// of the installation must not touch the server.
//
// WHY THESE TESTS EXIST: the failure this step repairs is invisible — Stalwart
// serves its own `CN=rcgen self signed cert` and every client rejects it, while
// nothing in the cluster looks broken. Three things therefore have to be fixed
// by a test rather than by a comment: the EXACT object (a wrong `@type` is
// accepted by nobody and the error surfaces minutes later), the fact that a
// changed Secret recreates the object (a `File` certificate is read at LOAD
// time, so editing the files changes nothing until the object is reloaded), and
// the absence of writes on a replay (an installation is replayed at every
// version, and each reload cuts nothing but is not free either).
package mail

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

// fauxTLS is a JMAP endpoint holding the certificates, the SystemSettings
// singleton and the action log, shaped like POC 9.C measured on 1.0.3.
type fauxTLS struct {
	certificats map[string]map[string]any // id → object as read back
	defaut      string
	appels      []string
	creation    []map[string]any // the `create` payload of every x:Certificate/set
	detruits    []string
	reloads     int
	prochainID  int
}

func nouveauFauxTLS() *fauxTLS {
	return &fauxTLS{
		certificats: map[string]map[string]any{},
		prochainID:  1,
	}
}

func (f *fauxTLS) transport(_ context.Context, corps []byte) ([]byte, error) {
	var enveloppe struct {
		MethodCalls [][]json.RawMessage `json:"methodCalls"`
	}
	if err := json.Unmarshal(corps, &enveloppe); err != nil {
		return nil, err
	}
	var methode string
	_ = json.Unmarshal(enveloppe.MethodCalls[0][0], &methode)
	var args map[string]any
	_ = json.Unmarshal(enveloppe.MethodCalls[0][1], &args)
	f.appels = append(f.appels, methode)

	reponse := map[string]any{}
	switch methode {
	case "x:Certificate/set":
		if creer, ok := args["create"].(map[string]any); ok {
			for _, brut := range creer {
				objet, _ := brut.(map[string]any)
				f.creation = append(f.creation, objet)
				id := fmt.Sprintf("cert-%d", f.prochainID)
				f.prochainID++
				// THE OBJECT AS THE SERVER DERIVES IT FROM THE FILES: issuer,
				// SANs and expiry are the proof the files were parsed, and that
				// is what the read-back inspects.
				f.certificats[id] = map[string]any{
					"id":                      id,
					"issuer":                  "CN=example-ca",
					"subjectAlternativeNames": map[string]any{"mail.example.com": true},
					"notValidAfter":           "2027-01-01T00:00:00Z",
				}
				reponse["created"] = map[string]any{"ceffio-mail": map[string]any{"id": id}}
			}
		}
		if detruire, ok := args["destroy"].([]any); ok {
			var ids []any
			for _, d := range detruire {
				id, _ := d.(string)
				f.detruits = append(f.detruits, id)
				delete(f.certificats, id)
				ids = append(ids, id)
			}
			reponse["destroyed"] = ids
		}
	case "x:Certificate/get":
		var liste []any
		demandes, _ := args["ids"].([]any)
		ids := make([]string, 0, len(demandes))
		for _, d := range demandes {
			id, _ := d.(string)
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			if objet, ok := f.certificats[id]; ok {
				liste = append(liste, objet)
			}
		}
		if liste == nil {
			liste = []any{}
		}
		reponse["list"] = liste
		reponse["notFound"] = []any{}
	case "x:SystemSettings/get":
		reponse["list"] = []any{map[string]any{
			"id": "singleton", "defaultCertificateId": nilIfEmpty(f.defaut),
		}}
		reponse["notFound"] = []any{}
	case "x:SystemSettings/set":
		maj, _ := args["update"].(map[string]any)
		if singleton, ok := maj["singleton"].(map[string]any); ok {
			if id, ok := singleton["defaultCertificateId"].(string); ok {
				f.defaut = id
			}
		}
		reponse["updated"] = map[string]any{"singleton": nil}
	case "x:Action/set":
		f.reloads++
		reponse["created"] = map[string]any{"reload-tls": map[string]any{"id": "a1"}}
	}
	brut, err := json.Marshal(map[string]any{
		"methodResponses": []any{[]any{methode, reponse, "c1"}},
	})
	return brut, err
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// installerFauxTLS poses the fake endpoint and a cluster holding the `mail-tls`
// Secret, and returns both so a test can change the Secret or count the writes.
func installerFauxTLS(t *testing.T) (*fauxTLS, *kubefake.Clientset) {
	t.Helper()
	faux := nouveauFauxTLS()
	ancienTransport := transportJMAP
	transportJMAP = faux.transport
	t.Cleanup(func() { transportJMAP = ancienTransport })

	cs := kubefake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: SecretTLS, Namespace: ns, ResourceVersion: "1"},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": []byte("CERT"), "tls.key": []byte("KEY")},
	})
	ancienClient := clientK8s
	clientK8s = func() (*k8sapi.Client, error) { return k8sapi.PourTest(cs, nil), nil }
	t.Cleanup(func() { clientK8s = ancienClient })
	return faux, cs
}

// compter compte les appels d'un nom donné.
func (f *fauxTLS) compter(methode string) int {
	n := 0
	for _, appel := range f.appels {
		if appel == methode {
			n++
		}
	}
	return n
}

// TestAssurerTLSDeclareLeCertificatDepuisLesFichiers fixes the EXACT object:
// a `File` certificate and a `File` key, at the paths the Secret is mounted on.
//
// A COPY OF THE PEM WOULD LOOK SIMPLER and would silently stop following the
// renewal: cert-manager rewrites the Secret, nothing re-reads it, and the
// server keeps serving the expired leaf.
func TestAssurerTLSDeclareLeCertificatDepuisLesFichiers(t *testing.T) {
	faux, cs := installerFauxTLS(t)
	ctx := context.Background()
	if err := AssurerTLS(ctx, "example.com"); err != nil {
		t.Fatalf("AssurerTLS: %v", err)
	}
	if len(faux.creation) != 1 {
		t.Fatalf("expected exactly one certificate creation, got %d: %v", len(faux.creation), faux.creation)
	}
	attendu := `{"certificate":{"@type":"File","filePath":"/etc/stalwart/tls/tls.crt"},` +
		`"privateKey":{"@type":"File","filePath":"/etc/stalwart/tls/tls.key"}}`
	obtenu, _ := json.Marshal(faux.creation[0])
	if string(obtenu) != attendu {
		t.Fatalf("certificate object:\n  got      %s\n  expected %s", obtenu, attendu)
	}
	if faux.defaut != "cert-1" {
		t.Errorf("defaultCertificateId = %q, expected the created certificate (cert-1)", faux.defaut)
	}
	if faux.reloads != 1 {
		t.Errorf("ReloadTlsCertificates sent %d time(s), expected once", faux.reloads)
	}
	// THE STATE IS REMEMBERED IN ITS OWN CONFIGMAP, never in `stalwart-config`:
	// that one is applied from a manifest, and an apply replaces the whole
	// object, wiping any bookkeeping stored there.
	cm, err := cs.CoreV1().ConfigMaps(ns).Get(ctx, configTLS, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("reading the state ConfigMap: %v", err)
	}
	if cm.Data["resourceVersion"] != "1" || cm.Data["certificateId"] != "cert-1" {
		t.Errorf("state ConfigMap = %v, expected resourceVersion=1 certificateId=cert-1", cm.Data)
	}
}

// TestAssurerTLSIdempotent: an unchanged Secret means a replay writes nothing to
// the server — the certificate is re-read, not re-created.
func TestAssurerTLSIdempotent(t *testing.T) {
	faux, _ := installerFauxTLS(t)
	ctx := context.Background()
	if err := AssurerTLS(ctx, "example.com"); err != nil {
		t.Fatalf("first AssurerTLS: %v", err)
	}
	creations, reloads, detruits := len(faux.creation), faux.reloads, len(faux.detruits)
	if err := AssurerTLS(ctx, "example.com"); err != nil {
		t.Fatalf("second AssurerTLS: %v", err)
	}
	if len(faux.creation) != creations {
		t.Errorf("the second run created %d certificate(s)", len(faux.creation)-creations)
	}
	if faux.reloads != reloads {
		t.Errorf("the second run sent %d reload(s)", faux.reloads-reloads)
	}
	if len(faux.detruits) != detruits {
		t.Errorf("the second run destroyed %d certificate(s)", len(faux.detruits)-detruits)
	}
}

// TestAssurerTLSRecreeApresRenouvellement: a new Secret version means the files
// changed, and a `File` certificate only re-reads them when the object is
// recreated — the old one is destroyed and the new one becomes the default.
func TestAssurerTLSRecreeApresRenouvellement(t *testing.T) {
	faux, cs := installerFauxTLS(t)
	ctx := context.Background()
	if err := AssurerTLS(ctx, "example.com"); err != nil {
		t.Fatalf("first AssurerTLS: %v", err)
	}
	sec, err := cs.CoreV1().Secrets(ns).Get(ctx, SecretTLS, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("reading the Secret: %v", err)
	}
	sec.ResourceVersion = "2"
	if _, err := cs.CoreV1().Secrets(ns).Update(ctx, sec, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("updating the Secret: %v", err)
	}
	if err := AssurerTLS(ctx, "example.com"); err != nil {
		t.Fatalf("AssurerTLS after renewal: %v", err)
	}
	if len(faux.creation) != 2 {
		t.Fatalf("expected a second certificate, got %d creation(s)", len(faux.creation))
	}
	if len(faux.detruits) != 1 || faux.detruits[0] != "cert-1" {
		t.Errorf("the previous certificate should have been destroyed, destroyed: %v", faux.detruits)
	}
	if faux.defaut != "cert-2" {
		t.Errorf("defaultCertificateId = %q, expected cert-2", faux.defaut)
	}
	cm, err := cs.CoreV1().ConfigMaps(ns).Get(ctx, configTLS, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("reading the state ConfigMap: %v", err)
	}
	if cm.Data["resourceVersion"] != "2" || cm.Data["certificateId"] != "cert-2" {
		t.Errorf("state ConfigMap = %v, expected resourceVersion=2 certificateId=cert-2", cm.Data)
	}
}

// TestAssurerTLSSansSecretNeRefusePas: a missing or empty Secret is an EXTERNAL
// prerequisite (§4.1) — cert-manager has not issued yet. Install says so and
// carries on; refusing here would block an installation on something it does
// not control.
func TestAssurerTLSSansSecretNeRefusePas(t *testing.T) {
	faux := nouveauFauxTLS()
	ancienTransport := transportJMAP
	transportJMAP = faux.transport
	t.Cleanup(func() { transportJMAP = ancienTransport })

	cs := kubefake.NewSimpleClientset()
	ancienClient := clientK8s
	clientK8s = func() (*k8sapi.Client, error) { return k8sapi.PourTest(cs, nil), nil }
	t.Cleanup(func() { clientK8s = ancienClient })

	if err := AssurerTLS(context.Background(), "example.com"); err != nil {
		t.Fatalf("a missing Secret must not fail the installation: %v", err)
	}
	if len(faux.appels) != 0 {
		t.Fatalf("the server was called %v with no certificate to declare", faux.appels)
	}
	if _, err := cs.CoreV1().ConfigMaps(ns).Get(context.Background(), configTLS, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("no state must be recorded when nothing was done, got %v", err)
	}
}

// TestCouvreHote fixes the wildcard rule the SAN warning depends on.
func TestCouvreHote(t *testing.T) {
	cas := []struct {
		noms   []string
		hote   string
		couvre bool
	}{
		{[]string{"mail.example.com"}, "mail.example.com", true},
		{[]string{"MAIL.Example.com"}, "mail.example.com", true},
		{[]string{"*.example.com"}, "mail.example.com", true},
		{[]string{"*.example.com"}, "example.com", false},
		{[]string{"*.example.com"}, "a.b.example.com", false},
		{[]string{"example.com"}, "mail.example.com", false},
		{[]string{}, "mail.example.com", false},
	}
	for _, c := range cas {
		if obtenu := couvreHote(c.noms, c.hote); obtenu != c.couvre {
			t.Errorf("couvreHote(%v, %s) = %v, expected %v", c.noms, c.hote, obtenu, c.couvre)
		}
	}
}

// TestSujetsAlternatifsTrie proves the SAN map is flattened and sorted: the
// warning message reads the list, and an unsorted one makes two runs print two
// different sentences for the same state.
func TestSujetsAlternatifsTrie(t *testing.T) {
	noms := sujetsAlternatifs(map[string]any{
		"subjectAlternativeNames": map[string]any{"mail.example.com": true, "autodiscover.example.com": true},
	})
	obtenu := strings.Join(noms, ",")
	if obtenu != "autodiscover.example.com,mail.example.com" {
		t.Fatalf("SANs = %s, expected them sorted", obtenu)
	}
}
