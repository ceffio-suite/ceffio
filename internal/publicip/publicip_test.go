// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package publicip

import (
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// paquetReponse builds a Binding Success response carrying an
// XOR-MAPPED-ADDRESS for ip:port, answered to tx.
func paquetReponse(t *testing.T, ip string, port uint16, tx [12]byte) []byte {
	t.Helper()
	adresse := net.ParseIP(ip).To4()
	if adresse == nil {
		t.Fatalf("%q is not an IPv4 address", ip)
	}
	cookie := make([]byte, 4)
	binary.BigEndian.PutUint32(cookie, stunMagicCookie)

	valeur := make([]byte, 8)
	valeur[1] = 0x01 // IPv4
	binary.BigEndian.PutUint16(valeur[2:4], port^uint16(stunMagicCookie>>16))
	for i := 0; i < 4; i++ {
		valeur[4+i] = adresse[i] ^ cookie[i]
	}

	attr := make([]byte, 4+len(valeur))
	binary.BigEndian.PutUint16(attr[0:2], stunAttrXORMapped)
	binary.BigEndian.PutUint16(attr[2:4], uint16(len(valeur)))
	copy(attr[4:], valeur)

	entete := make([]byte, 20)
	binary.BigEndian.PutUint16(entete[0:2], stunBindingSuccess)
	binary.BigEndian.PutUint16(entete[2:4], uint16(len(attr)))
	binary.BigEndian.PutUint32(entete[4:8], stunMagicCookie)
	copy(entete[8:20], tx[:])
	return append(entete, attr...)
}

func TestAnalyserReponseLitXORMappedAddress(t *testing.T) {
	var tx [12]byte
	copy(tx[:], "0123456789ab")

	ip, err := analyserReponse(paquetReponse(t, "203.0.113.7", 54321, tx), tx)
	if err != nil {
		t.Fatalf("analyserReponse: %v", err)
	}
	if ip != "203.0.113.7" {
		t.Fatalf("address = %q, want 203.0.113.7", ip)
	}
}

// A response with the wrong transaction id is not our answer: accepting it
// would let any host on the path dictate the address the suite announces.
func TestAnalyserReponseRejetteUneAutreTransaction(t *testing.T) {
	var tx, autre [12]byte
	copy(tx[:], "0123456789ab")
	copy(autre[:], "ba9876543210")

	if _, err := analyserReponse(paquetReponse(t, "203.0.113.7", 54321, autre), tx); err == nil {
		t.Fatal("a response for another transaction was accepted")
	}
}

func TestConsensusMajoritaire(t *testing.T) {
	a, ok := consensus([]reponse{
		{ip: "198.51.100.4", source: "stun:a"},
		{ip: "198.51.100.4", source: "stun:b"},
		{ip: "203.0.113.9", source: "stun:c"},
	}, "stun")
	if !ok {
		t.Fatal("a 2-of-3 majority was refused")
	}
	if a.IPv4 != "198.51.100.4" || a.Sources != 2 || a.Total != 3 {
		t.Fatalf("got %+v, want 198.51.100.4 2/3", a)
	}
	if len(a.Divergence) != 1 {
		t.Fatalf("divergence = %v, want the single dissenting source", a.Divergence)
	}
}

// Three different answers mean the NAT is not telling one story: refusing is
// the only honest outcome, and the caller falls through to HTTP.
func TestConsensusRefuseSansAccord(t *testing.T) {
	if _, ok := consensus([]reponse{
		{ip: "198.51.100.4"}, {ip: "198.51.100.5"}, {ip: "198.51.100.6"},
	}, "stun"); ok {
		t.Fatal("a three-way disagreement was accepted as consensus")
	}
}

// One answer is better than none on a network that reaches a single server.
func TestConsensusAccepteUneSeuleReponse(t *testing.T) {
	a, ok := consensus([]reponse{{ip: "198.51.100.4"}, {err: errTest}}, "stun")
	if !ok || a.Sources != 1 || a.Total != 1 {
		t.Fatalf("a single answer was refused: %+v ok=%v", a, ok)
	}
}

var errTest = &erreurTest{}

type erreurTest struct{}

func (*erreurTest) Error() string { return "unreachable" }

func TestDecouvrirStaticIgnoreLesSources(t *testing.T) {
	a, err := Decouvrir(context.Background(), Config{Static: "192.0.2.10", STUN: []string{"invalid"}}, nil)
	if err != nil {
		t.Fatalf("Decouvrir: %v", err)
	}
	if a.IPv4 != "192.0.2.10" || a.Source != "static" {
		t.Fatalf("got %+v, want the static address", a)
	}
}

func TestDecouvrirHTTPEnSecours(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("198.51.100.9\n"))
	}))
	defer srv.Close()

	a, err := Decouvrir(context.Background(), Config{HTTP: []string{srv.URL}}, srv.Client())
	if err != nil {
		t.Fatalf("Decouvrir: %v", err)
	}
	if a.IPv4 != "198.51.100.9" || a.Source != "http" {
		t.Fatalf("got %+v, want the HTTP answer", a)
	}
}

func TestPublierPuisLire(t *testing.T) {
	cs := fake.NewSimpleClientset()
	ctx := context.Background()

	voulu := Adresse{IPv4: "198.51.100.4", Source: "stun", Sources: 3, Total: 3}
	if err := Publier(ctx, cs, voulu); err != nil {
		t.Fatalf("Publier: %v", err)
	}
	lu, ok, err := Lire(ctx, cs)
	if err != nil || !ok {
		t.Fatalf("Lire: ok=%v err=%v", ok, err)
	}
	if lu.IPv4 != "198.51.100.4" || lu.Source != "stun" || lu.Sources != 3 || lu.Total != 3 {
		t.Fatalf("got %+v", lu)
	}

	// A second publication must UPDATE, not fail: that is the refresh path.
	if err := Publier(ctx, cs, Adresse{IPv4: "203.0.113.8", Source: "stun", Sources: 2, Total: 2}); err != nil {
		t.Fatalf("second Publier: %v", err)
	}
	lu, _, _ = Lire(ctx, cs)
	if lu.IPv4 != "203.0.113.8" {
		t.Fatalf("address = %q, want the refreshed one", lu.IPv4)
	}
}

func TestLireAbsentNEstPasUneErreur(t *testing.T) {
	_, ok, err := Lire(context.Background(), fake.NewSimpleClientset())
	if err != nil {
		t.Fatalf("Lire on an empty cluster: %v", err)
	}
	if ok {
		t.Fatal("an absent ConfigMap was reported as published")
	}
}

func TestPropagerAnnoteLesConsommateurs(t *testing.T) {
	cs := fake.NewSimpleClientset(&appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "janus",
			Namespace: "ceffio-video",
			Labels:    map[string]string{LabelConsommateur: "true"},
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "janus"}},
			},
		},
	})
	if err := Propager(context.Background(), cs, Adresse{IPv4: "198.51.100.4"}, []string{"ceffio-video"}); err != nil {
		t.Fatalf("Propager: %v", err)
	}
	d, err := cs.AppsV1().Deployments("ceffio-video").Get(context.Background(), "janus", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Spec.Template.Annotations[AnnotationIP]; got != "198.51.100.4" {
		t.Fatalf("annotation = %q, want the address", got)
	}

	// THE MIRROR IS THE POINT: a pod only resolves a ConfigMap from its own
	// namespace, so without this copy the consumer's env is silently empty.
	cm, err := cs.CoreV1().ConfigMaps("ceffio-video").Get(context.Background(), Nom, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("the consumer namespace has no %s ConfigMap: %v", Nom, err)
	}
	if cm.Data[CleIPv4] != "198.51.100.4" {
		t.Fatalf("mirror ipv4 = %q, want the address", cm.Data[CleIPv4])
	}
}

// An unlabelled Deployment must not be restarted: rolling something that never
// asked for the address would drop media for nothing.
func TestPropagerIgnoreLesNonConsommateurs(t *testing.T) {
	cs := fake.NewSimpleClientset(&appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "autre", Namespace: "ceffio-video"},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "autre"}},
			},
		},
	})
	if err := Propager(context.Background(), cs, Adresse{IPv4: "198.51.100.4"}, []string{"ceffio-video"}); err != nil {
		t.Fatalf("Propager: %v", err)
	}
	d, _ := cs.AppsV1().Deployments("ceffio-video").Get(context.Background(), "autre", metav1.GetOptions{})
	if _, set := d.Spec.Template.Annotations[AnnotationIP]; set {
		t.Fatal("an unlabelled deployment was rolled")
	}
}

func TestValiderConfig(t *testing.T) {
	cas := []struct {
		nom     string
		cfg     Config
		attendu int
	}{
		{"défaut valide", Defaut(), 0},
		{"IP statique invalide", Config{Static: "pas-une-ip"}, 1},
		{"STUN sans port", Config{STUN: []string{"stun.example.com"}}, 1},
		{"aucune source", Config{}, 1},
		{"intervalle trop court", Config{STUN: DefaultSTUN, Interval: "1s"}, 1},
	}
	for _, c := range cas {
		if got := len(ValiderConfig(c.cfg)); got != c.attendu {
			t.Errorf("%s: %d problème(s), attendu %d (%v)", c.nom, got, c.attendu, ValiderConfig(c.cfg))
		}
	}
}

func TestDepuisValeursRetombeSurLesDefauts(t *testing.T) {
	cfg := DepuisValeurs(map[string]string{"static_ip": ""})
	if len(cfg.STUN) != len(DefaultSTUN) || cfg.Interval != "60s" {
		t.Fatalf("empty values did not fall back to the defaults: %+v", cfg)
	}
}

func TestAttendreRetourneLaValeurPubliee(t *testing.T) {
	cs := fake.NewSimpleClientset()
	ctx := context.Background()
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = Publier(ctx, cs, Adresse{IPv4: "198.51.100.4", Source: "stun", Sources: 2, Total: 2})
	}()
	a, ok := Attendre(ctx, cs, 3*time.Second)
	if !ok || a.IPv4 != "198.51.100.4" {
		t.Fatalf("Attendre: ok=%v a=%+v", ok, a)
	}
}
