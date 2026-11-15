// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// The mail host's TLS certificate, installed into Stalwart.
//
// WHY THIS FILE EXISTS (docs/plan-mail.md §4.8 step 2): Stalwart serves its own
// built-in certificate ("CN=rcgen self signed cert", SAN DNS:localhost) until
// it is told about another one. Every mail client — Nextcloud Mail, a phone,
// Thunderbird — then refuses the connection, which the `tls` check reports as
// blocking. cert-manager already issues the right certificate into the
// `mail-tls` Secret (the mail Ingress asks for it); this file only makes
// Stalwart USE it.
//
// THE SEQUENCE IS THE ONE VERIFIED IN POC 9.C (docs/plan-mail.md):
//
//  1. mount the `mail-tls` Secret inside the pod, at a fixed path;
//  2. create an `x:Certificate` object whose certificate and key are read from
//     those FILES (`{"@type":"File","filePath":…}`);
//  3. point `SystemSettings.defaultCertificateId` at that object;
//  4. send the `x:Action` `ReloadTlsCertificates` so the server re-reads the
//     files WITHOUT a restart.
//
// A FILE CERTIFICATE IS READ AT LOAD TIME ONLY. cert-manager renews the Secret
// roughly every 60 days, and nothing in the server notices by itself: without
// steps 3–4 the renewed certificate sits in the Secret and the old one keeps
// being served until the pod restarts. That is why the Secret's
// `resourceVersion` is remembered: a changed Secret means "reload".
//
// THIS IS AN EXTERNAL PREREQUISITE, NEVER A REFUSAL (module rule): a cluster
// where cert-manager has not issued anything yet still installs, with a clear
// message, and the `tls` check tells the operator what is missing. Refusing the
// installation would leave them with no mail at all and no way to see why.
package mail

import (
	"context"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ceffio-suite/ceffio/internal/mail/jmap"
)

const (
	// SecretTLS is the Secret cert-manager fills for the mail host. The mail
	// Ingress already declares it (`tls: [{hosts: [mail.<domain>], secretName:
	// mail-tls}]`), so it exists as soon as the Ingress is reconciled.
	SecretTLS = "mail-tls"
	// configTLS remembers what was installed from that Secret. It is a
	// DEDICATED object, and that is deliberate: the workload's ConfigMap is
	// re-applied from a manifest on every deploy, which would erase annotations
	// written beside it. This one is only ever touched by this file.
	configTLS = "stalwart-tls"
	// The two files the injector puts in the pod's volume. Fixed paths, because
	// they are what the `x:Certificate` object references.
	cheminCertificat = "/etc/stalwart/tls/tls.crt"
	cheminCle        = "/etc/stalwart/tls/tls.key"
)

// AssurerTLS makes Stalwart serve the certificate of the `mail-tls` Secret,
// idempotently: an installation whose Secret has not changed performs reads
// only.
//
// `domaine` is the PLATFORM domain; the host whose name the certificate must
// carry is `mail.<domaine>`, the same rule as the rest of the package.
func AssurerTLS(ctx context.Context, domaine string) error {
	hote := domaineMail(domaine)

	cli, err := clientK8s()
	if err != nil {
		return fmt.Errorf("TLS: cluster access: %w", err)
	}
	sec, err := cli.Kubernetes().CoreV1().Secrets(ns).Get(ctx, SecretTLS, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		fmt.Printf("  ! TLS: Secret %s/%s is not issued yet — Stalwart keeps its self-signed certificate, the `tls` check reports it\n", ns, SecretTLS)
		return nil
	case err != nil:
		return fmt.Errorf("TLS: reading Secret %s/%s: %w", ns, SecretTLS, err)
	}
	if len(sec.Data["tls.crt"]) == 0 || len(sec.Data["tls.key"]) == 0 {
		fmt.Printf("  ! TLS: Secret %s/%s carries no tls.crt/tls.key yet — the `tls` check reports it\n", ns, SecretTLS)
		return nil
	}

	etat, err := lireEtatTLS(ctx)
	if err != nil {
		return err
	}

	// WHAT IS IN PLACE IS READ BEFORE ANYTHING IS WRITTEN. The certificate is
	// created once and then only re-read from its files, so the common case of
	// a replayed installation must issue no write at all.
	present, infos := false, map[string]any{}
	if id, _ := etat["certificateId"].(string); id != "" {
		present, infos, err = lireCertificat(ctx, id)
		if err != nil {
			return fmt.Errorf("TLS: reading certificate %q: %w", id, err)
		}
	}
	defaut, err := lireCertificatDefaut(ctx)
	if err != nil {
		return fmt.Errorf("TLS: reading the default certificate: %w", err)
	}

	// A CHANGED SECRET MEANS THE FILES ARE NEW, and the server will not notice:
	// it read them at load time. Recreating the object is what re-reads them
	// (§4.8: "a File certificate needs the ReloadTlsCertificates action").
	versionEnPlace, _ := etat["resourceVersion"].(string)
	secretChange := versionEnPlace != sec.ResourceVersion

	if !present || secretChange {
		ancien, _ := etat["certificateId"].(string)
		id, nouveaux, err := creerCertificatTLS(ctx)
		if err != nil {
			return fmt.Errorf("TLS: %w", err)
		}
		// THE OLD OBJECT IS DESTROYED ONLY ONCE THE NEW ONE IS DEFAULT: a
		// dangling defaultCertificateId is a server with no usable certificate,
		// which is worse than one stale object left behind.
		if ancien != "" && ancien != id {
			if err := detruireCertificatTLS(ctx, ancien); err != nil {
				fmt.Printf("  ! TLS: the previous certificate %q is still declared: %v\n", ancien, err)
			}
		}
		infos = nouveaux
		if err := activerCertificat(ctx, id); err != nil {
			return fmt.Errorf("TLS: %w", err)
		}
		if err := ecrireEtatTLS(ctx, sec.ResourceVersion, id); err != nil {
			return fmt.Errorf("TLS: %w", err)
		}
	} else if defaut != etat["certificateId"] {
		// The object is right but the server no longer points at it (a
		// restored store, a hand edit): point it again, without recreating.
		id := etat["certificateId"].(string)
		if err := activerCertificat(ctx, id); err != nil {
			return fmt.Errorf("TLS: %w", err)
		}
	}

	// THE NAME IS VERIFIED, NOT ASSUMED: a certificate issued for another host
	// is the failure that looks like success until a client connects.
	if san := sujetsAlternatifs(infos); len(san) > 0 && !couvreHote(san, hote) {
		fmt.Printf("  ! TLS: the certificate covers %s, NOT %s — check the mail Ingress hosts (the `tls` check reports it)\n",
			strings.Join(san, ", "), hote)
	}
	if emetteur, _ := infos["issuer"].(string); emetteur != "" {
		// The date is reported as the server stores it; it is what the `tls`
		// check compares against.
		jusqua, _ := infos["notValidAfter"].(string)
		fmt.Printf("  ∙ TLS: certificate %s (%s, valid until %s)\n", emetteur, hote, jusqua)
	} else {
		fmt.Printf("  ∙ TLS: certificate installed for %s\n", hote)
	}
	return nil
}

// creerCertificatTLS declares an `x:Certificate` reading the two mounted files.
//
// THE FILES ARE THE SOURCE, not their content: cert-manager renews the Secret,
// and a certificate object carrying a copy of the PEM would need this code to
// run again with the new bytes. A `File` object plus one reload action is what
// the server documents for exactly this case (POC 9.C).
func creerCertificatTLS(ctx context.Context) (string, map[string]any, error) {
	crees, err := clientJMAP().Set(ctx, "x:Certificate/set", jmap.Modification{
		Creer: map[string]map[string]any{"ceffio-mail": {
			"certificate": map[string]any{"@type": "File", "filePath": cheminCertificat},
			"privateKey":  map[string]any{"@type": "File", "filePath": cheminCle},
		}},
	})
	if err != nil {
		return "", nil, fmt.Errorf("declaring the certificate: %w", err)
	}
	id := crees["ceffio-mail"]
	if id == "" {
		return "", nil, fmt.Errorf("declaring the certificate: creation without a returned identifier")
	}
	// THE READ-BACK IS THE PROOF THE FILES WERE PARSED: the server answers with
	// the issuer and the SANs it actually read, which is the only way to know
	// the Secret is not empty or malformed.
	_, infos, err := lireCertificat(ctx, id)
	if err != nil {
		return "", nil, fmt.Errorf("reading back certificate %q: %w", id, err)
	}
	return id, infos, nil
}

// lireCertificat reports whether the object exists, with the fields the server
// derives from the files (issuer, SANs, expiry).
func lireCertificat(ctx context.Context, id string) (bool, map[string]any, error) {
	objets, err := clientJMAP().Get(ctx, "x:Certificate/get", []string{id},
		[]string{"id", "issuer", "subjectAlternativeNames", "notValidAfter", "notValidBefore"})
	if err != nil {
		return false, nil, err
	}
	for _, m := range objets {
		if m["id"] == id {
			return true, m, nil
		}
	}
	return false, nil, nil
}

// detruireCertificatTLS removes an object this code created. Its failure is not
// worth failing the installation: the new certificate is already the default,
// and an extra object is inert — so it is reported, not returned.
func detruireCertificatTLS(ctx context.Context, id string) error {
	_, err := clientJMAP().Set(ctx, "x:Certificate/set", jmap.Modification{
		Detruire: []string{id},
	})
	return err
}

// lireCertificatDefaut returns the current `SystemSettings.defaultCertificateId`
// ("" when none).
func lireCertificatDefaut(ctx context.Context) (string, error) {
	corps, err := appelJMAP(ctx, "x:SystemSettings/get", map[string]any{
		"ids": []string{"singleton"},
	})
	if err != nil {
		return "", err
	}
	liste, _ := corps["list"].([]any)
	if len(liste) == 0 {
		return "", fmt.Errorf("no SystemSettings object")
	}
	m, _ := liste[0].(map[string]any)
	valeur, _ := m["defaultCertificateId"].(string)
	return valeur, nil
}

// activerCertificat points the server at the object, then makes it reload the
// files, then verifies both by reading them back.
//
// READ-BACK, NOT TRUST: the `set` answers `{"updated":{"singleton":null}}` — a
// success with no detail — and the action answers with an identifier. Neither
// says that the certificate served on 993 is now the new one, so the value of
// `defaultCertificateId` is read again. The served certificate is the `tls`
// check's job: it dials the ports and looks at the leaf.
func activerCertificat(ctx context.Context, id string) error {
	// THE SHAPE IS THE SINGLETON PATCH, verified on the demo:
	//   x:SystemSettings/set {"update":{"singleton":{"defaultCertificateId":"…"}}}
	// It is the same shape as the outbound strategy's, which is what the
	// server's own configuration objects use.
	if err := majJMAP(ctx, "x:SystemSettings/set", map[string]any{
		"update": map[string]any{"singleton": map[string]any{
			"defaultCertificateId": id,
		}},
	}); err != nil {
		return fmt.Errorf("setting the default certificate to %q: %w", id, err)
	}
	defaut, err := lireCertificatDefaut(ctx)
	if err != nil {
		return fmt.Errorf("verifying the default certificate: %w", err)
	}
	if defaut != id {
		return fmt.Errorf("the default certificate reads back %q, expected %q", defaut, id)
	}
	// NO RESTART: the action re-reads the files whose paths the object
	// references (POC 9.C measured the swap without a connection being cut).
	if _, err := clientJMAP().Set(ctx, "x:Action/set", jmap.Modification{
		Creer: map[string]map[string]any{"reload-tls": {"@type": "ReloadTlsCertificates"}},
	}); err != nil {
		return fmt.Errorf("reloading the certificates: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// What was installed, remembered in a ConfigMap of its own
// ---------------------------------------------------------------------------

func lireEtatTLS(ctx context.Context) (map[string]any, error) {
	cli, err := clientK8s()
	if err != nil {
		return nil, fmt.Errorf("TLS: cluster access: %w", err)
	}
	cm, err := cli.Kubernetes().CoreV1().ConfigMaps(ns).Get(ctx, configTLS, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// NOT AN ERROR: a first installation has nothing remembered, which is
		// exactly what "create the certificate" means.
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("TLS: reading ConfigMap %s/%s: %w", ns, configTLS, err)
	}
	etat := make(map[string]any, len(cm.Data))
	for k, v := range cm.Data {
		etat[k] = v
	}
	return etat, nil
}

func ecrireEtatTLS(ctx context.Context, versionSecret, idCertificat string) error {
	cli, err := clientK8s()
	if err != nil {
		return fmt.Errorf("cluster access: %w", err)
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: configTLS, Namespace: ns},
		Data: map[string]string{
			"resourceVersion": versionSecret,
			"certificateId":   idCertificat,
		},
	}
	existante, err := cli.Kubernetes().CoreV1().ConfigMaps(ns).Get(ctx, configTLS, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		if _, err := cli.Kubernetes().CoreV1().ConfigMaps(ns).Create(ctx, cm, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("recording the installed certificate: %w", err)
		}
	case err != nil:
		return fmt.Errorf("reading ConfigMap %s/%s: %w", ns, configTLS, err)
	default:
		cm.ResourceVersion = existante.ResourceVersion
		if _, err := cli.Kubernetes().CoreV1().ConfigMaps(ns).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("recording the installed certificate: %w", err)
		}
	}
	return nil
}

// sujetsAlternatifs flattens the server's SAN map (`{"mail.example.com":true}`)
// into a sorted list.
func sujetsAlternatifs(infos map[string]any) []string {
	brut, _ := infos["subjectAlternativeNames"].(map[string]any)
	noms := make([]string, 0, len(brut))
	for nom := range brut {
		if nom != "" {
			noms = append(noms, nom)
		}
	}
	sortStrings(noms)
	return noms
}

// couvreHote reports whether one of the certificate's names covers the host:
// one of the explicit names is the host, or a wildcard covers its parent.
func couvreHote(noms []string, hote string) bool {
	hote = strings.ToLower(strings.TrimSpace(hote))
	for _, nom := range noms {
		nom = strings.ToLower(strings.TrimSpace(nom))
		switch {
		case nom == hote:
			return true
		case strings.HasPrefix(nom, "*."):
			// *.example.com covers mail.example.com but neither example.com nor
			// a.b.example.com.
			parent := strings.TrimPrefix(nom, "*.")
			if i := strings.IndexByte(hote, '.'); i > 0 && hote[i+1:] == parent {
				return true
			}
		}
	}
	return false
}

// sortStrings sorts in place.
func sortStrings(s []string) {
	sort.Strings(s)
}
