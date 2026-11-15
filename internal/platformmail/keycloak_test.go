// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package platformmail

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// WHY THESE TESTS EXIST: Keycloak's SMTP settings live in a realm map that kcadm
// accepts WITHOUT VALIDATING IT — a misspelled key exits 0 and is simply ignored —
// so a written-but-wrong realm looks configured and silently drops the account
// e-mails. The payload and the read-back are the two halves of that contract, and
// both are asserted here.

// kcadmFaux replaces the kcadm seam with a realm map.
type kcadmFaux struct {
	realm map[string]string
	// entrees records the JSON documents handed to kcadm on stdin.
	entrees []string
	// cmds records the shell commands kcadm was invoked with.
	cmds []string
	// lecture overrides the read command's output when a test needs a document
	// that does not match the map.
	lecture string
	// ignoreEcriture simulates kcadm accepting the document and changing nothing.
	ignoreEcriture bool
	// muet simulates an exec that answers nothing at all.
	muet bool
}

func (k *kcadmFaux) exec(_ context.Context, _ string, entree, commande string) (string, error) {
	k.cmds = append(k.cmds, commande)
	if entree != "" {
		k.entrees = append(k.entrees, entree)
		if k.ignoreEcriture {
			return "", nil
		}
		var doc struct {
			SmtpServer map[string]string `json:"smtpServer"`
		}
		if err := json.Unmarshal([]byte(entree), &doc); err != nil {
			return "", err
		}
		k.realm = doc.SmtpServer
		return "", nil
	}
	if k.muet {
		return "", nil
	}
	if k.lecture != "" {
		return k.lecture, nil
	}
	doc, _ := json.Marshal(map[string]any{"smtpServer": k.realm})
	return string(doc), nil
}

func kcadmSilencieux(t *testing.T, faux *kcadmFaux) {
	t.Helper()
	occSilencieux(t)
	remplacer(t, &executerKcadm, faux.exec)
}

// TestKeycloakPayloadUsesTheRealmsVocabulary : booleans as "true"/"false" strings,
// port as a string, platform display name, and the two mutually exclusive
// security flags.
func TestKeycloakPayloadUsesTheRealmsVocabulary(t *testing.T) {
	cas := []struct {
		nom           string
		securite      string
		ssl, starttls string
	}{
		{"implicit TLS", "ssl", "true", "false"},
		{"STARTTLS", "starttls", "false", "true"},
		{"plain", "", "false", "false"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			charge := chargeKeycloak(&Sender{
				Host: "mail.example.com", Port: 465, Security: c.securite,
				User: "noreply@example.com", Password: "app-secret",
				From: "noreply@example.com",
			})
			if charge["ssl"] != c.ssl || charge["starttls"] != c.starttls {
				t.Fatalf("ssl/starttls are %q/%q; want %q/%q",
					charge["ssl"], charge["starttls"], c.ssl, c.starttls)
			}
			if charge["port"] != "465" {
				t.Fatalf("port is %q; the realm stores a Map<String,String>, so it must be "+
					"a string", charge["port"])
			}
			if charge["fromDisplayName"] != "Ceffio" {
				t.Fatalf("fromDisplayName is %q; want the platform name, which is what the "+
					"recipient reads", charge["fromDisplayName"])
			}
			if charge["password"] != "app-secret" || charge["auth"] != "true" {
				t.Fatalf("authentication fields are missing: %v", charge)
			}
		})
	}
}

// TestKeycloakPayloadClearsWithAnEmptyMap : `null` would be ignored by the realm
// update, leaving the previous settings in place.
func TestKeycloakPayloadClearsWithAnEmptyMap(t *testing.T) {
	charge := chargeKeycloak(nil)
	if charge == nil {
		t.Fatal("chargeKeycloak(nil) is nil: json.Marshal would write `null`, which the " +
			"realm update ignores — the sender would survive an uninstall")
	}
	if len(charge) != 0 {
		t.Fatalf("chargeKeycloak(nil) carries %v; want an empty map", charge)
	}
}

// TestKeycloakWriterKeepsThePasswordOffTheCommandLine : the document travels
// through a file on stdin, and the file is removed in the same shell.
func TestKeycloakWriterKeepsThePasswordOffTheCommandLine(t *testing.T) {
	faux := &kcadmFaux{}
	kcadmSilencieux(t, faux)
	s := &Sender{Host: "mail.example.com", Port: 465, Security: "ssl",
		User: "noreply@example.com", Password: "app-secret",
		From: "noreply@example.com", FromName: "Ceffio"}

	if err := ecrireSmtpServerKeycloak(context.Background(), chargeKeycloak(s)); err != nil {
		t.Fatalf("ecrireSmtpServerKeycloak: %v", err)
	}
	if len(faux.entrees) != 1 {
		t.Fatalf("kcadm received %d document(s); want exactly one on stdin", len(faux.entrees))
	}
	if len(faux.cmds) != 1 {
		t.Fatalf("kcadm was invoked %d time(s); want once", len(faux.cmds))
	}
	if strings.Contains(faux.cmds[0], "app-secret") {
		t.Fatal("the SMTP password appears on kcadm's command line, where every process " +
			"in the pod can read it")
	}
	if !strings.Contains(faux.cmds[0], "-f ") || strings.Contains(faux.cmds[0], "-s smtpServer") {
		t.Fatalf("the writer does not pass the document through a file: %s", faux.cmds[0])
	}
	if !strings.Contains(faux.cmds[0], "rm -f") {
		t.Fatalf("the temporary file is not removed: %s", faux.cmds[0])
	}
	var relu struct {
		SmtpServer map[string]string `json:"smtpServer"`
	}
	if err := json.Unmarshal([]byte(faux.entrees[0]), &relu); err != nil {
		t.Fatalf("the document sent on stdin is not JSON: %v", err)
	}
	if relu.SmtpServer["user"] != "noreply@example.com" || relu.SmtpServer["password"] != "app-secret" {
		t.Fatalf("the document lost its credential fields: %v", relu.SmtpServer)
	}
	// THE DOCUMENT IS A REALM REPRESENTATION: the settings live under `smtpServer`.
	// A bare map makes `kcadm update realms/<realm> -f` fail with `Unrecognized
	// field "auth"`, and the realm is left without a sender.
	var brut map[string]json.RawMessage
	if err := json.Unmarshal([]byte(faux.entrees[0]), &brut); err != nil {
		t.Fatalf("the document sent on stdin is not a JSON object: %v", err)
	}
	if _, ok := brut["smtpServer"]; !ok {
		t.Fatalf("the document is not a realm representation (no smtpServer field): %s", faux.entrees[0])
	}
	if _, ok := brut["auth"]; ok {
		t.Fatalf("the SMTP settings leak at the top level, where kcadm rejects them: %s", faux.entrees[0])
	}
}

// TestKeycloakReadBackRequestsTheNestedMap : the read-back asks for the SMTP map
// WITH ITS CHILDREN. `--fields smtpServer` makes Keycloak 26.8 answer
// `{"smtpServer": {}}`, which reads as "no sender" on a configured realm and turns
// every install into a mismatch; the bracketed form is the documented way to ask
// for an object's fields.
func TestKeycloakReadBackRequestsTheNestedMap(t *testing.T) {
	faux := &kcadmFaux{realm: map[string]string{"host": "mail.example.com"}}
	kcadmSilencieux(t, faux)

	if _, err := lireSmtpServerKeycloak(context.Background()); err != nil {
		t.Fatalf("lireSmtpServerKeycloak: %v", err)
	}
	if len(faux.cmds) != 1 {
		t.Fatalf("kcadm was invoked %d time(s); want once", len(faux.cmds))
	}
	if !strings.Contains(faux.cmds[0], `--fields "smtpServer(*)"`) {
		t.Fatalf("the read-back does not ask for the nested map: %s\nKeycloak 26.8 "+
			"answers {\"smtpServer\": {}} for a bare --fields smtpServer, so a "+
			"configured realm would be reported as having no sender", faux.cmds[0])
	}
}

// TestKeycloakReadBackIgnoresTheSurroundingNoise : kcadm prints log lines around
// its JSON document.
func TestKeycloakReadBackIgnoresTheSurroundingNoise(t *testing.T) {
	faux := &kcadmFaux{lecture: "INFO  updating\n{\"smtpServer\":{\"host\":\"mail.example.com\"," +
		"\"port\":\"465\",\"ssl\":\"true\",\"starttls\":\"false\",\"auth\":\"true\"," +
		"\"user\":\"noreply@example.com\",\"password\":\"app-secret\"," +
		"\"from\":\"noreply@example.com\",\"fromDisplayName\":\"Ceffio\"}}\n"}
	kcadmSilencieux(t, faux)

	relu, err := lireSmtpServerKeycloak(context.Background())
	if err != nil {
		t.Fatalf("lireSmtpServerKeycloak: %v", err)
	}
	if relu["host"] != "mail.example.com" || relu["fromDisplayName"] != "Ceffio" {
		t.Fatalf("the read-back lost the document: %v", relu)
	}
}

// TestKeycloakReadBackRefusesAnEmptyAnswer : "no JSON" must not read as "no sender",
// which would clear a working configuration on a broken exec.
func TestKeycloakReadBackRefusesAnEmptyAnswer(t *testing.T) {
	kcadmSilencieux(t, &kcadmFaux{muet: true})
	if _, err := lireSmtpServerKeycloak(context.Background()); err == nil {
		t.Fatal("an empty kcadm answer was read as an empty realm")
	}
}

// TestKeycloakComparisonSkipsAMaskedPassword : a masked password means "not
// shown", not "different" — otherwise every install would rewrite the realm and
// report a mismatch that does not exist.
func TestKeycloakComparisonSkipsAMaskedPassword(t *testing.T) {
	voulu := chargeKeycloak(&Sender{Host: "mail.example.com", Port: 465, Security: "ssl",
		User: "noreply@example.com", Password: "app-secret", From: "noreply@example.com"})
	actuel := map[string]string{}
	for k, v := range voulu {
		actuel[k] = v
	}
	actuel["password"] = "**********"
	if !memeSmtpServer(actuel, voulu) {
		t.Fatal("a masked password was treated as a different one: the realm would be " +
			"rewritten on every install")
	}
	actuel["host"] = "relay.example.net"
	if memeSmtpServer(actuel, voulu) {
		t.Fatal("a different host compared equal")
	}
}

// TestApplyKeycloakIsIdempotent : the realm is compared BEFORE anything is written,
// so a replay writes nothing at all.
func TestApplyKeycloakIsIdempotent(t *testing.T) {
	s := &Sender{Host: "mail.example.com", Port: 465, Security: "ssl",
		User: "noreply@example.com", Password: "app-secret",
		From: "noreply@example.com", FromName: "Ceffio"}
	faux := &kcadmFaux{realm: chargeKeycloak(s)}
	kcadmSilencieux(t, faux)
	// NO INGRESS: the alias step then has nothing to align, which keeps this test
	// about the realm write alone.
	cluster := clusterMinimal(t, nsIdentity, deploiementKeycloak)
	remplacer(t, &clientK8s, func() (clientCluster, error) { return cluster, nil })

	if err := ApplyKeycloak(context.Background(), s); err != nil {
		t.Fatalf("ApplyKeycloak: %v", err)
	}
	if len(faux.entrees) != 0 {
		t.Fatalf("the realm matched already but %d document(s) were written", len(faux.entrees))
	}
}

// TestApplyKeycloakWritesAndReadsBack : the first install writes the document, and
// a realm that reads back differently is reported instead of assumed.
func TestApplyKeycloakWritesAndReadsBack(t *testing.T) {
	s := &Sender{Host: "mail.example.com", Port: 465, Security: "ssl",
		User: "noreply@example.com", Password: "app-secret",
		From: "noreply@example.com", FromName: "Ceffio"}
	faux := &kcadmFaux{realm: map[string]string{}}
	kcadmSilencieux(t, faux)
	cluster := clusterMinimal(t, nsIdentity, deploiementKeycloak)
	remplacer(t, &clientK8s, func() (clientCluster, error) { return cluster, nil })

	if err := ApplyKeycloak(context.Background(), s); err != nil {
		t.Fatalf("ApplyKeycloak: %v", err)
	}
	if len(faux.entrees) != 1 {
		t.Fatalf("the realm was empty but %d document(s) were written; want one", len(faux.entrees))
	}
	if faux.realm["host"] != "mail.example.com" {
		t.Fatalf("the realm holds %v after the write", faux.realm)
	}
}

// TestApplyKeycloakReportsARealmThatDidNotStick : a write kcadm ignores leaves the
// realm unchanged, and the caller must learn it.
func TestApplyKeycloakReportsARealmThatDidNotStick(t *testing.T) {
	s := &Sender{Host: "mail.example.com", Port: 465, Security: "ssl",
		User: "noreply@example.com", Password: "app-secret",
		From: "noreply@example.com", FromName: "Ceffio"}
	faux := &kcadmFaux{realm: map[string]string{}, ignoreEcriture: true}
	kcadmSilencieux(t, faux)
	cluster := clusterMinimal(t, nsIdentity, deploiementKeycloak)
	remplacer(t, &clientK8s, func() (clientCluster, error) { return cluster, nil })

	if err := ApplyKeycloak(context.Background(), s); err == nil {
		t.Fatal("ApplyKeycloak reported success although the realm still reads empty")
	}
}
