// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package platformmail

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes"
)

// WHY THESE TESTS EXIST: the Nextcloud writer is the only thing that MOVES the
// platform's mail from an external relay to its own server, and its failure mode
// is silent — `occ config:system:set` exits 0 on a key it does not know, and a
// Nextcloud still pointing at the old relay keeps working until the relay is
// switched off. The read-back is therefore the behaviour under test, not a detail.

// occFaux is a Nextcloud system configuration that records what was written.
type occFaux struct {
	valeurs   map[string]string
	ecritures []string
	// ignore lists keys whose write succeeds without storing anything — the defect
	// the read-back exists to catch.
	ignore  map[string]bool
	erreurs map[string]error
}

func (o *occFaux) exec(args ...string) (string, error) {
	switch args[0] {
	case "config:system:get":
		if v, ok := o.valeurs[args[1]]; ok {
			return v + "\n", nil
		}
		// THE REAL COMMAND PRINTS "Config key not set" AND EXITS 1; the writer
		// treats that exactly like an empty answer.
		return "", errors.New("exit status 1")
	case "config:system:set":
		cle, valeur := args[1], args[3]
		o.ecritures = append(o.ecritures, cle+"="+valeur)
		if err := o.erreurs[cle]; err != nil {
			return "", err
		}
		if !o.ignore[cle] {
			o.valeurs[cle] = valeur
		}
		return "", nil
	case "config:system:delete":
		o.ecritures = append(o.ecritures, "delete:"+args[1])
		delete(o.valeurs, args[1])
		return "", nil
	}
	return "", fmt.Errorf("unexpected occ command %v", args)
}

func occSilencieux(t *testing.T) {
	t.Helper()
	remplacer(t, &Sortie, io.Writer(io.Discard))
}

// TestNextcloudGetsTheSendersAddressAndTransport : the whole mapping, including
// the two fields the old writer got wrong (`mail_from_address` local part,
// `mail_domain` domain).
func TestNextcloudGetsTheSendersAddressAndTransport(t *testing.T) {
	occSilencieux(t)
	occ := &occFaux{valeurs: map[string]string{}}
	s := &Sender{
		Host: "mail.example.com", Port: 465, Security: "ssl",
		User: "noreply@example.com", Password: "app-secret",
		From: "noreply@example.com", FromName: "Ceffio",
	}

	if err := ecrireNextcloud(s, occ.exec); err != nil {
		t.Fatalf("ecrireNextcloud: %v", err)
	}

	attendus := map[string]string{
		"mail_smtpmode":     "smtp",
		"mail_smtphost":     "mail.example.com",
		"mail_smtpport":     "465",
		"mail_smtpsecure":   "ssl",
		"mail_smtpauth":     "1",
		"mail_smtpauthtype": "LOGIN",
		"mail_smtpname":     "noreply@example.com",
		"mail_from_address": "noreply",
		"mail_domain":       "example.com",
		"mail_smtppassword": "app-secret",
	}
	for cle, valeur := range attendus {
		if occ.valeurs[cle] != valeur {
			t.Errorf("Nextcloud's %s is %q; want %q", cle, occ.valeurs[cle], valeur)
		}
	}
	// THE ADDRESS THE OLD WRITER BROKE: `mail_domain` held the display name, so
	// Nextcloud composed noreply@Ceffio.
	if strings.Contains(occ.valeurs["mail_domain"], "Ceffio") {
		t.Fatalf("mail_domain holds the display name (%q): Nextcloud would compose an "+
			"address whose domain is free text", occ.valeurs["mail_domain"])
	}
}

// TestNextcloudWriterReportsAValueThatDoesNotStick : the defect the read-back
// exists for.
func TestNextcloudWriterReportsAValueThatDoesNotStick(t *testing.T) {
	occSilencieux(t)
	occ := &occFaux{valeurs: map[string]string{}, ignore: map[string]bool{"mail_smtphost": true}}
	s := &Sender{Host: "mail.example.com", Port: 465, Security: "ssl",
		User: "noreply@example.com", From: "noreply@example.com"}

	err := ecrireNextcloud(s, occ.exec)
	if err == nil {
		t.Fatal("ecrireNextcloud reported success although mail_smtphost was not stored: " +
			"Nextcloud would keep sending through its default transport")
	}
	if !strings.Contains(err.Error(), "mail_smtphost") {
		t.Fatalf("the error does not name the key that did not stick: %v", err)
	}
}

// TestNextcloudClearRemovesOnlyTheMode : clearing the sender must not erase values
// an operator typed by hand in another key.
func TestNextcloudClearRemovesOnlyTheMode(t *testing.T) {
	occSilencieux(t)
	occ := &occFaux{valeurs: map[string]string{
		"mail_smtpmode": "smtp",
		"mail_smtphost": "relay.example.net",
		"newsletter_ss": "operator-value",
	}}

	if err := effacerNextcloud(occ.exec); err != nil {
		t.Fatalf("effacerNextcloud: %v", err)
	}
	if _, ok := occ.valeurs["mail_smtpmode"]; ok {
		t.Fatal("mail_smtpmode is still set: Nextcloud would keep using the old transport")
	}
	if occ.valeurs["mail_smtphost"] != "relay.example.net" || occ.valeurs["newsletter_ss"] != "operator-value" {
		t.Fatalf("clearing the mode erased unrelated keys: %v", occ.valeurs)
	}
	if len(occ.ecritures) != 1 || occ.ecritures[0] != "delete:mail_smtpmode" {
		t.Fatalf("the clear wrote %v; want exactly one deletion of mail_smtpmode", occ.ecritures)
	}
}

// TestNextcloudClearIsANoOpWhenNothingIsSet : an uninstall on a platform that
// never had a sender must not fail on a missing key.
func TestNextcloudClearIsANoOpWhenNothingIsSet(t *testing.T) {
	occSilencieux(t)
	occ := &occFaux{valeurs: map[string]string{}}

	if err := effacerNextcloud(occ.exec); err != nil {
		t.Fatalf("effacerNextcloud on an empty configuration: %v", err)
	}
	if len(occ.ecritures) != 0 {
		t.Fatalf("the clear wrote %v; want no write at all", occ.ecritures)
	}
}

// TestNextcloudEmptyPasswordDeletesTheStaleOne : switching from an authenticated
// sender to one that authenticates by address must not leave the old password.
func TestNextcloudEmptyPasswordDeletesTheStaleOne(t *testing.T) {
	occSilencieux(t)
	occ := &occFaux{valeurs: map[string]string{"mail_smtppassword": "old-secret"}}
	s := &Sender{Host: "mail.example.com", Port: 25, Security: "",
		User: "noreply@example.com", From: "noreply@example.com"}

	if err := ecrireNextcloud(s, occ.exec); err != nil {
		t.Fatalf("ecrireNextcloud: %v", err)
	}
	if _, ok := occ.valeurs["mail_smtppassword"]; ok {
		t.Fatal("the previous password is still stored: the sender would authenticate " +
			"with a credential that is no longer valid")
	}
}

// TestNextcloudWriterRefusesAnAddressWithoutDomain : an address that cannot be
// composed is a programming error, and it must not be written as an empty domain.
func TestNextcloudWriterRefusesAnAddressWithoutDomain(t *testing.T) {
	occSilencieux(t)
	occ := &occFaux{valeurs: map[string]string{}}
	s := &Sender{Host: "mail.example.com", Port: 465, Security: "ssl",
		User: "noreply", From: "noreply"}

	if err := ecrireNextcloud(s, occ.exec); err == nil {
		t.Fatal("ecrireNextcloud accepted a From address with no domain")
	}
	if len(occ.ecritures) != 0 {
		t.Fatalf("the refused write still wrote %v", occ.ecritures)
	}
}

// clientPodQuiBouge is a cluster whose pod changes between two commands — the
// state the alias rewrite leaves behind while the rollout converges.
type clientPodQuiBouge struct {
	// pods is the sequence the resolver answers; the last one repeats.
	pods []string
	// resolus counts the resolutions, so a test asserts the pod was looked up
	// again instead of reusing a name that no longer exists.
	resolus int
	// execs records "pod:commande" for every attempt.
	execs []string
	// occ answers the commands, when the pod is reachable.
	occ *occFaux
	// injoignable says which pods cannot be exec'd into (the one being deleted).
	injoignable map[string]bool
}

func (c *clientPodQuiBouge) Executer(_ context.Context, _, pod, _ string, args ...string) (string, error) {
	commande := strings.Join(args, " ")
	c.execs = append(c.execs, pod+":"+commande)
	if c.injoignable[pod] {
		return "", errors.New("error dialing backend: EOF")
	}
	if len(args) > 2 && args[0] == "php" && args[1] == "occ" {
		args = args[2:]
	}
	return c.occ.exec(args...)
}

func (c *clientPodQuiBouge) ExecuterAvecEntree(context.Context, string, string, string, string, ...string) (string, error) {
	return "", errors.New("not used")
}

func (c *clientPodQuiBouge) PodDuDeploiement(context.Context, string, string, string) (string, error) {
	c.resolus++
	if len(c.pods) == 0 {
		return "", errors.New("no pod")
	}
	if c.resolus < len(c.pods) {
		return c.pods[c.resolus-1], nil
	}
	return c.pods[len(c.pods)-1], nil
}

func (c *clientPodQuiBouge) AttendreDeploiement(context.Context, string, string, time.Duration) error {
	return nil
}

func (c *clientPodQuiBouge) Kubernetes() kubernetes.Interface { return nil }

// TestNextcloudWriterSurvitAuRemplacementDuPod : the pod the alias rewrite is
// about to replace must not make the write fail. This is the live failure of
// 0.11.0-rc.5: the fifth key was written to a pod that had just gone, the
// read-back found nothing, and the error blamed `mail_smtpauth`.
func TestNextcloudWriterSurvitAuRemplacementDuPod(t *testing.T) {
	occSilencieux(t)
	occ := &occFaux{valeurs: map[string]string{}}
	cli := &clientPodQuiBouge{
		pods:        []string{"pod-supprime", "pod-nouveau"},
		occ:         occ,
		injoignable: map[string]bool{"pod-supprime": true},
	}
	s := &Sender{
		Host: "mail.example.com", Port: 465, Security: "ssl",
		User: "noreply@example.com", Password: "app-secret",
		From: "noreply@example.com", FromName: "Ceffio",
	}

	if err := ecrireNextcloud(s, occAvecReprise(context.Background(), cli)); err != nil {
		t.Fatalf("the write failed because the pod was replaced under it: %v", err)
	}
	if occ.valeurs["mail_smtpauth"] != "1" {
		t.Fatalf("mail_smtpauth = %q, want 1: the retry did not land on the new pod",
			occ.valeurs["mail_smtpauth"])
	}
	// THE FIRST ATTEMPT MUST HAVE FAILED ON THE OLD POD AND ONLY ONE: a retry
	// that hammers a disappearing pod hides the diagnosis instead of fixing it.
	echecs := 0
	for _, e := range cli.execs {
		if strings.HasPrefix(e, "pod-supprime:") {
			echecs++
		}
	}
	if echecs != 1 {
		t.Fatalf("attempts on the replaced pod = %d, want exactly 1: %v", echecs, cli.execs)
	}
	if cli.resolus < 2 {
		t.Fatalf("the pod was resolved %d time(s): the retry reused the dead name", cli.resolus)
	}
}

// TestNextcloudWriterRapporteUneErreurQuiPersiste : when even the second attempt
// fails, the occ error must come back — silently returning an empty string is
// what turned an exec failure into a message about a value.
func TestNextcloudWriterRapporteUneErreurQuiPersiste(t *testing.T) {
	occSilencieux(t)
	cli := &clientPodQuiBouge{
		pods:        []string{"pod-1"},
		occ:         &occFaux{valeurs: map[string]string{}},
		injoignable: map[string]bool{"pod-1": true},
	}
	occ := occAvecReprise(context.Background(), cli)

	_, err := occ("config:system:get", "mail_smtpauth")
	if err == nil {
		t.Fatal("a command that could not be run reported success")
	}
	if !strings.Contains(err.Error(), "dialing backend") {
		t.Fatalf("the error does not carry the exec failure: %v", err)
	}
	if len(cli.execs) != 2 {
		t.Fatalf("attempts = %d, want 2 (the initial one and a single retry): %v", len(cli.execs), cli.execs)
	}
}
