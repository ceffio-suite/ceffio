// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package sso

import (
	"context"
	"strings"
	"testing"
)

// TestUnClientSansIDEstRefuse : an ID is what appears in the application's config and
// in Keycloak. Empty, the client would be created with no name — and nothing could
// ever find it again.
func TestUnClientSansIDEstRefuse(t *testing.T) {
	_, err := AssurerClient(context.Background(), Client{
		Redirects: "https://app.example.org/callback",
	})
	if err == nil {
		t.Fatal("a client with no ID was accepted")
	}
	if !strings.Contains(err.Error(), "ID") {
		t.Errorf("the error does not say what is missing: %v", err)
	}
}

// TestUnClientSansRedirectionEstRefuse : Keycloak refuses every login until a redirect
// URI is listed. Creating the client anyway produces a client that exists, is enabled,
// and signs nobody in — with no error at creation time.
func TestUnClientSansRedirectionEstRefuse(t *testing.T) {
	_, err := AssurerClient(context.Background(), Client{ID: "longhorn"})
	if err == nil {
		t.Fatal("a client with no redirect URI was accepted: Keycloak would refuse every " +
			"login, and the creation would have reported success")
	}
	if !strings.Contains(err.Error(), "longhorn") {
		t.Errorf("the error does not name the client: %v", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "redirect") {
		t.Errorf("the error does not say what is missing: %v", err)
	}
}

// TestLaValidationPrecedeLeCluster : both refusals above happen BEFORE any call to
// Keycloak.
//
// THAT IS THE POINT OF A VALIDATION: an operator with a sealed vault or an unreachable
// cluster should learn that their description is wrong, not that the cluster is. The
// context here is a background one with no vault configured — if the function reached
// the cluster first, the error would be about the vault or the connection.
func TestLaValidationPrecedeLeCluster(t *testing.T) {
	for _, cas := range []Client{
		{},                         // nothing at all
		{ID: "x"},                  // no redirect
		{Redirects: "https://a/b"}, // no ID
	} {
		_, err := AssurerClient(context.Background(), cas)
		if err == nil {
			t.Errorf("client %+v was accepted", cas)
			continue
		}
		bas := strings.ToLower(err.Error())
		if strings.Contains(bas, "vault") || strings.Contains(bas, "connection") ||
			strings.Contains(bas, "exec") {
			t.Errorf("the error came from the cluster, not from the description: %v\n"+
				"A wrong description must be refused before anything is contacted.", err)
		}
	}
}

// TestUnClientPublicNeDemandePasDeSecret : a public client authenticates by PKCE and
// cannot keep a secret. The zero value of the struct is confidential, so the default is
// the safe one — a module that forgets the field gets a confidential client, not a
// public one, and forgetting to protect is not a security decision.
func TestUnClientPublicNeDemandePasDeSecret(t *testing.T) {
	if (Client{ID: "x", Redirects: "https://a/b"}).Public {
		t.Error("the zero value is Public: a module that forgets the field would silently " +
			"declare a client that cannot keep a secret")
	}
}

// TestLesChampsDeCoffreSontOptionnels : a client with no vault path stores nothing.
//
// IT IS THE CORRECT BEHAVIOUR FOR A CALLER THAT MANAGES ITS OWN ENTRY: writing a
// credential under a path the caller did not ask for puts a secret where nobody reads
// it, and the caller still believes it holds the value.
func TestLesChampsDeCoffreSontOptionnels(t *testing.T) {
	c := Client{ID: "x", Redirects: "https://a/b"}
	if _, ok := secretDuCoffre(context.Background(), c); ok {
		t.Error("a client with no vault path returned a secret: it cannot have read one")
	}
	if err := ecrireSecretClient(context.Background(), c, "un-secret"); err != nil {
		t.Errorf("writing nothing failed: %v", err)
	}
}
