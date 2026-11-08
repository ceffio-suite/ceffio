// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// registry-check answers one question a week: is any pinned component behind
// what its upstream project publishes?
//
// Exit codes, and the workflow depends on them:
//
//	0  everything pinned is the newest comparable version
//	1  the check itself failed
//	2  at least one component has a newer version, or could not be compared
//
// WHY A SEPARATE BINARY AND NOT A `ceffio` SUBCOMMAND: an operator does not need
// to query three registries from their installation, and the CLI surface should
// describe the product, not the maintainer's chores. cmd/pin-digests is the
// precedent.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/ceffio-suite/ceffio/internal/freshness"
	"github.com/ceffio-suite/ceffio/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "registry-check: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	obs := freshness.Comparer(ctx, freshness.NewHTTP(), version.Registry)

	fmt.Println("# Fraîcheur du registre")
	fmt.Println()
	fmt.Print(freshness.Rapport(obs))

	aFaire := freshness.AChanger(obs)
	if len(aFaire) == 0 {
		fmt.Println()
		fmt.Println("Tout ce qui est épinglé est la version la plus récente que le dépôt publie.")
		return nil
	}
	fmt.Println()
	fmt.Printf("%d composant(s) à regarder.\n", len(aFaire))
	os.Exit(2)
	return nil
}
