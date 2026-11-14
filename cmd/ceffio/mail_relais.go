// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"context"
	"fmt"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// relaisInitialisable is the part of the mail module the installation needs.
//
// WHY AN INTERFACE AND NOT A DIRECT IMPORT: this file must not pull
// internal/modules/mail into the CLI's dependency graph for one call — the
// registry exists so the CLI walks modules WITHOUT naming their packages. The
// assertion says "whichever module is registered under `mail`, if it accepts a
// relay at installation time, this is how".
type relaisInitialisable interface {
	ConfigurerRelaisInstallation(ctx context.Context, env module.Env,
		hote string, port int, utilisateur, motDePasse string) error
}

// enregistrerRelaisInitial stores the relay given to `ceffio install` in the
// mail module's settings, and applies it.
func enregistrerRelaisInitial(ctx context.Context, domaine, hote string, port int,
	utilisateur, motDePasse string) error {
	m, ok := module.Get("mail")
	if !ok {
		return fmt.Errorf("the mail module is not registered: the installation cannot configure a relay")
	}
	enr, ok := m.(relaisInitialisable)
	if !ok {
		return fmt.Errorf("the mail module cannot be given a relay: %T", m)
	}
	env := moduleEnv(domaine)
	env.ModuleID = "mail"
	return enr.ConfigurerRelaisInstallation(ctx, env, hote, port, utilisateur, motDePasse)
}
