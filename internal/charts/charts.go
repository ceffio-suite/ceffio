// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package charts embeds the signed Helm charts (data included) into the
// binary, so an installation is self-contained (no relative repo).
package charts

import "embed"

//go:embed ceffio
var FS embed.FS
