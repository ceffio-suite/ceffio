// Package charts embarque les charts Helm signés (data incluses) dans le
// binaire, pour qu'une installation soit autoportante (pas de dépôt relatif).
package charts

import "embed"

//go:embed ceffio
var FS embed.FS
