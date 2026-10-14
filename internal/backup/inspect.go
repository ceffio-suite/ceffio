package backup

import (
	"context"
	"strings"
)

// ManifesteResume is used by the CLI (defined here to stay close to the data
// it describes).
func ManifesteResume(m *Manifest) string {
	var sb strings.Builder
	sb.WriteString("created on : " + m.CreatedAt + "\n")
	if m.Domain != "" {
		sb.WriteString("domain     : " + m.Domain + "\n")
	}
	if m.K8sVersion != "" {
		sb.WriteString("kubernetes : " + m.K8sVersion + "\n")
	}
	return sb.String()
}

// CompterTables returns the number of public tables of a restored database.
// Serves as a post-restore check: "the command succeeded" does not say the
// data is there. Returns -1 if the database is unreachable.
func CompterTables(ctx context.Context, base string) int {
	pod := pgPodName(ctx)
	if pod == "" {
		return -1
	}
	out := strings.TrimSpace(query(ctx, pod, base,
		"SELECT count(*) FROM information_schema.tables WHERE table_schema='public'"))
	if out == "" {
		return -1
	}
	n := 0
	for _, c := range out {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	return n
}
