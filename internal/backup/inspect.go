package backup

import (
	"context"
	"strings"
)

// printManifesteData est utilisé par le CLI (défini ici pour rester proche des
// données qu'il décrit).
func ManifesteResume(m *Manifest) string {
	var sb strings.Builder
	sb.WriteString("créée le   : " + m.CreatedAt + "\n")
	if m.Domain != "" {
		sb.WriteString("domaine    : " + m.Domain + "\n")
	}
	if m.K8sVersion != "" {
		sb.WriteString("kubernetes : " + m.K8sVersion + "\n")
	}
	return sb.String()
}

// CompterTables renvoie le nombre de tables publiques d'une base restaurée.
// Sert de contrôle post-restauration : « la commande a réussi » ne dit pas que
// les données sont là. Renvoie -1 si la base est injoignable.
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
