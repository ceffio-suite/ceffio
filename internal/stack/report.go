package stack

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Finding est un problème détecté, avec de quoi agir.
type Finding struct {
	Severity string `json:"severity"` // critique | avertissement
	Scope    string `json:"scope"`    // cluster, tls, reseau, ou nom de couche
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
	Action   string `json:"action,omitempty"`
}

// Report est le résultat complet d'un diagnostic.
type Report struct {
	GeneratedAt string    `json:"generated_at"`
	Version     string    `json:"version,omitempty"`
	State       *State    `json:"state"`
	Findings    []Finding `json:"findings"`
}

// WriteJSON sérialise un rapport.
func WriteJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// ---------------------------------------------------------------------------
// Archive de support
// ---------------------------------------------------------------------------

// Expressions de ce qui ne doit JAMAIS sortir de la machine dans un bundle.
// On filtre à l'écriture : même si l'appelant se trompe et joint un document
// trop large, les valeurs sensibles sont neutralisées avant d'entrer dans
// l'archive. Un bundle de support circule par courriel — il ne doit contenir
// aucun secret, sans exception.
var (
	reSecretJSON = regexp.MustCompile(`(?i)"(password|passwd|secret|token|api[_-]?key|private[_-]?key|client[_-]?secret)"\s*:\s*"[^"]*"`)
	reSecretYAML = regexp.MustCompile(`(?im)^(\s*(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|client[_-]?secret|smtp_password)\s*:\s*).*$`)
	reDataType   = regexp.MustCompile(`(?i)"data"\s*:\s*\{[^}]*\}`)
	reBearer     = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._\-]{8,}`)
	rePrivateKey = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)
	reConnString = regexp.MustCompile(`(?i)([a-z]+://[^:@/\s]+:)[^@/\s]+(@)`)
)

// Redact neutralise les valeurs sensibles d'un texte.
func Redact(s string) string {
	s = rePrivateKey.ReplaceAllString(s, "[CLE PRIVEE RETIREE]")
	s = reSecretJSON.ReplaceAllString(s, `"$1":"[RETIRE]"`)
	s = reSecretYAML.ReplaceAllString(s, `${1}[RETIRE]`)
	s = reDataType.ReplaceAllString(s, `"data":{"[RETIRE]":"les valeurs de Secret ne sont pas collectées"}`)
	s = reBearer.ReplaceAllString(s, `${1}[RETIRE]`)
	s = reConnString.ReplaceAllString(s, `${1}[RETIRE]${2}`)
	return s
}

// bundleDir collecte les éléments non sensibles : état, diagnostic, et les
// journaux des seuls pods en difficulté (jamais ceux des pods sains).
func bundleDir(r Report) (string, error) {
	dir, err := os.MkdirTemp("", "ceffio-support-")
	if err != nil {
		return "", err
	}

	// Le rapport (l'état ne contient que des noms et des états, aucun secret).
	f, err := os.Create(filepath.Join(dir, "diagnostic.json"))
	if err != nil {
		return dir, err
	}
	if err := WriteJSON(f, r); err != nil {
		f.Close()
		return dir, err
	}
	f.Close()

	// Journal des pods en difficulté uniquement.
	if r.State != nil && r.State.ClusterReachable {
		for _, l := range r.State.Layers {
			for _, p := range l.Pods {
				if p.Ready && p.Restarts < 3 {
					continue // pod sain : rien à diagnostiquer
				}
				raw, err := kubectlJSONString("logs", "-n", l.Namespace, p.Name, "--tail=200")
				if err != nil {
					continue
				}
				name := fmt.Sprintf("logs/%s__%s.log", l.Namespace, p.Name)
				os.MkdirAll(filepath.Join(dir, "logs"), 0o755)
				os.WriteFile(filepath.Join(dir, name), []byte(Redact(raw)), 0o644)
			}
		}
	}

	// Manifeste lisible par un humain.
	var sb strings.Builder
	fmt.Fprintf(&sb, "Archive de support Ceffio\n")
	fmt.Fprintf(&sb, "Genere le : %s\n\n", time.Now().Format(time.RFC3339))
	if r.State != nil {
		fmt.Fprintf(&sb, "Domaine   : %s\n", r.State.Domain)
		fmt.Fprintf(&sb, "Noeuds    : %d/%d prets\n", r.State.NodesReady, len(r.State.Nodes))
		fmt.Fprintf(&sb, "Pods      : %d/%d prets\n", r.State.ReadyPods, r.State.TotalPods)
	}
	fmt.Fprintf(&sb, "Problemes : %d\n\n", len(r.Findings))
	for _, x := range r.Findings {
		fmt.Fprintf(&sb, "[%s] %s — %s\n", x.Severity, x.Scope, x.Title)
	}
	sb.WriteString("\nAucun secret n'est inclus : ni valeur de Secret, ni mot de passe,\n")
	sb.WriteString("ni cle privee. Les journaux sont filtres avant ecriture.\n")
	os.WriteFile(filepath.Join(dir, "LISEZ-MOI.txt"), []byte(sb.String()), 0o644)

	return dir, nil
}

// WriteBundle produit l'archive .tar.gz de support et renvoie son chemin.
func WriteBundle(r Report) (string, error) {
	dir, err := bundleDir(r)
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)

	name := fmt.Sprintf("ceffio-support-%s.tar.gz", time.Now().Format("20060102-150405"))
	out, err := os.Create(name)
	if err != nil {
		return "", err
	}
	defer out.Close()

	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)

	var fichiers []string
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			fichiers = append(fichiers, p)
		}
		return nil
	})
	sort.Strings(fichiers)

	for _, p := range fichiers {
		rel, _ := filepath.Rel(dir, p)
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			continue
		}
		hdr.Name = rel
		if err := tw.WriteHeader(hdr); err != nil {
			return "", err
		}
		fh, err := os.Open(p)
		if err != nil {
			continue
		}
		io.Copy(tw, fh)
		fh.Close()
	}

	if err := tw.Close(); err != nil {
		return "", err
	}
	if err := gz.Close(); err != nil {
		return "", err
	}

	abs, _ := filepath.Abs(name)
	return abs, nil
}

func kubectlJSONString(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := kubectlJSON(ctx, args...)
	return string(out), err
}
