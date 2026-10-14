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

// Finding is a detected problem, with something to act on.
type Finding struct {
	Severity string `json:"severity"` // severity levels emitted by `ceffio doctor`: "critical" | "warning"
	Scope    string `json:"scope"`    // cluster, tls, network, or a layer name
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
	Action   string `json:"action,omitempty"`
}

// Report is the complete result of a diagnostic.
type Report struct {
	GeneratedAt string    `json:"generated_at"`
	Version     string    `json:"version,omitempty"`
	State       *State    `json:"state"`
	Findings    []Finding `json:"findings"`
}

// WriteJSON serializes a report.
func WriteJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// ---------------------------------------------------------------------------
// Support archive
// ---------------------------------------------------------------------------

// Patterns for what must NEVER leave the machine in a bundle. We filter at
// write time: even if the caller makes a mistake and attaches an overly broad
// document, the sensitive values are neutralized before entering the
// archive. A support bundle travels by email — it must contain no secrets,
// without exception.
var (
	reSecretJSON = regexp.MustCompile(`(?i)"(password|passwd|secret|token|api[_-]?key|private[_-]?key|client[_-]?secret)"\s*:\s*"[^"]*"`)
	reSecretYAML = regexp.MustCompile(`(?im)^(\s*(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|client[_-]?secret|smtp_password)\s*:\s*).*$`)
	reDataType   = regexp.MustCompile(`(?i)"data"\s*:\s*\{[^}]*\}`)
	reBearer     = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._\-]{8,}`)
	rePrivateKey = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)
	reConnString = regexp.MustCompile(`(?i)([a-z]+://[^:@/\s]+:)[^@/\s]+(@)`)
)

// Redact neutralizes the sensitive values of a text.
func Redact(s string) string {
	s = rePrivateKey.ReplaceAllString(s, "[PRIVATE KEY REMOVED]")
	s = reSecretJSON.ReplaceAllString(s, `"$1":"[REMOVED]"`)
	s = reSecretYAML.ReplaceAllString(s, `${1}[REMOVED]`)
	s = reDataType.ReplaceAllString(s, `"data":{"[REMOVED]":"Secret values are not collected"}`)
	s = reBearer.ReplaceAllString(s, `${1}[REMOVED]`)
	s = reConnString.ReplaceAllString(s, `${1}[REMOVED]${2}`)
	return s
}

// bundleDir collects the non-sensitive items: state, diagnostic, and the
// logs of only the pods in trouble (never those of healthy pods).
func bundleDir(r Report) (string, error) {
	dir, err := os.MkdirTemp("", "ceffio-support-")
	if err != nil {
		return "", err
	}

	// The report (the state only contains names and statuses, no secrets).
	f, err := os.Create(filepath.Join(dir, "diagnostic.json"))
	if err != nil {
		return dir, err
	}
	if err := WriteJSON(f, r); err != nil {
		f.Close()
		return dir, err
	}
	f.Close()

	// Logs of the pods in trouble only.
	if r.State != nil && r.State.ClusterReachable {
		for _, l := range r.State.Layers {
			for _, p := range l.Pods {
				if p.Ready && p.Restarts < 3 {
					continue // healthy pod: nothing to diagnose
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

	// Human-readable manifest.
	var sb strings.Builder
	fmt.Fprintf(&sb, "Ceffio support archive\n")
	fmt.Fprintf(&sb, "Generated on: %s\n\n", time.Now().Format(time.RFC3339))
	if r.State != nil {
		fmt.Fprintf(&sb, "Domain     : %s\n", r.State.Domain)
		fmt.Fprintf(&sb, "Nodes      : %d/%d ready\n", r.State.NodesReady, len(r.State.Nodes))
		fmt.Fprintf(&sb, "Pods       : %d/%d ready\n", r.State.ReadyPods, r.State.TotalPods)
	}
	fmt.Fprintf(&sb, "Problems   : %d\n\n", len(r.Findings))
	for _, x := range r.Findings {
		fmt.Fprintf(&sb, "[%s] %s — %s\n", x.Severity, x.Scope, x.Title)
	}
	sb.WriteString("\nNo secrets are included: no Secret values, no passwords,\n")
	sb.WriteString("no private keys. Logs are filtered before writing.\n")
	os.WriteFile(filepath.Join(dir, "README.txt"), []byte(sb.String()), 0o644)

	return dir, nil
}

// WriteBundle produces the .tar.gz support archive and returns its path.
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
