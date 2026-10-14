// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package console — SMTP configuration of the platform.
//
// WHY IN THE CONSOLE AND NOT IN THE CODE:
// SMTP is an OPERATIONS setting, not a deployment one. Each organization has
// its mail server, its credentials, its sender. Freezing it in `ceffio
// install` would force a redeployment to change an address, and would put a
// password in the code. Its place is therefore in the interface, where the
// administrator configures, TESTS and saves it.
//
// What SMTP serves: the mails Nextcloud sends ITSELF — share invitations,
// password reset, notifications. It is NOT the Mail app account, which reads
// the user's mailboxes (IMAP/SMTP of their own accounts). The two are
// independent.
//
// THE TEST BEFORE SAVE is the key point: an untested SMTP configuration is
// worthless. The test opens a real dialogue with the server (connection,
// STARTTLS, authentication, send) and reports what failed, step by step. We
// do not settle for a bare "error": we say WHERE it breaks.
package console

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"

	"github.com/ceffio-suite/ceffio/internal/secrets"
)

// SmtpConfig is the SMTP configuration as the interface manipulates it.
//
// The password is NEVER sent back to the browser: we only say whether it is
// set (`MotDePasseDefini`). A secret value must not travel to a web page, not
// even to display it.
type SmtpConfig struct {
	Hote             string `json:"hote"`
	Port             int    `json:"port"`
	Securite         string `json:"securite"` // "tls" (STARTTLS), "ssl", "aucune" (none)
	Utilisateur      string `json:"utilisateur"`
	MotDePasseDefini bool   `json:"mot_de_passe_defini"`
	Expediteur       string `json:"expediteur"`
	NomExpediteur    string `json:"nom_expediteur,omitempty"`
}

// handleSmtp reads or writes the SMTP configuration.
//
//	GET  /api/smtp   → the current configuration (without the password)
//	POST /api/smtp   → saves (and sets the Secret if a password is provided)
func (s *Server) handleSmtp(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg, err := s.lireSmtp(r)
		if err != nil {
			apiErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, cfg)

	case http.MethodPost:
		var entree struct {
			Hote          string `json:"hote"`
			Port          int    `json:"port"`
			Securite      string `json:"securite"`
			Utilisateur   string `json:"utilisateur"`
			MotDePasse    string `json:"mot_de_passe"`
			Expediteur    string `json:"expediteur"`
			NomExpediteur string `json:"nom_expediteur"`
		}
		if err := json.NewDecoder(r.Body).Decode(&entree); err != nil {
			apiErr(w, 400, "unreadable JSON: "+err.Error())
			return
		}
		if entree.Hote == "" || entree.Utilisateur == "" {
			apiErr(w, 400, "server and user are required")
			return
		}
		if entree.Port == 0 {
			entree.Port = 587
		}
		if entree.Securite == "" {
			entree.Securite = "tls"
		}
		// VERIFICATION BEFORE SAVE.
		//
		// We test the ENTERED configuration before saving it. Without this, a
		// typo goes to production and cuts mail sending for the whole instance
		// — the user only notices afterwards. The test runs with the entered
		// password, or the already saved one if the field was left empty.
		mdpTest := entree.MotDePasse
		if mdpTest == "" {
			if mdp, err := s.motDePasseSmtp(r); err == nil {
				mdpTest = mdp
			}
		}
		destinataire := entree.Expediteur
		if entree.Expediteur == "" {
			destinataire = entree.Utilisateur
		}
		etapes, errTest := testerSmtp(entree.Hote, entree.Port, entree.Securite,
			entree.Utilisateur, mdpTest, entree.Expediteur, destinataire, 25*time.Second)
		if errTest != nil {
			// We do NOT SAVE: we return the detail so the user corrects and
			// retries, without having broken anything.
			writeJSON(w, 200, map[string]any{
				"ok":      false,
				"etapes":  etapes,
				"erreur":  errTest.Error(),
				"message": "configuration NOT saved: the test failed",
			})
			return
		}

		if err := s.ecrireSmtp(r, entree.Hote, entree.Port, entree.Securite,
			entree.Utilisateur, entree.MotDePasse, entree.Expediteur,
			entree.NomExpediteur); err != nil {
			apiErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{
			"ok":      true,
			"etapes":  etapes,
			"message": "Test passed, configuration saved",
		})

	default:
		apiErr(w, 405, "method not allowed")
	}
}

// handleSmtpTester tests the configuration WITHOUT saving it.
//
// POST /api/smtp/tester
//
// This is the important point: we test what is ENTERED, not what is already
// saved — otherwise the user adjusts, tests, gets it wrong, and discovers the
// problem after saving.
func (s *Server) handleSmtpTester(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apiErr(w, 405, "method not allowed")
		return
	}

	var entree struct {
		Hote         string `json:"hote"`
		Port         int    `json:"port"`
		Securite     string `json:"securite"`
		Utilisateur  string `json:"utilisateur"`
		MotDePasse   string `json:"mot_de_passe"`
		Expediteur   string `json:"expediteur"`
		Destinataire string `json:"destinataire"`
	}
	if err := json.NewDecoder(r.Body).Decode(&entree); err != nil {
		apiErr(w, 400, "JSON illisible : "+err.Error())
		return
	}

	// If no password is provided, we take the already saved one:
	// the user testing an existing config should not retype it.
	if entree.MotDePasse == "" {
		mdp, err := s.motDePasseSmtp(r)
		if err != nil {
			// Do not mask the error: without this message, the user sees
			// "credentials refused" while the password could never be read
			// back — two very different problems.
			log.Printf("smtp: cannot re-read the saved password: %v", err)
		} else {
			entree.MotDePasse = mdp
		}
	}
	if entree.Destinataire == "" {
		// By default: the sender itself. A test that leaves and comes back to
		// oneself proves the full chain without depending on another mailbox.
		entree.Destinataire = entree.Expediteur
	}

	etapes, err := testerSmtp(entree.Hote, entree.Port, entree.Securite,
		entree.Utilisateur, entree.MotDePasse, entree.Expediteur, entree.Destinataire, 25*time.Second)

	reponse := map[string]any{"etapes": etapes, "ok": err == nil}
	if err != nil {
		reponse["erreur"] = err.Error()
	}
	writeJSON(w, 200, reponse)
}

// ---------------------------------------------------------------------------
// Reading / writing the configuration
// ---------------------------------------------------------------------------

func (s *Server) lireSmtp(r *http.Request) (*SmtpConfig, error) {
	// We read the configuration via occ: it is the source of truth, and it
	// avoids duplicating the logic of reading a PHP file.
	sortie, err := s.occSortie(r.Context(), "config:list", "system")
	if err != nil {
		return nil, fmt.Errorf("reading the configuration: %w", err)
	}
	// occ config:list system returns {"system": {...}} — the "config" level
	// does NOT exist. Reading the wrong level gives an empty map, so all the
	// fields appear empty while the configuration is actually set.
	var corps struct {
		System map[string]any `json:"system"`
	}
	if err := json.Unmarshal([]byte(sortie), &corps); err != nil {
		return nil, fmt.Errorf("unreadable response: %w", err)
	}
	sys := corps.System

	// For the fields MASKED by occ (the mail_smtp* contain the username,
	// treated as sensitive), we query each key individually —
	// config:system:get returns the real value.
	lire := func(cle string) string {
		v, err := s.occSortie(r.Context(), "config:system:get", cle)
		if err != nil {
			return ""
		}
		v = strings.TrimSpace(v)
		if strings.Contains(v, "REMOVED SENSITIVE") {
			return ""
		}
		return v
	}

	cfg := &SmtpConfig{
		Hote:          premier(lire("mail_smtphost"), chaine(sys["mail_smtphost"])),
		Port:          entier(sys["mail_smtpport"], 587),
		Securite:      premier(lire("mail_smtpsecure"), chaine(sys["mail_smtpsecure"])),
		Utilisateur:   premier(lire("mail_smtpname"), chaine(sys["mail_smtpname"])),
		Expediteur:    premier(lire("mail_from_address"), chaine(sys["mail_from_address"])),
		NomExpediteur: premier(lire("mail_domain"), chaine(sys["mail_domain"])),
	}
	// We NEVER send back the password: only whether it exists.
	cfg.MotDePasseDefini = chaine(sys["mail_smtppassword"]) != "" ||
		lire("mail_smtppassword") != ""
	if cfg.Securite == "" {
		cfg.Securite = "tls"
	}
	return cfg, nil
}

func (s *Server) ecrireSmtp(r *http.Request, hote string, port int, securite,
	utilisateur, motdepasse, expediteur, nomExpediteur string) error {

	// 1. Nextcloud configuration. The password goes through occ, which writes
	//    it in config.php — that is how Nextcloud works, and there is no other
	//    supported path.
	reglages := [][]string{
		{"mail_smtpmode", "smtp"},
		{"mail_smtphost", hote},
		{"mail_smtpport", fmt.Sprint(port)},
		{"mail_smtpsecure", securite},
		{"mail_smtpauth", "1"},
		{"mail_smtpauthtype", "LOGIN"},
		{"mail_smtpname", utilisateur},
	}
	if expediteur != "" {
		reglages = append(reglages, []string{"mail_from_address", expediteur})
	}
	if nomExpediteur != "" {
		reglages = append(reglages, []string{"mail_domain", nomExpediteur})
	}
	if motdepasse != "" {
		reglages = append(reglages, []string{"mail_smtppassword", motdepasse})
	}

	for _, r2 := range reglages {
		if _, err := s.occSortie(r.Context(), "config:system:set", r2[0], "--value", r2[1]); err != nil {
			return fmt.Errorf("setting \"%s\": %w", r2[0], err)
		}
	}

	// 2. Copy into a Kubernetes Secret: config.php is on the persistent
	//    volume, and a password that only exists in one place is a password
	//    lost at the next reinstall.
	if motdepasse != "" {
		if err := s.ecrireSecretSmtp(r, utilisateur, motdepasse); err != nil {
			// Non-blocking: the Nextcloud configuration is already set and
			// functional. We flag it without failing the save.
			fmt.Printf("  (secret not updated: %v)\n", err)
		}
	}
	return nil
}

// ecrireSecretSmtp stores the relay credentials IN THE VAULT.
//
// NO MORE KUBERNETES SECRET: the SMTP relay is an application setting, not a
// cluster resource. Nextcloud already receives its configuration via occ;
// keeping a copy in Kubernetes would only have created a second source to let
// diverge.
func (s *Server) ecrireSecretSmtp(r *http.Request, utilisateur, motdepasse string) error {
	return secrets.EcrireDansCoffre(r.Context(), secrets.DepuisEnvironnement(), "smtp", "relais",
		map[string]string{"username": utilisateur, "password": motdepasse})
}

func (s *Server) motDePasseSmtp(r *http.Request) (string, error) {
	if s.kube == nil {
		return "", fmt.Errorf("Kubernetes client unavailable")
	}
	// THE PASSWORD IS READ FROM THE VAULT, like everything else in the suite.
	// The fallback to the Kubernetes Secret disappeared with it: keeping both
	// sources meant guaranteeing they would diverge one day.
	entree, err := secrets.LireEntreeCoffre(r.Context(), secrets.DepuisEnvironnement(), "smtp", "relais")
	if err != nil {
		return "", err
	}
	return entree["password"], nil
}

// occSortie runs occ in the Nextcloud pod.
//
// WHY occ HERE AND NOT THE OCS API: the OCS API exposes applications and
// users, but NOT the system settings (mail_smtp*). For those, occ is the only
// supported path, and it must run in the pod.
//
// We go through the Kubernetes API (pods/exec) rather than the kubectl
// binary: the console does not need a kubectl, and the ServiceAccount already
// carries the right to exec in ceffio-files (acquired for application
// management).
func (s *Server) occSortie(ctx context.Context, args ...string) (string, error) {
	if s.kube == nil {
		return "", fmt.Errorf("Kubernetes client unavailable")
	}
	complet := append([]string{"php", "occ"}, args...)
	pod, err := s.podNextcloud(ctx)
	if err != nil {
		return "", err
	}
	// Exec is not in the standard Kubernetes client: it lives in the
	// remotecommand package, which builds the streaming request. It is the
	// only supported path to run a command in a pod from Go code.
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return "", fmt.Errorf("cluster configuration unreadable: %w", err)
	}
	req := s.kube.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod).
		Namespace("ceffio-files").
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "nextcloud",
			Command:   complet,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	executeur, err := remotecommand.NewSPDYExecutor(cfg, "POST", req.URL())
	if err != nil {
		return "", fmt.Errorf("executor unavailable: %w", err)
	}
	var sortie, errs strings.Builder
	if err := executeur.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &sortie,
		Stderr: &errs,
	}); err != nil {
		return sortie.String(), fmt.Errorf("%w: %s", err, errs.String())
	}
	return sortie.String(), nil
}

// podNextcloud returns the name of the Nextcloud pod in service.
func (s *Server) podNextcloud(ctx context.Context) (string, error) {
	pods, err := s.kube.CoreV1().Pods("ceffio-files").List(ctx, metav1.ListOptions{
		LabelSelector: "app=nextcloud",
	})
	if err != nil {
		return "", err
	}
	for _, p := range pods.Items {
		if p.Status.Phase == corev1.PodRunning {
			return p.Name, nil
		}
	}
	return "", fmt.Errorf("no Nextcloud pod in service")
}

// ---------------------------------------------------------------------------
// The test: a real SMTP dialogue, step by step
// ---------------------------------------------------------------------------

// testerSmtp opens a real SMTP session and reports EACH step.
//
// We do not settle for "it works / it doesn't": we say where it breaks. A
// refused password and an unreachable server demand opposite corrections, and
// the raw error message does not distinguish them.
func testerSmtp(hote string, port int, securite, utilisateur, motdepasse,
	expediteur, destinataire string, timeout time.Duration) ([]string, error) {

	var etapes []string
	journal := func(f string, a ...any) { etapes = append(etapes, fmt.Sprintf(f, a...)) }

	adresse := net.JoinHostPort(hote, fmt.Sprint(port))
	journal("Connecting to %s…", adresse)

	conn, err := net.DialTimeout("tcp", adresse, timeout)
	if err != nil {
		journal("FAILED: server unreachable")
		return etapes, fmt.Errorf("cannot connect to %s: %w", adresse, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	journal("Connected")

	br := bufio.NewReader(conn)
	// Reading ONE line is not enough: SMTP responses are multi-line, with
	// "250-" for the intermediate lines and "250 " (space) for the last one.
	// Reading a single line catches "250-PIPELINING" and believes the response
	// is finished — which produces a false failure on a perfectly correct
	// server.
	//
	// The reader is passed AS A PARAMETER, not captured: after STARTTLS we
	// replace the reader with the one of the encrypted connection, and a
	// closure that had captured the old one would keep reading the unencrypted
	// bytes — it would see TLS noise and conclude to a failure.
	lireDepuis := func(rd *bufio.Reader) string {
		var dernier string
		for {
			ligne, err := rd.ReadString('\n')
			if err != nil {
				return strings.TrimSpace(dernier)
			}
			dernier = ligne
			// A line whose 4th character is a space ends the response.
			if len(ligne) < 4 || ligne[3] == ' ' {
				return strings.TrimSpace(ligne)
			}
		}
	}
	lire := func() string { return lireDepuis(br) }
	// envoyer traces the command AND the response: without this, an SMTP
	// dialogue cannot be diagnosed — the summary masks what the server says.
	//
	// It uses `lire`, which re-reads the CURRENT reader: after STARTTLS the
	// reader changes, and a closure that had captured the old one would read
	// the unencrypted bytes.
	envoyer := func(cmd string) string {
		fmt.Fprintf(conn, "%s\r\n", cmd)
		rep := lire()
		journal(">> %s", tronquer(cmd, 60))
		journal("<< %s", tronquer(rep, 80))
		return rep
	}

	// 1. banner
	journal("Server: %s", tronquer(lire(), 80))

	// 2. EHLO
	if rep := envoyer("EHLO ceffio.local"); !strings.HasPrefix(rep, "250") {
		return etapes, fmt.Errorf("server rejected EHLO: %s", rep)
	}

	// 3. STARTTLS if requested
	if securite == "tls" {
		fmt.Fprintf(conn, "STARTTLS\r\n")
		rep := lire()
		if !strings.HasPrefix(rep, "220") {
			journal("STARTTLS FAILED: %s", tronquer(rep, 80))
			return etapes, fmt.Errorf("STARTTLS refused: %s", rep)
		}
		tlsConn := tls.Client(conn, &tls.Config{ServerName: hote})
		if err := tlsConn.Handshake(); err != nil {
			journal("TLS FAILED: %s", err)
			return etapes, fmt.Errorf("TLS handshake refused: %w", err)
		}
		conn = tlsConn
		br = bufio.NewReader(conn)
		// `lire` now reads from THE NEW reader: this is the point that made the
		// test fail — the old reader was reading raw TLS.
		lire = func() string { return lireDepuis(br) }
		journal("TLS established (%s)", versionTLS(tlsConn.ConnectionState().Version))
		// EHLO must be sent again after STARTTLS: the server resets the session.
		fmt.Fprintf(conn, "EHLO ceffio.local\r\n")
		lire()
	}

	// 4. authentication
	//
	// AUTH PLAIN first: it is the mechanism this kind of server accepts
	// directly, and the shortest dialogue (a single "\0user\0password"
	// block). AUTH LOGIN as fallback.
	//
	// An authentication failure leaves the session in a state where the server
	// no longer answers normally: we therefore do NOT retry on the same
	// connection — that is what produced cascading "501 Syntax".
	bloc := "\x00" + utilisateur + "\x00" + motdepasse
	if rep := envoyer("AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte(bloc))); strings.HasPrefix(rep, "235") {
		journal("Authentication accepted (PLAIN)")
	} else {
		journal("AUTH PLAIN refused: %s", tronquer(rep, 80))
		// LOGIN fallback, on the same session: if the server still accepts it.
		if rep2 := envoyer("AUTH LOGIN"); strings.HasPrefix(rep2, "334") {
			envoyer(base64.StdEncoding.EncodeToString([]byte(utilisateur)))
			if rep3 := envoyer(base64.StdEncoding.EncodeToString([]byte(motdepasse))); strings.HasPrefix(rep3, "235") {
				journal("Authentication accepted (LOGIN)")
			} else {
				journal("AUTHENTICATION FAILED: %s", tronquer(rep3, 80))
				return etapes, fmt.Errorf("credentials rejected: %s", rep3)
			}
		} else {
			journal("AUTHENTICATION FAILED: %s", tronquer(rep, 80))
			return etapes, fmt.Errorf("credentials rejected: %s", rep)
		}
	}

	// 5. send
	fmt.Fprintf(conn, "MAIL FROM:<%s>\r\n", expediteur)
	if rep := lire(); !strings.HasPrefix(rep, "250") {
		journal("sender FAILED: %s", tronquer(rep, 80))
		return etapes, fmt.Errorf("sender rejected: %s", rep)
	}
	journal("Sender accepted: %s", expediteur)

	fmt.Fprintf(conn, "RCPT TO:<%s>\r\n", destinataire)
	if rep := lire(); !strings.HasPrefix(rep, "250") {
		journal("recipient FAILED: %s", tronquer(rep, 80))
		return etapes, fmt.Errorf("recipient rejected: %s", rep)
	}
	journal("Recipient accepted: %s", destinataire)

	fmt.Fprintf(conn, "DATA\r\n")
	if rep := lire(); !strings.HasPrefix(rep, "354") {
		journal("DATA FAILED: %s", tronquer(rep, 80))
		return etapes, fmt.Errorf("server refuses the message body: %s", rep)
	}
	corps := "Subject: Test SMTP Ceffio\r\n" +
		"From: " + expediteur + "\r\n" +
		"To: " + destinataire + "\r\n" +
		"\r\n" +
		"SMTP configuration test from the Ceffio console.\r\n" +
		"If you are reading this message, mail delivery is correctly configured.\r\n" +
		".\r\n"
	fmt.Fprint(conn, corps)
	if rep := lire(); !strings.HasPrefix(rep, "250") {
		journal("send FAILED: %s", tronquer(rep, 80))
		return etapes, fmt.Errorf("server rejected the message: %s", rep)
	}
	journal("Message accepted by the server")

	fmt.Fprintf(conn, "QUIT\r\n")
	journal("Completed successfully")
	return etapes, nil
}

// versionTLS returns the TLS version as text. A uint16 formatted with %s shows
// "%!s(uint16=772)", which says nothing to anyone.
func versionTLS(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	}
	return fmt.Sprintf("unknown version (%d)", v)
}

func tronquer(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// premier returns the first non-empty value — used to prefer the per-key read
// (real value) over the config:list fallback (sometimes masked value).
func premier(valeurs ...string) string {
	for _, v := range valeurs {
		if v != "" {
			return v
		}
	}
	return ""
}

func chaine(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func entier(v any, def int) int {
	if f, ok := v.(float64); ok {
		return int(f)
	}
	return def
}
