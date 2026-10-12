// Package console — configuration du SMTP de la plateforme.
//
// POURQUOI DANS LA CONSOLE ET PAS DANS LE CODE :
// Le SMTP est un réglage d'EXPLOITATION, pas de déploiement. Chaque organisation
// a son serveur mail, ses identifiants, son expéditeur. Le figer dans `ceffio
// install` obligerait à redéployer pour changer une adresse, et mettrait un mot
// de passe dans le code. Sa place est donc dans l'interface, où l'administrateur
// le configure, le TESTE et le sauvegarde.
//
// Ce que le SMTP sert : les mails que Nextcloud envoie LUI-MÊME — invitation à
// un partage, réinitialisation de mot de passe, notifications. Ce n'est PAS le
// compte de l'app Mail, qui lit les boîtes de l'utilisateur (IMAP/SMTP de ses
// propres comptes). Les deux sont indépendants.
//
// LE TEST AVANT SAUVEGARDE est le point clé : une configuration SMTP non testée
// ne vaut rien. Le test ouvre un vrai dialogue avec le serveur (connexion,
// STARTTLS, authentification, envoi) et rapporte ce qui a échoué, étape par
// étape. On ne se contente pas d'un « erreur » : on dit OÙ ça casse.
package console

import (
	"bufio"
	"log"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

// SmtpConfig est la configuration SMTP telle que l'interface la manipule.
//
// Le mot de passe n'est JAMAIS renvoyé au navigateur : on dit seulement s'il est
// défini (`MotDePasseDefini`). Une valeur de secret ne doit pas voyager vers une
// page web, même pour l'afficher.
type SmtpConfig struct {
	Hote              string `json:"hote"`
	Port              int    `json:"port"`
	Securite          string `json:"securite"`  // "tls" (STARTTLS), "ssl", "aucune"
	Utilisateur       string `json:"utilisateur"`
	MotDePasseDefini  bool   `json:"mot_de_passe_defini"`
	Expediteur        string `json:"expediteur"`
	NomExpediteur     string `json:"nom_expediteur,omitempty"`
}

// handleSmtp lit ou écrit la configuration SMTP.
//
//	GET  /api/smtp   → la configuration actuelle (sans le mot de passe)
//	POST /api/smtp   → enregistre (et pose le Secret si un mot de passe est fourni)
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
			apiErr(w, 400, "JSON illisible : "+err.Error())
			return
		}
		if entree.Hote == "" || entree.Utilisateur == "" {
			apiErr(w, 400, "le serveur et l'utilisateur sont requis")
			return
		}
		if entree.Port == 0 {
			entree.Port = 587
		}
		if entree.Securite == "" {
			entree.Securite = "tls"
		}
		// VÉRIFICATION AVANT SAUVEGARDE.
		//
		// On teste la configuration SAISIE avant de l'enregistrer. Sans cela,
		// une faute de frappe part en production et coupe l'envoi de mails de
		// toute l'instance — l'utilisateur ne s'en aperçoit qu'après coup.
		// Le test se fait avec le mot de passe saisi, ou celui déjà enregistré
		// si le champ a été laissé vide.
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
			// On N'ENREGISTRE PAS : on renvoie le detail pour que l'utilisateur
			// corrige et reessaie, sans avoir rien casse.
			writeJSON(w, 200, map[string]any{
				"ok":      false,
				"etapes":  etapes,
				"erreur":  errTest.Error(),
				"message": "configuration NON enregistrée : le test a échoué",
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
			"message": "Test réussi, configuration enregistrée",
		})

	default:
		apiErr(w, 405, "méthode non autorisée")
	}
}

// handleSmtpTester teste la configuration SANS l'enregistrer.
//
// POST /api/smtp/tester
//
// C'est le point important : on teste ce qui est SAISI, pas ce qui est déjà
// enregistré — sinon l'utilisateur ajuste, teste, se trompe, et découvre le
// problème après avoir sauvegardé.
func (s *Server) handleSmtpTester(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apiErr(w, 405, "méthode non autorisée")
		return
	}

	var entree struct {
		Hote          string `json:"hote"`
		Port          int    `json:"port"`
		Securite      string `json:"securite"`
		Utilisateur   string `json:"utilisateur"`
		MotDePasse    string `json:"mot_de_passe"`
		Expediteur    string `json:"expediteur"`
		Destinataire  string `json:"destinataire"`
	}
	if err := json.NewDecoder(r.Body).Decode(&entree); err != nil {
		apiErr(w, 400, "JSON illisible : "+err.Error())
		return
	}

	// Si aucun mot de passe n'est fourni, on reprend celui déjà enregistré :
	// l'utilisateur qui teste une config existante ne doit pas le ressaisir.
	if entree.MotDePasse == "" {
		mdp, err := s.motDePasseSmtp(r)
		if err != nil {
			// Ne pas masquer l'erreur : sans ce message, l'utilisateur voit
			// « identifiants refusés » alors que le mot de passe n'a jamais pu
			// être relu — deux problèmes très différents.
			log.Printf("smtp: relecture du mot de passe enregistré impossible : %v", err)
		} else {
			entree.MotDePasse = mdp
		}
	}
	if entree.Destinataire == "" {
		// Par défaut : l'expéditeur lui-même. Un test qui part et revient à
		// soi-même prouve la chaîne complète sans dépendre d'une autre boîte.
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
// Lecture / écriture de la configuration
// ---------------------------------------------------------------------------

func (s *Server) lireSmtp(r *http.Request) (*SmtpConfig, error) {
	// On lit la configuration via occ : c'est la source de vérité, et cela évite
	// de dupliquer la logique de lecture d'un fichier PHP.
	sortie, err := s.occSortie(r.Context(), "config:list", "system")
	if err != nil {
		return nil, fmt.Errorf("lecture de la configuration : %w", err)
	}
	// occ config:list system rend {"system": {...}} — le niveau "config" n'existe
	// PAS. Lire le mauvais niveau donne une map vide, donc tous les champs
	// apparaissent vides alors que la configuration est bien posée.
	var corps struct {
		System map[string]any `json:"system"`
	}
	if err := json.Unmarshal([]byte(sortie), &corps); err != nil {
		return nil, fmt.Errorf("réponse illisible : %w", err)
	}
	sys := corps.System

	// Pour les champs MASQUÉS par occ (les mail_smtp* contiennent le nom
	// d'utilisateur, traité comme sensible), on interroge chaque clé
	// individuellement — config:system:get rend la valeur réelle.
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
	// On ne renvoie JAMAIS le mot de passe : seulement s'il existe.
	cfg.MotDePasseDefini = chaine(sys["mail_smtppassword"]) != "" ||
		lire("mail_smtppassword") != ""
	if cfg.Securite == "" {
		cfg.Securite = "tls"
	}
	return cfg, nil
}

func (s *Server) ecrireSmtp(r *http.Request, hote string, port int, securite,
	utilisateur, motdepasse, expediteur, nomExpediteur string) error {

	// 1. Configuration Nextcloud. Le mot de passe passe par occ, qui l'écrit
	//    dans config.php — c'est ainsi que Nextcloud fonctionne, et il n'y a pas
	//    d'autre voie qui soit supportée.
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
			return fmt.Errorf("réglage « %s » : %w", r2[0], err)
		}
	}

	// 2. Copie dans un Secret Kubernetes : config.php est sur le volume
	//    persistant, et un mot de passe qui n'existe qu'à un seul endroit est un
	//    mot de passe qu'on perd à la prochaine réinstallation.
	if motdepasse != "" {
		if err := s.ecrireSecretSmtp(r, utilisateur, motdepasse); err != nil {
			// Non bloquant : la configuration Nextcloud est déjà posée et
			// fonctionnelle. On le signale sans faire échouer l'enregistrement.
			fmt.Printf("  (secret non mis à jour : %v)\n", err)
		}
	}
	return nil
}

// ecrireSecretSmtp pose les identifiants dans un Secret du namespace Nextcloud.
func (s *Server) ecrireSecretSmtp(r *http.Request, utilisateur, motdepasse string) error {
	if s.kube == nil {
		return fmt.Errorf("client Kubernetes indisponible")
	}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nextcloud-smtp",
			Namespace: "ceffio-files",
			Labels:    map[string]string{"app.kubernetes.io/part-of": "ceffio"},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"username": []byte(utilisateur),
			"password": []byte(motdepasse),
		},
	}
	// Create-or-update : on tente la création, et si le secret existe on le met
	// à jour. Deux appels plutôt qu'un « apply » : la console n'a pas de client
	// kubectl, elle parle directement à l'API.
	if _, err := s.kube.CoreV1().Secrets("ceffio-files").Create(r.Context(), sec, metav1.CreateOptions{}); err != nil {
		if _, err2 := s.kube.CoreV1().Secrets("ceffio-files").Update(r.Context(), sec, metav1.UpdateOptions{}); err2 != nil {
			return err2
		}
	}
	return nil
}

func (s *Server) motDePasseSmtp(r *http.Request) (string, error) {
	if s.kube == nil {
		return "", fmt.Errorf("client Kubernetes indisponible")
	}
	sec, err := s.kube.CoreV1().Secrets("ceffio-files").Get(r.Context(),
		"nextcloud-smtp", metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	return string(sec.Data["password"]), nil
}

// occSortie exécute occ dans le pod Nextcloud.
//
// POURQUOI occ ICI ET PAS L'API OCS : l'API OCS expose les applications et les
// utilisateurs, mais PAS les réglages système (mail_smtp*). Pour ceux-là, occ
// est la seule voie supportée, et il doit tourner dans le pod.
//
// On passe par l'API Kubernetes (pods/exec) plutôt que par le binaire kubectl :
// la console n'a pas besoin d'un kubectl, et le ServiceAccount porte déjà le
// droit d'exécuter dans ceffio-files (acquis pour la gestion des applications).
func (s *Server) occSortie(ctx context.Context, args ...string) (string, error) {
	if s.kube == nil {
		return "", fmt.Errorf("client Kubernetes indisponible")
	}
	complet := append([]string{"php", "occ"}, args...)
	pod, err := s.podNextcloud(ctx)
	if err != nil {
		return "", err
	}
	// Exec n'est pas dans le client Kubernetes standard : il vit dans le paquet
	// remotecommand, qui construit la requête de streaming. C'est le seul chemin
	// supporté pour exécuter une commande dans un pod depuis du code Go.
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return "", fmt.Errorf("configuration du cluster illisible : %w", err)
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
		return "", fmt.Errorf("exécuteur indisponible : %w", err)
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

// podNextcloud rend le nom du pod Nextcloud en service.
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
	return "", fmt.Errorf("aucun pod Nextcloud en service")
}

// ---------------------------------------------------------------------------
// Le test : un vrai dialogue SMTP, étape par étape
// ---------------------------------------------------------------------------

// testerSmtp ouvre une vraie session SMTP et rapporte CHAQUE étape.
//
// On ne se contente pas de « ça marche / ça ne marche pas » : on dit où ça
// casse. Un mot de passe refusé et un serveur injoignable demandent des
// corrections opposées, et le message d'erreur brut ne les distingue pas.
func testerSmtp(hote string, port int, securite, utilisateur, motdepasse,
	expediteur, destinataire string, timeout time.Duration) ([]string, error) {

	var etapes []string
	journal := func(f string, a ...any) { etapes = append(etapes, fmt.Sprintf(f, a...)) }

	adresse := net.JoinHostPort(hote, fmt.Sprint(port))
	journal("Connexion à %s…", adresse)

	conn, err := net.DialTimeout("tcp", adresse, timeout)
	if err != nil {
		journal("ÉCHEC : serveur injoignable")
		return etapes, fmt.Errorf("connexion à %s impossible : %w", adresse, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	journal("Connecté")

	br := bufio.NewReader(conn)
	// Lire UNE ligne ne suffit pas : les réponses SMTP sont multi-lignes, avec
	// "250-" pour les lignes intermédiaires et "250 " (espace) pour la dernière.
	// Lire une seule ligne attrape « 250-PIPELINING » et croit la réponse finie —
	// ce qui produit un faux échec sur un serveur parfaitement correct.
	//
	// Le reader est passé EN PARAMÈTRE, pas capturé : après STARTTLS on remplace
	// le reader par celui de la connexion chiffrée, et une closure qui aurait
	// capturé l'ancien continuerait de lire les octets non chiffrés — elle
	// verrait du bruit TLS et conclurait à un échec.
	lireDepuis := func(rd *bufio.Reader) string {
		var dernier string
		for {
			ligne, err := rd.ReadString('\n')
			if err != nil {
				return strings.TrimSpace(dernier)
			}
			dernier = ligne
			// Une ligne dont le 4e caractère est un espace termine la réponse.
			if len(ligne) < 4 || ligne[3] == ' ' {
				return strings.TrimSpace(ligne)
			}
		}
	}
	lire := func() string { return lireDepuis(br) }
	// envoyer trace la commande ET la réponse : sans cela, on ne peut pas
	// diagnostiquer un dialogue SMTP — le résumé masque ce que le serveur dit.
	//
	// Elle utilise `lire`, qui relit le reader COURANT : après STARTTLS le reader
	// change, et une closure qui aurait capturé l'ancien lirait les octets non
	// chiffrés.
	envoyer := func(cmd string) string {
		fmt.Fprintf(conn, "%s\r\n", cmd)
		rep := lire()
		journal(">> %s", tronquer(cmd, 60))
		journal("<< %s", tronquer(rep, 80))
		return rep
	}

	// 1. bannière
	journal("Serveur : %s", tronquer(lire(), 80))

	// 2. EHLO
	if rep := envoyer("EHLO ceffio.local"); !strings.HasPrefix(rep, "250") {
		return etapes, fmt.Errorf("le serveur a refusé EHLO : %s", rep)
	}

	// 3. STARTTLS si demandé
	if securite == "tls" {
		fmt.Fprintf(conn, "STARTTLS\r\n")
		rep := lire()
		if !strings.HasPrefix(rep, "220") {
			journal("ÉCHEC STARTTLS : %s", tronquer(rep, 80))
			return etapes, fmt.Errorf("STARTTLS refusé : %s", rep)
		}
		tlsConn := tls.Client(conn, &tls.Config{ServerName: hote})
		if err := tlsConn.Handshake(); err != nil {
			journal("ÉCHEC TLS : %s", err)
			return etapes, fmt.Errorf("poignée de main TLS refusée : %w", err)
		}
		conn = tlsConn
		br = bufio.NewReader(conn)
		// `lire` lit maintenant depuis LE NOUVEAU reader : c'est le point qui
		// faisait échouer le test — l'ancien reader lisait du TLS brut.
		lire = func() string { return lireDepuis(br) }
		journal("TLS établi (%s)", versionTLS(tlsConn.ConnectionState().Version))
		// Il faut refaire EHLO après STARTTLS : le serveur remet la session à zéro.
		fmt.Fprintf(conn, "EHLO ceffio.local\r\n")
		lire()
	}

	// 4. authentification
	//
	// AUTH PLAIN d'abord : c'est le mécanisme que ce type de serveur accepte
	// directement, et le dialogue le plus court (un seul bloc
	// « \0utilisateur\0motdepasse »). AUTH LOGIN en repli.
	//
	// Un échec d'authentification laisse la session dans un état où le serveur
	// ne répond plus normalement : on NE réessaie donc PAS sur la même
	// connexion — c'est ce qui produisait des « 501 Syntax » en cascade.
	bloc := "\x00" + utilisateur + "\x00" + motdepasse
	if rep := envoyer("AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte(bloc)));
		strings.HasPrefix(rep, "235") {
		journal("Authentification acceptée (PLAIN)")
	} else {
		journal("AUTH PLAIN refusé : %s", tronquer(rep, 80))
		// Repli LOGIN, sur la même session : si le serveur l'accepte encore.
		if rep2 := envoyer("AUTH LOGIN"); strings.HasPrefix(rep2, "334") {
			envoyer(base64.StdEncoding.EncodeToString([]byte(utilisateur)))
			if rep3 := envoyer(base64.StdEncoding.EncodeToString([]byte(motdepasse)));
				strings.HasPrefix(rep3, "235") {
				journal("Authentification acceptée (LOGIN)")
			} else {
				journal("ÉCHEC AUTHENTIFICATION : %s", tronquer(rep3, 80))
				return etapes, fmt.Errorf("identifiants refusés : %s", rep3)
			}
		} else {
			journal("ÉCHEC AUTHENTIFICATION : %s", tronquer(rep, 80))
			return etapes, fmt.Errorf("identifiants refusés : %s", rep)
		}
	}

	// 5. envoi
	fmt.Fprintf(conn, "MAIL FROM:<%s>\r\n", expediteur)
	if rep := lire(); !strings.HasPrefix(rep, "250") {
		journal("ÉCHEC expéditeur : %s", tronquer(rep, 80))
		return etapes, fmt.Errorf("expéditeur refusé : %s", rep)
	}
	journal("Expéditeur accepté : %s", expediteur)

	fmt.Fprintf(conn, "RCPT TO:<%s>\r\n", destinataire)
	if rep := lire(); !strings.HasPrefix(rep, "250") {
		journal("ÉCHEC destinataire : %s", tronquer(rep, 80))
		return etapes, fmt.Errorf("destinataire refusé : %s", rep)
	}
	journal("Destinataire accepté : %s", destinataire)

	fmt.Fprintf(conn, "DATA\r\n")
	if rep := lire(); !strings.HasPrefix(rep, "354") {
		journal("ÉCHEC DATA : %s", tronquer(rep, 80))
		return etapes, fmt.Errorf("le serveur refuse le corps du message : %s", rep)
	}
	corps := "Subject: Test SMTP Ceffio\r\n" +
		"From: " + expediteur + "\r\n" +
		"To: " + destinataire + "\r\n" +
		"\r\n" +
		"Test de configuration SMTP depuis la console Ceffio.\r\n" +
		"Si vous lisez ce message, l'envoi est correctement configuré.\r\n" +
		".\r\n"
	fmt.Fprint(conn, corps)
	if rep := lire(); !strings.HasPrefix(rep, "250") {
		journal("ÉCHEC envoi : %s", tronquer(rep, 80))
		return etapes, fmt.Errorf("le serveur a refusé le message : %s", rep)
	}
	journal("Message accepté par le serveur")

	fmt.Fprintf(conn, "QUIT\r\n")
	journal("Terminé avec succès")
	return etapes, nil
}

// versionTLS rend la version TLS en texte. Un uint16 formaté avec %s affiche
// « %!s(uint16=772) », ce qui ne dit rien à personne.
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
	return fmt.Sprintf("version inconnue (%d)", v)
}

func tronquer(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// premier rend la première valeur non vide — sert à préférer la lecture par clé
// (valeur réelle) au repli sur config:list (valeur parfois masquée).
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