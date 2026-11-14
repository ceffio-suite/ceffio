// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package mail

// The mail module's SETTINGS: the server itself, and the outbound relay.
//
// WHY THIS MOVED HERE: the relay was configurable ONLY at installation, through
// four flags (--smtp-relais, --smtp-relais-port, --smtp-relais-user,
// --smtp-relais-pass). Changing a relay host meant relaunching the whole
// installation — an operation that redeploys every layer — for a value that
// concerns one line of one configuration.
//
// WHAT IT IS FOR, and why it is indispensable: outbound port 25 is blocked by
// consumer ISPs, so Stalwart cannot deliver to Gmail by itself. The
// authenticated relay on 587 works around that block and provides the reverse
// DNS. Without it the suite receives mail and cannot send any.
//
// FOUND WHILE WRITING THIS, and worth reporting: the password was NEVER STORED.
// `configurerRelais` (removed by PR 1 of docs/plan-mail.md) received it, used it
// to verify the authentication, and forgot it — the relay was never actually
// written into Stalwart's configuration, and the function said so itself ("to be
// finalized through the admin interface"). The credential now goes to OpenBao,
// at `kv/ceffio/mail/relay`, so a restart, a reinstall or a restore does not
// lose it.
//
// THE `server` GROUP WAS ADDED BY PR 1, for the three settings the deployment
// could not express: how mail leaves, how big the store is, and whether IMAP /
// SMTPS are published to the outside. They were measured as broken or missing
// (docs/plan-mail.md §9.E): the Service declared ports 587 and 143 that Stalwart
// 1.0.3 does not listen on, and the volume was a hard-coded 20 GiB.
//
// THE TWO GROUPS SHARE ONE APPLY PATH: `Apply` of either one ends by
// re-applying the server configuration (volume size, exposure, outbound route)
// and reading it back, as §4.2 rule 6 of the plan requires. A setting that is
// stored but not applied is the failure mode this file exists to prevent.

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mailcore "github.com/ceffio-suite/ceffio/internal/mail"
	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/secrets"
)

const (
	// groupeRelais is the settings group for the outbound relay.
	groupeRelais = "relay"
	// groupeServeur is the settings group for the server itself: send mode,
	// volume size, default quota, external clients.
	groupeServeur = "server"

	// ComposantCoffre and SousCheminCoffre are the vault coordinates of the
	// relay credential.
	//
	// A NEW PATH, and deliberately: the relay password was never stored before,
	// so there is nothing to preserve and no existing installation to migrate.
	// It is named after the module so a backup picks it up with the rest of the
	// mail layer's secrets.
	ComposantCoffre  = "mail"
	SousCheminCoffre = "relay"
)

// Settings declares the groups.
func (m *mailModule) Settings() []module.Group {
	return []module.Group{{
		ID:    groupeRelais,
		Title: "Outbound relay (Stalwart)",
		Description: "Where Stalwart hands its outgoing mail. This is NOT Nextcloud's own mail — " +
			"that one is the files module's business. A relay is indispensable in practice: " +
			"outbound port 25 is blocked by consumer ISPs, so the suite receives mail and cannot " +
			"send any without one.",
		Fields: []module.Field{
			{
				Key:      "hote",
				Label:    "Relay host",
				Help:     "Hostname of the provider's SMTP relay, for example smtp.example.org.",
				Type:     module.Text,
				Required: true,
			},
			{
				Key:     "port",
				Label:   "Port",
				Help:    "587 for an authenticated submission relay. 465 is accepted where the provider offers it.",
				Type:    module.Number,
				Default: "587",
			},
			{
				Key:      "utilisateur",
				Label:    "Username",
				Help:     "The authenticated account on the relay.",
				Type:     module.Text,
				Required: true,
			},
			{
				Key:   "mot_de_passe",
				Label: "Password",
				Help:  "Never sent back to a page: leave empty to keep the stored one.",
				Type:  module.Secret,
			},
			{
				Key:     "exiger_tls",
				Label:   "Require STARTTLS",
				Help:    "Refuses a relay that does not upgrade the connection to TLS. Turning this off sends the credential in clear text.",
				Type:    module.Bool,
				Default: "true",
			},
		},
	}, {
		ID:    groupeServeur,
		Title: "Mail server (Stalwart)",
		Description: "How the server sends, how much space it has, and to whom it shows its " +
			"mailbox ports. These are the values the deployment applies; changing them " +
			"re-applies the server configuration rather than reinstalling the suite.",
		Fields: []module.Field{
			{
				Key:   "envoi",
				Label: "Outgoing mail",
				Help: "`Direct` hands each message to the recipient's MX: it only works if " +
					"outbound port 25 is open and the reverse DNS of the public IP is right. " +
					"`Through the relay` requires the relay group to be filled in and its Test to pass.",
				Type: module.Choice,
				Options: []module.Option{
					{Value: mailcore.ModeDirect, Label: "Direct (recipient's MX)"},
					{Value: mailcore.ModeRelais, Label: "Through the outbound relay"},
				},
				Default: mailcore.ModeDirect,
			},
			{
				Key:   "volume_gio",
				Label: "Mailbox volume (GiB)",
				Help: "Size of the volume holding every mailbox. It can grow, never shrink: a " +
					"smaller value than the volume in place is refused by Kubernetes itself.",
				Type:    module.Number,
				Default: strconv.Itoa(mailcore.TailleVolumeDefautGio),
			},
			{
				Key:     "quota_defaut_gio",
				Label:   "Default mailbox quota (GiB)",
				Help:    "Applied to each new mailbox. It cannot exceed the volume's size, or the first mailbox would not fit.",
				Type:    module.Number,
				Default: strconv.Itoa(mailcore.QuotaDefautGio),
			},
			{
				Key:   "clients_externes",
				Label: "Publish IMAP and SMTPS",
				Help: "`On` opens ports 465 and 993 to the outside, so a phone or Thunderbird can " +
					"reach the mailboxes. `Off` publishes only inbound mail (25) and the " +
					"administration interface (8080).",
				Type:    module.Bool,
				Default: "true",
			},
		},
	}}
}

// Current reads one group's values.
// The two cluster- and network-touching calls are variables, so that the
// decisions built on them — "a volume cannot shrink", "a relay send mode is only
// admissible once the relay answers" — can be exercised without a cluster and
// without a relay. Same seam as internal/modules/ingress.
var (
	tailleVolume       = mailcore.TailleVolume
	verifierRelaisSMTP = verifierRelais
)

// Current returns one group's values.
func (m *mailModule) Current(ctx context.Context, env module.Env, groupe string) (module.Values, error) {
	switch groupe {
	case groupeRelais:
		return m.currentRelais(ctx, env)
	case groupeServeur:
		return m.currentServeur(ctx, env)
	}
	return nil, fmt.Errorf("%w: %s", module.ErrUnknownGroup, groupe)
}

// currentRelais reads the relay group's values.
//
// THE VALUES COME FROM THE STORE, and the password answers the placeholder. An
// installation configured through the old flags has nothing stored: the fields
// then come back empty rather than guessing from the environment, because those
// flags are an INSTALLATION-time input and reading them at run time would make a
// page depend on a shell variable.
func (m *mailModule) currentRelais(ctx context.Context, env module.Env) (module.Values, error) {
	out := module.Values{
		"hote": "", "port": "587", "utilisateur": "",
		"mot_de_passe": "", "exiger_tls": "true",
	}

	// The ordinary values come from the common store.
	if env.Settings != nil {
		brut, err := env.Settings.Lire(ctx, "ceffio-system", "ceffio-settings", mailcore.CleRelais)
		if err != nil {
			return nil, err
		}
		if brut != "" {
			stoc := module.Values{}
			if err := jsonUnmarshal(brut, &stoc); err != nil {
				return nil, fmt.Errorf("mail: settings entry is not valid JSON: %w", err)
			}
			for k, v := range stoc {
				if k != "mot_de_passe" {
					out[k] = v
				}
			}
		}
	}

	// The password comes from the vault, and only its presence is reported.
	if _, err := lireRelais(ctx); err == nil {
		val, _ := secrets.LireEntreeCoffre(ctx, secrets.DepuisEnvironnement(),
			ComposantCoffre, SousCheminCoffre)
		if val["mot_de_passe"] != "" {
			out["mot_de_passe"] = module.SecretSet
		}
	}
	return out, nil
}

// currentServeur reads the server group's values.
//
// THE VOLUME SIZE IS READ FROM THE CLAIM WHEN NOTHING IS STORED, and that is
// not a detail: the deployment creates it at a default, and a page that showed
// 20 GiB over a 30 GiB claim would invite a save that Kubernetes must refuse.
// The claim is the truth about the size; the setting only asks for changes.
func (m *mailModule) currentServeur(ctx context.Context, env module.Env) (module.Values, error) {
	out := module.Values{
		"envoi":            mailcore.ModeDirect,
		"volume_gio":       strconv.Itoa(mailcore.TailleVolumeDefautGio),
		"quota_defaut_gio": strconv.Itoa(mailcore.QuotaDefautGio),
		"clients_externes": "true",
	}

	if env.Settings != nil {
		brut, err := env.Settings.Lire(ctx, "ceffio-system", "ceffio-settings", mailcore.CleServeur)
		if err != nil {
			return nil, err
		}
		if brut != "" {
			cfg, _, err := mailcore.LireServeur(brut)
			if err != nil {
				return nil, err
			}
			if cfg.Envoi.Mode != "" {
				out["envoi"] = cfg.Envoi.Mode
			}
			if cfg.VolumeGio > 0 {
				out["volume_gio"] = strconv.Itoa(cfg.VolumeGio)
			}
			if cfg.QuotaDefautGio > 0 {
				out["quota_defaut_gio"] = strconv.Itoa(cfg.QuotaDefautGio)
			}
			out["clients_externes"] = strconv.FormatBool(cfg.ClientsExternes)
		}
	}

	// The size in place wins over the default, but not over a stored request:
	// an operator who asked for 30 GiB must see 30, even before the claim grew.
	if taille, present, err := tailleVolume(ctx); err == nil && present {
		if demande, _ := strconv.Atoi(out["volume_gio"]); demande <= taille {
			out["volume_gio"] = strconv.Itoa(taille)
		}
	}
	return out, nil
}

// Apply validates, stores and applies one group.
//
// THE CREDENTIAL GOES TO THE VAULT, never to a ConfigMap: a password in a
// ConfigMap is readable by anyone who can read the namespace, and it would land
// in every backup in clear text.
func (m *mailModule) Apply(ctx context.Context, env module.Env, groupe string, v module.Values) error {
	switch groupe {
	case groupeRelais:
		return m.appliquerRelais(ctx, env, v)
	case groupeServeur:
		return m.appliquerServeur(ctx, env, v)
	}
	return fmt.Errorf("%w: %s", module.ErrUnknownGroup, groupe)
}

// appliquerRelais validates, stores and applies the relay group.
func (m *mailModule) appliquerRelais(ctx context.Context, env module.Env, v module.Values) error {
	g, _ := m.groupeDe(groupeRelais)
	if err := module.Validate(g, v); err != nil {
		return err
	}
	if err := m.stockerRelais(ctx, env, v); err != nil {
		return err
	}

	// THE SERVER IS RE-APPLIED (plan §4.2 rule 6): the new relay must reach
	// Stalwart's routing now, not at the next reinstall. A relay that is stored
	// but not applied would leave outbound mail on the old path, which is
	// exactly the bug this PR closes.
	return m.reappliquerServeur(ctx)
}

// stockerRelais writes the relay group's values without applying them.
func (m *mailModule) stockerRelais(ctx context.Context, env module.Env, v module.Values) error {
	// 1. The credential, in the vault. Merged, so an empty field keeps the
	//    stored one and a save that changes the port does not lose the password.
	if err := ecrireRelais(ctx, v); err != nil {
		return err
	}

	// 2. The ordinary values, in the common store.
	ordinaires := map[string]string{}
	for _, cle := range []string{"hote", "port", "utilisateur", "exiger_tls"} {
		ordinaires[cle] = strings.TrimSpace(v[cle])
	}
	if ordinaires["port"] == "" {
		ordinaires["port"] = "587"
	}
	if ordinaires["exiger_tls"] == "" {
		ordinaires["exiger_tls"] = "true"
	}
	if env.Settings != nil {
		poids, err := jsonMarshal(ordinaires)
		if err != nil {
			return err
		}
		if err := env.Settings.Ecrire(ctx, "ceffio-system", "ceffio-settings",
			map[string]string{mailcore.CleRelais: poids}); err != nil {
			return err
		}
	}
	return nil
}

// ConfigurerRelaisInstallation stores the relay given at installation time and
// switches outgoing mail to it.
//
// WHY THIS ENTRY POINT EXISTS: the installation still accepts --smtp-relais*,
// and those flags must end up in the SAME store as the page and as
// `ceffio module config` — otherwise an installation could hold a relay that no
// page shows and that a later save silently overwrites.
//
// THE PASSWORD IS READ FROM THE HISTORICAL LOCATIONS WHEN THE FLAG IS EMPTY,
// which keeps installations that never typed it working: it used to live in the
// vault's `smtp/relais` entry and in the Nextcloud SMTP Secret.
func (m *mailModule) ConfigurerRelaisInstallation(ctx context.Context, env module.Env, hote string, port int, utilisateur, motDePasse string) error {
	if port <= 0 {
		port = 587
	}
	coffre := secrets.DepuisEnvironnement()
	if utilisateur == "" {
		if v, err := secrets.LireOuSecret(ctx, coffre, "smtp", "relais",
			"username", "ceffio-files/nextcloud-smtp", "username"); err == nil {
			utilisateur = v
		}
	}
	if motDePasse == "" {
		if v, err := secrets.LireOuSecret(ctx, coffre, "smtp", "relais",
			"password", "ceffio-files/nextcloud-smtp", "password"); err == nil {
			motDePasse = v
		}
	}

	v := module.Values{
		"hote":         strings.TrimSpace(hote),
		"port":         strconv.Itoa(port),
		"utilisateur":  strings.TrimSpace(utilisateur),
		"mot_de_passe": motDePasse,
		"exiger_tls":   "true",
	}
	g, _ := m.groupeDe(groupeRelais)
	if err := module.Validate(g, v); err != nil {
		return fmt.Errorf("the relay given to the installation is incomplete: %w", err)
	}

	// CHECKED BEFORE STORED: a relay that refuses the connection at install
	// time will refuse it forever, and outbound mail would silently stay on the
	// direct path.
	ok, detail := verifierRelaisSMTP(v["hote"], port, v["utilisateur"], motDePasse)
	if !ok {
		return fmt.Errorf("the relay %s:%d refuses the connection: %s", v["hote"], port, detail)
	}

	if err := m.stockerRelais(ctx, env, v); err != nil {
		return err
	}
	if err := m.forcerModeEnvoi(ctx, env, mailcore.ModeRelais); err != nil {
		return err
	}
	fmt.Printf("  ∙ outgoing mail: through the relay %s:%d (stored in the mail settings)\n",
		v["hote"], port)

	// THE VALUES ARE STORED, NOT APPLIED, WHEN THE SERVER DOES NOT EXIST YET.
	// Since the mail server became an optional module, the installation writes
	// the relay BEFORE the optional phase — that is what lets mailcore.Deploy
	// read it — so there is no Deployment to re-apply to at this point. Applying
	// anyway would fail on a missing pod and abort an installation for a server
	// that is about to be deployed a few seconds later. Deploy applies the
	// stored values itself, and §4.2 rule 6 keeps them applied afterwards.
	if deploiementAbsent(ctx, env) {
		fmt.Println("  ∙ the mail server is not deployed yet: these values will be applied when it is")
		return nil
	}
	return m.reappliquerServeur(ctx)
}

// deploiementAbsent says whether the mail Deployment is KNOWN to be missing.
//
// WHY "KNOWN": a nil client cannot answer the question, and guessing "absent"
// would skip an application the caller expected. The default is therefore the
// historical behaviour (apply), and only a positive NotFound skips it.
func deploiementAbsent(ctx context.Context, env module.Env) bool {
	if env.Kube == nil {
		return false
	}
	_, err := env.Kube.AppsV1().Deployments(nsMail).Get(ctx, "stalwart", metav1.GetOptions{})
	return apierrors.IsNotFound(err)
}

// forcerModeEnvoi records the send mode WITHOUT touching the other server
// settings, so an installation that hands a relay does not overwrite a volume
// size or an exposure choice the operator made earlier.
func (m *mailModule) forcerModeEnvoi(ctx context.Context, env module.Env, mode string) error {
	if env.Settings == nil {
		return nil
	}
	brut, err := env.Settings.Lire(ctx, "ceffio-system", "ceffio-settings", mailcore.CleServeur)
	if err != nil {
		return err
	}
	cfg := mailcore.ReglagesParDefaut()
	if brut != "" {
		lu, _, err := mailcore.LireServeur(brut)
		if err != nil {
			return err
		}
		cfg = lu
	}
	cfg.Envoi.Mode = mode
	poids, err := cfg.JSON()
	if err != nil {
		return err
	}
	return env.Settings.Ecrire(ctx, "ceffio-system", "ceffio-settings",
		map[string]string{mailcore.CleServeur: poids})
}

// appliquerServeur validates, stores and applies the server group.
func (m *mailModule) appliquerServeur(ctx context.Context, env module.Env, v module.Values) error {
	g, _ := m.groupeDe(groupeServeur)
	if err := module.Validate(g, v); err != nil {
		return err
	}

	cfg, err := m.reglagesDe(ctx, env, v)
	if err != nil {
		return err
	}
	// A send mode that goes through the relay is only admissible if the relay
	// WORKS. This is the "its Test must pass" of the plan, checked at the moment
	// the value is saved rather than discovered when the first message bounces.
	if cfg.Envoi.Mode == mailcore.ModeRelais {
		ok, detail := verifierRelaisSMTP(cfg.Envoi.Hote, cfg.Envoi.Port,
			cfg.Envoi.Utilisateur, cfg.Envoi.MotDePasse)
		if !ok {
			return fmt.Errorf("%w: the relay refuses the connection (%s); fill the relay group "+
				"and run its Test first", module.ErrInvalidSettings, detail)
		}
	}
	if err := cfg.Valider(); err != nil {
		return fmt.Errorf("%w: %s", module.ErrInvalidSettings, err)
	}

	// STORED BEFORE APPLIED: if applying fails, the operator's values are kept
	// and only the effect is missing. The reverse order would lose the values
	// whenever the cluster was momentarily unavailable.
	brut, err := cfg.JSON()
	if err != nil {
		return err
	}
	if env.Settings != nil {
		if err := env.Settings.Ecrire(ctx, "ceffio-system", "ceffio-settings",
			map[string]string{mailcore.CleServeur: brut}); err != nil {
			return err
		}
	}

	return m.appliquerAuServeur(ctx, cfg)
}

// reappliquerServeur re-applies the STORED server configuration.
func (m *mailModule) reappliquerServeur(ctx context.Context) error {
	cfg, err := mailcore.LireReglages(ctx)
	if err != nil {
		return err
	}
	if err := cfg.Valider(); err != nil {
		return fmt.Errorf("%w: %s", module.ErrInvalidSettings, err)
	}
	return m.appliquerAuServeur(ctx, cfg)
}

// appliquerAuServeur makes the values effective, and says how to finish the job
// when this frontend cannot.
//
// WHY THIS IS NOT A SILENT SUCCESS: the console runs from a `scratch` image with
// no kubectl (build/console/Dockerfile), and it has no Stalwart administrative
// credential: it can store settings but not apply them. Reporting the failure
// while saying the values ARE stored is the honest answer — claiming success
// would leave outbound mail on the old route with a green page.
func (m *mailModule) appliquerAuServeur(ctx context.Context, cfg mailcore.Reglages) error {
	if err := mailcore.AppliquerServeur(ctx, cfg); err != nil {
		return fmt.Errorf("the values are stored, but applying them to the server failed: %w — "+
			"from a machine with kubectl, `ceffio mail deploy` applies them", err)
	}
	return nil
}

// reglagesDe builds the deployment configuration from a submitted server form.
func (m *mailModule) reglagesDe(ctx context.Context, env module.Env, v module.Values) (mailcore.Reglages, error) {
	cfg := mailcore.ReglagesParDefaut()
	if mode := strings.TrimSpace(v["envoi"]); mode != "" {
		cfg.Envoi.Mode = mode
	}
	if n, err := entier(v["volume_gio"]); err == nil {
		cfg.VolumeGio = n
	} else {
		return mailcore.Reglages{}, fmt.Errorf("%w: %s", module.ErrInvalidSettings, err)
	}
	if n, err := entier(v["quota_defaut_gio"]); err == nil {
		cfg.QuotaDefautGio = n
	} else {
		return mailcore.Reglages{}, fmt.Errorf("%w: %s", module.ErrInvalidSettings, err)
	}
	if b := strings.TrimSpace(v["clients_externes"]); b != "" {
		cfg.ClientsExternes = b == "true"
	}

	// Going through the relay takes its coordinates from the relay group, which
	// is the only place they are configured: duplicating them in this group
	// would create two sources for one credential.
	if cfg.Envoi.Mode == mailcore.ModeRelais {
		relais, err := m.relaisStocke(ctx, env)
		if err != nil {
			return mailcore.Reglages{}, err
		}
		cfg.Envoi = relais
		cfg.Envoi.Mode = mailcore.ModeRelais
	}
	return cfg, nil
}

// relaisStocke reads the stored relay, password included, as an Envoi.
func (m *mailModule) relaisStocke(ctx context.Context, env module.Env) (mailcore.Envoi, error) {
	e := mailcore.Envoi{Mode: mailcore.ModeRelais, Port: 587}
	if env.Settings != nil {
		brut, err := env.Settings.Lire(ctx, "ceffio-system", "ceffio-settings", mailcore.CleRelais)
		if err != nil {
			return e, err
		}
		r, err := mailcore.LireRelais(brut)
		if err != nil {
			return e, err
		}
		e.Hote, e.Port, e.Utilisateur = r.Hote, r.Port, r.Utilisateur
	}
	val, err := lireRelais(ctx)
	if err != nil {
		return e, err
	}
	e.MotDePasse = strings.TrimSpace(val["mot_de_passe"])
	return e, nil
}

// entier parses a whole-number field, naming the field in the error.
func entier(brut string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(brut))
	if err != nil {
		return 0, fmt.Errorf("%q is not a whole number", brut)
	}
	return n, nil
}

// Test verifies one group before saving.
func (m *mailModule) Test(ctx context.Context, env module.Env, groupe string, v module.Values) module.TestResult {
	switch groupe {
	case groupeRelais:
		return m.testerRelais(ctx, v)
	case groupeServeur:
		return m.testerServeur(ctx, env, v)
	}
	return module.TestResult{Detail: "unknown group: " + groupe}
}

// testerRelais verifies the relay accepts the connection and the credentials.
//
// IT REUSES THE SMTP CHECK the files module wrote, rather than a second
// implementation: the two check the same thing — a host, a port, a credential —
// and a second implementation would drift, with one of them accepting a
// configuration the other refuses. The check reaches the relay, and it is the
// same proof for both.
func (m *mailModule) testerRelais(ctx context.Context, v module.Values) module.TestResult {
	g, _ := m.groupeDe(groupeRelais)
	if err := module.Validate(g, v); err != nil {
		return module.TestResult{Detail: err.Error()}
	}

	// The password is not in the form when it is stored: read it back, so a
	// check on an existing configuration does not force a retype.
	mdp := strings.TrimSpace(v["mot_de_passe"])
	if mdp == "" || mdp == module.SecretSet {
		stocke, _ := lireRelais(ctx)
		mdp = stocke["mot_de_passe"]
	}

	port := 587
	if p := strings.TrimSpace(v["port"]); p != "" {
		fmt.Sscanf(p, "%d", &port)
	}

	etapes := []string{"checking the relay " + strings.TrimSpace(v["hote"])}
	ok, detail := verifierRelaisSMTP(strings.TrimSpace(v["hote"]), port,
		strings.TrimSpace(v["utilisateur"]), mdp)
	etapes = append(etapes, detail)

	r := module.TestResult{Steps: etapes, OK: ok, Detail: detail}
	if !ok {
		return r
	}
	r.Detail = "the relay accepted the connection and the credentials"
	return r
}

// testerServeur checks the server group: the values are coherent among
// themselves, the volume can actually be asked for, and a relay send mode is
// only OK if the relay answers.
func (m *mailModule) testerServeur(ctx context.Context, env module.Env, v module.Values) module.TestResult {
	g, _ := m.groupeDe(groupeServeur)
	if err := module.Validate(g, v); err != nil {
		return module.TestResult{Detail: err.Error()}
	}
	cfg, err := m.reglagesDe(ctx, env, v)
	if err != nil {
		return module.TestResult{Detail: err.Error()}
	}

	// COHERENCE FIRST, CLUSTER SECOND: a default quota larger than the volume it
	// is served from is wrong whatever the cluster holds, and answering it
	// without dialling keeps the check usable from a machine that cannot reach
	// the cluster (the console, typically).
	etapes := []string{"checking the default quota against the volume size"}
	if err := cfg.Valider(); err != nil {
		return module.TestResult{Steps: etapes, Detail: err.Error()}
	}
	etapes = append(etapes, fmt.Sprintf("the default quota is %d GiB for a %d GiB volume",
		cfg.QuotaDefautGio, cfg.VolumeGio))

	etapes = append(etapes, "checking the volume size against the claim in place")
	actuelle, present, err := tailleVolume(ctx)
	if err != nil {
		return module.TestResult{Steps: etapes, Detail: err.Error()}
	}
	if present {
		if cfg.VolumeGio > 0 && cfg.VolumeGio < actuelle {
			return module.TestResult{
				Steps: etapes,
				Detail: fmt.Sprintf("the volume in place is already %d GiB and Kubernetes cannot "+
					"shrink it: ask for %d GiB or more", actuelle, actuelle),
			}
		}
		etapes = append(etapes, fmt.Sprintf("the volume in place is %d GiB", actuelle))
	} else {
		etapes = append(etapes, "no volume yet: it will be created at the requested size")
	}

	if cfg.Envoi.Mode == mailcore.ModeRelais {
		etapes = append(etapes, "checking the outbound relay "+cfg.Envoi.Hote)
		ok, detail := verifierRelaisSMTP(cfg.Envoi.Hote, cfg.Envoi.Port,
			cfg.Envoi.Utilisateur, cfg.Envoi.MotDePasse)
		etapes = append(etapes, detail)
		if !ok {
			return module.TestResult{Steps: etapes, Detail: "the relay refuses the connection: " + detail}
		}
	}

	exposition := "IMAP and SMTPS are published (465, 993)"
	if !cfg.ClientsExternes {
		exposition = "only inbound mail and the administration interface are published (25, 8080)"
	}
	return module.TestResult{
		Steps:  etapes,
		OK:     true,
		Detail: "the settings are coherent and can be applied; " + exposition,
	}
}

// groupeDe returns the declared group with that ID.
func (m *mailModule) groupeDe(id string) (module.Group, bool) {
	for _, g := range m.Settings() {
		if g.ID == id {
			return g, true
		}
	}
	return module.Group{}, false
}

// --- Vault -----------------------------------------------------------------

func lireRelais(ctx context.Context) (map[string]string, error) {
	cfg := secrets.DepuisEnvironnement()
	if cfg == nil {
		return map[string]string{}, nil
	}
	val, err := secrets.LireEntreeCoffre(ctx, cfg, ComposantCoffre, SousCheminCoffre)
	if err != nil {
		if estAbsent(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	return val, nil
}

func ecrireRelais(ctx context.Context, v module.Values) error {
	mdp := strings.TrimSpace(v["mot_de_passe"])
	if mdp == "" || mdp == module.SecretSet {
		return nil
	}
	cfg := secrets.DepuisEnvironnement()
	if cfg == nil {
		return fmt.Errorf("mail: no vault configured: the relay password must be stored in OpenBao, " +
			"never in a ConfigMap, where anyone able to read the namespace could read it")
	}
	existants, err := secrets.LireEntreeCoffre(ctx, cfg, ComposantCoffre, SousCheminCoffre)
	if err != nil && !estAbsent(err) {
		return err
	}
	if existants == nil {
		existants = map[string]string{}
	}
	existants["mot_de_passe"] = mdp
	if u := strings.TrimSpace(v["utilisateur"]); u != "" {
		existants["utilisateur"] = u
	}
	if h := strings.TrimSpace(v["hote"]); h != "" {
		existants["hote"] = h
	}
	return secrets.EcrireDansCoffre(ctx, cfg, ComposantCoffre, SousCheminCoffre, existants)
}

func estAbsent(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "404") || strings.Contains(s, "absent") || strings.Contains(s, "not found")
}
