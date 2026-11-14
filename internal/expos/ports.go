// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package expos

// WHY THIS IS A SEPARATE AND FORGIVING PATH. The os-caddy publication above
// talks to a plugin whose endpoints this tool has used for long enough to
// trust them. The NAT port-forward endpoints are not in the same situation:
// the plugin that exposes them differs between OPNsense versions, its payload
// shape is not documented in a way we can pin, and this workspace has no
// reachable firewall to try it on.
//
// So the VERIFIABLE CONTRACT IS THE PRINTED RULE, not the API call. An
// operator can always create a port forward by hand in the firewall UI, and
// the inbound-25 check of the mail module tells the truth afterwards
// (`ceffio module check mail`). The API attempt is a best effort that removes
// typing when it works; any doubt (transport error, an HTML answer, a body
// without a uuid) falls back to the rules instead of pretending success. A
// tool that printed "port 25 forwarded" while the firewall dropped the request
// would be worse than no tool at all: the operator would look for the fault in
// Stalwart while the mail never leaves the sender's queue.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Endpoints of the OPNsense NAT port-forward plugin, used ONLY by
// PublierPorts.
//
// UNVERIFIED ON THE OPERATOR'S API VERSION: these three paths are our best
// reading of the firewall plugin, not something this repository has exercised
// against a real appliance. They are gathered in one place for that reason: the
// day an operator reports the fallback firing although the API works, there is
// one line to correct, and every caller already prints the manual rules while
// it is wrong. Keep them as paths relative to /api/, like the caddy endpoints
// in opnsense.go.
const (
	// cheminNATRecherche lists the existing port forwards, so that a second
	// run does not create duplicates.
	cheminNATRecherche = "firewall_nat/port_forward/searchRule"
	// cheminNATAjout creates one port forward.
	cheminNATAjout = "firewall_nat/port_forward/addRule"
	// cheminNATApplique reloads the running firewall. Chosen over
	// `firewall_nat/apply` because this firewall's plugins expose their reload
	// as `<module>/service/reconfigure` (see caddy/service/reconfigure in
	// opnsense.go), and a plugin that diverges from that convention would have
	// diverged on the search path too.
	cheminNATApplique = "firewall_nat/service/reconfigure"
	// champNAT: the MVC endpoints of the firewall receive the record under the
	// controller's model name, "rule" for a port-forward controller. UNVERIFIED
	// like the paths: if a version expects another key it answers 4xx or with
	// an empty body, the add is not confirmed, and the caller prints the rules.
	champNAT = "rule"
)

// ReglesManuelles returns the exact firewall rules an operator must create by
// hand for the given ports, one string per rule, in the order the UI shows
// them: the NAT rule first, then the filter rule it needs.
//
// The strings are a contract: they are locked by a test because an operator
// acting on a vague instruction ("open port 25") ends up with a firewall that
// accepts SMTP on the wrong interface, or a NAT rule with no pass rule that
// redirects the packet into the void.
//
// Interface naming: the UI and pf print the interface GROUP (`WAN`), while the
// API takes the interface identifier (`wan`). These rules are meant to be read
// and typed in the UI, so they keep the spelling the operator sees there; the
// payload built by chargeRedirection uses the identifier.
func ReglesManuelles(ipInterne string, ports []int) []string {
	var regles []string
	for _, port := range PortsValides(ports) {
		regles = append(regles,
			// Firewall > NAT > Port Forward: external port on the WAN group,
			// redirected to the same port of the node.
			fmt.Sprintf("WAN TCP * -> %s:%d", ipInterne, port),
			// The matching pass rule, the firewall's "associated rule": the NAT
			// alone only rewrites the header, the filter would still drop the
			// packet.
			fmt.Sprintf("pass in on WAN inet proto tcp from any to %s port %d keep state", ipInterne, port))
	}
	return regles
}

// PublierPorts creates the TCP port forwards that let inbound L4 traffic reach
// IPInterne, and never makes the publication fail.
//
// Contract: every port the firewall did not CONFIRM (a uuid, or a result field
// in its answer) comes back in Resultat.ReglesManuelles with the reason in
// Resultat.Avertissemts, and the caller prints them. An error return would let
// a caller stop before printing the rules, which is exactly the failure mode
// this path exists to avoid, so err is always nil here; the signature keeps it
// for symmetry with Publier and for a future caller that needs one.
//
// A port already forwarded to IPInterne is not created twice: idempotence is
// why the search happens first, and a search we cannot read is not a reason to
// create blindly (a second forward on the same WAN port is a conflicting
// ruleset), it is a reason to print the rules.
func PublierPorts(ctx context.Context, cfg Config, ports []int, progress func(string)) (*Resultat, error) {
	if progress == nil {
		progress = func(string) {}
	}
	res := &Resultat{}
	valides := PortsValides(ports)
	if len(valides) == 0 {
		// No credential read, no HTTP call: a configuration without ports must
		// leave today's behaviour untouched.
		return res, nil
	}

	cli, err := newClient(cfg)
	if err != nil {
		res.Avertissemts = append(res.Avertissemts,
			fmt.Sprintf("firewall API unusable (%v): create the port forwards by hand", err))
		res.ReglesManuelles = ReglesManuelles(cfg.IPInterne, valides)
		return res, nil
	}

	progress("searching the existing port forwards")
	existants, err := redirectionsExistantes(ctx, cli, cfg.IPInterne)
	if err != nil {
		res.Avertissemts = append(res.Avertissemts,
			fmt.Sprintf("reading the existing port forwards failed (%v): create them by hand", err))
		res.ReglesManuelles = ReglesManuelles(cfg.IPInterne, valides)
		return res, nil
	}

	var aCreer []int
	for _, port := range valides {
		if existants[port] {
			res.PortsExistants = append(res.PortsExistants, port)
			continue
		}
		aCreer = append(aCreer, port)
	}

	// The failures are independent: a port the firewall refuses does not
	// prevent the next one from being created.
	var nonConfirmes []int
	var crees []int
	for _, port := range aCreer {
		progress(fmt.Sprintf("creating the port forward %d", port))
		out, err := cli.appel(ctx, cheminNATAjout, "POST", chargeRedirection(cfg.IPInterne, port))
		if err == nil && !confirme(out) {
			// 200 OK is not an answer: some versions and reverse proxies
			// return an HTML page with a 200, and the legacy endpoints answer
			// `{"result":"saved"}` rather than a uuid. Only a field the
			// firewall filled proves the rule exists.
			err = fmt.Errorf("answer without uuid: %s", tronque(out))
		}
		if err != nil {
			res.Avertissemts = append(res.Avertissemts,
				fmt.Sprintf("port %d not created by the firewall API (%v)", port, err))
			nonConfirmes = append(nonConfirmes, port)
			continue
		}
		crees = append(crees, port)
	}

	// Without an apply the rules are saved but not loaded, which is the worst
	// state: the UI shows them, the ports stay closed. An apply that fails
	// leaves every rule created just before it unconfirmed.
	if len(crees) > 0 {
		progress("applying the firewall configuration")
		out, err := cli.appel(ctx, cheminNATApplique, "POST", nil)
		if err == nil && !jsonValide(out) {
			err = fmt.Errorf("answer unreadable: %s", tronque(out))
		}
		if err != nil {
			res.Avertissemts = append(res.Avertissemts,
				fmt.Sprintf("applying the firewall configuration failed (%v): the rules exist but are not active", err))
			nonConfirmes = append(nonConfirmes, crees...)
			crees = nil
		}
	}

	// What the firewall confirmed, existing or created, in one ascending list:
	// the CLI prints it as the ports it does not have to mention again.
	res.PortsOuverts = append(res.PortsOuverts, res.PortsExistants...)
	res.PortsOuverts = append(res.PortsOuverts, crees...)
	sort.Ints(res.PortsOuverts)
	if len(nonConfirmes) > 0 {
		sort.Ints(nonConfirmes)
		res.ReglesManuelles = ReglesManuelles(cfg.IPInterne, nonConfirmes)
	}
	return res, nil
}

// redirectionsExistantes returns the WAN/TCP destination ports already
// forwarded to ipInterne.
//
// The answer is read permissively, row by row, because the firewall renders
// booleans and numbers as strings ("0"/"1") on some versions and as JSON
// values on others: a strict struct would fail the whole read on the first
// mismatch and send every installation to the manual path for a detail of
// encoding, when the manual path is supposed to cover real failures.
func redirectionsExistantes(ctx context.Context, cli *client, ipInterne string) (map[int]bool, error) {
	out, err := cli.appel(ctx, cheminNATRecherche, "GET", nil)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Rows []map[string]any `json:"rows"`
	}
	if json.Unmarshal([]byte(out), &doc) != nil {
		return nil, fmt.Errorf("non-JSON answer: %s", tronque(out))
	}
	existants := make(map[int]bool, len(doc.Rows))
	for _, row := range doc.Rows {
		if valeur(row, "disabled") {
			// A disabled rule opens nothing: it must not stop the creation.
			continue
		}
		if iface := texte(row, "interface"); iface != "" && !strings.EqualFold(iface, "wan") {
			continue
		}
		if proto := texte(row, "protocol", "proto"); proto != "" && !strings.EqualFold(proto, "tcp") {
			continue
		}
		port, err := strconv.Atoi(texte(row, "dstport", "destination_port", "local-port", "local_port"))
		if err != nil {
			continue
		}
		// A forward to another target does not answer for this node: it is not
		// counted as existing, the add is attempted, and a refusal ends in the
		// manual rules like any other failure.
		if cible := texte(row, "target", "local-ip", "local_ip"); cible != ipInterne {
			continue
		}
		existants[port] = true
	}
	return existants, nil
}

// chargeRedirection builds the body of one port-forward creation.
//
// Field names follow the legacy NAT form the plugin keeps (dstport,
// local-port, target, descr): the search answer uses the same vocabulary, so a
// single reading of the plugin covers both directions.
func chargeRedirection(ipInterne string, port int) map[string]any {
	return map[string]any{
		champNAT: map[string]any{
			"enabled":    "1",
			"interface":  "wan", // API identifier; the UI prints "WAN"
			"ipprotocol": "inet",
			"protocol":   "tcp",
			"dstport":    strconv.Itoa(port),
			"target":     ipInterne,
			"local-port": strconv.Itoa(port),
			"descr":      fmt.Sprintf("Ceffio - %d", port),
			// Ask the firewall to create the matching pass rule: without it
			// the NAT rule redirects a packet the filter still drops.
			// UNVERIFIED: a version ignoring this key creates the NAT rule
			// without its filter rule, and this code cannot tell — the port
			// stays closed until the operator runs the inbound-25 check, which
			// is the only proof this path claims.
			"associated-rule-id": "add",
		},
	}
}

// confirme reports whether an add answer carries the proof that the firewall
// accepted the rule: a uuid, or a result field on the versions that answer
// "saved". An empty body, an HTML error page or a bare {} is not a success.
func confirme(out string) bool {
	var reponse struct {
		UUID   string `json:"uuid"`
		Result string `json:"result"`
	}
	if json.Unmarshal([]byte(out), &reponse) != nil {
		return false
	}
	return reponse.UUID != "" || reponse.Result != ""
}

// jsonValide reports whether a body is an empty body or a JSON document.
// The apply endpoint has nothing to confirm (no uuid), so the best we can do
// is reject an answer we cannot read at all, typically an HTML page served with
// a 200 by a proxy.
func jsonValide(out string) bool {
	corps := strings.TrimSpace(out)
	return corps == "" || json.Valid([]byte(corps))
}

// PortsValides filters what cannot be a port and returns the rest in ascending
// order without duplicates.
//
// Filtering instead of failing: the list may come from Config.Ports, written
// by hand, and one bad entry must not discard the good ones; a port of 0 or
// 70000 would produce a rule that matches nothing. The CLI rejects bad input
// explicitly before this point, so this is the guard for the configuration-file
// path.
func PortsValides(ports []int) []int {
	vus := make(map[int]bool, len(ports))
	var valides []int
	for _, port := range ports {
		if port < 1 || port > 65535 || vus[port] {
			continue
		}
		vus[port] = true
		valides = append(valides, port)
	}
	sort.Ints(valides)
	return valides
}

// texte returns the first non-empty representation of a field, whatever
// encoding the plugin used (string, number, boolean). Names are tried in order
// so that a version renaming a field still gets read.
func texte(row map[string]any, noms ...string) string {
	for _, nom := range noms {
		switch v := row[nom].(type) {
		case string:
			if v != "" {
				return v
			}
		case float64:
			return strconv.Itoa(int(v))
		case bool:
			if v {
				return "1"
			}
		}
	}
	return ""
}

// valeur reports whether a flag-like field is set, accepting "1", 1 and true:
// the firewall writes each of them depending on the version.
func valeur(row map[string]any, noms ...string) bool {
	return texte(row, noms...) == "1"
}
