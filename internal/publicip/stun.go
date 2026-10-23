// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package publicip

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"time"
)

// Minimal STUN client (RFC 5389): one Binding Request, one response, the
// XOR-MAPPED-ADDRESS it carries.
//
// WHY NOT A LIBRARY: the discovery is a single request/response, and the
// project's dependency set is deliberately small (go.mod: cobra, client-go,
// yaml). A binding is a hundred lines; a library would add a module, its
// transitive tree and its release cadence for one packet.
//
// WHY NOT `turnutils_stunclient`, which coturn's image already carries: the
// reporter runs FROM scratch, with no shell and no coturn tools. Doing it in
// Go also lets us FORCE IPv4 — the measured Janus failure where a dual-stack
// name resolves to IPv6 and Janus announces an address no IPv4 browser can
// reach.

const (
	stunBindingRequest = 0x0001
	stunBindingSuccess = 0x0101
	stunMagicCookie    = 0x2112A442

	// MAPPED-ADDRESS, the pre-RFC 5389 attribute: kept as a fallback for the
	// rare server that answers with it only.
	stunAttrMapped = 0x0001
	// XOR-MAPPED-ADDRESS: the address the server saw, XORed with the magic
	// cookie so that a NAT rewriting the payload in flight cannot make the
	// client believe an address that is not its own.
	stunAttrXORMapped = 0x0020
)

// stunLookup asks serveur ("host:port") for the public address it sees.
//
// The socket is dialled over udp4 on purpose: requesting the IPv4 mapping
// keeps the answer comparable with what Janus and coturn announce, and with
// the A record an operator publishes.
func stunLookup(ctx context.Context, serveur string) (string, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "udp4", serveur)
	if err != nil {
		return "", fmt.Errorf("stun: dial %s: %w", serveur, err)
	}
	defer conn.Close()

	// The caller's deadline wins; a local one keeps a silent server from
	// hanging the reporter for its whole refresh interval.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	}

	var tx [12]byte
	if _, err := rand.Read(tx[:]); err != nil {
		return "", fmt.Errorf("stun: transaction id: %w", err)
	}

	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(req[2:4], 0) // no attribute
	binary.BigEndian.PutUint32(req[4:8], stunMagicCookie)
	copy(req[8:20], tx[:])

	if _, err := conn.Write(req); err != nil {
		return "", fmt.Errorf("stun: write: %w", err)
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("stun: read: %w", err)
	}
	return analyserReponse(buf[:n], tx)
}

// analyserReponse extracts the mapped address from a Binding Success
// response. It rejects anything that is not an answer to OUR request: a
// response off the network with the wrong transaction id is not evidence of
// our public address.
func analyserReponse(p []byte, tx [12]byte) (string, error) {
	if len(p) < 20 {
		return "", fmt.Errorf("stun: response too short (%d bytes)", len(p))
	}
	if t := binary.BigEndian.Uint16(p[0:2]); t != stunBindingSuccess {
		return "", fmt.Errorf("stun: unexpected message type 0x%04x", t)
	}
	if binary.BigEndian.Uint32(p[4:8]) != stunMagicCookie {
		return "", fmt.Errorf("stun: bad magic cookie")
	}
	if !bytes.Equal(p[8:20], tx[:]) {
		return "", fmt.Errorf("stun: transaction id mismatch")
	}

	// The header length excludes the header itself; a truncated datagram is
	// clamped rather than trusted, and every attribute is bounds-checked
	// below anyway.
	longueur := int(binary.BigEndian.Uint16(p[2:4]))
	if 20+longueur > len(p) {
		longueur = len(p) - 20
	}

	var mapped string
	for off := 20; off+4 <= 20+longueur; {
		atype := binary.BigEndian.Uint16(p[off : off+2])
		alen := int(binary.BigEndian.Uint16(p[off+2 : off+4]))
		valeur := p[off+4:]
		if alen > len(valeur) {
			break
		}
		valeur = valeur[:alen]

		switch atype {
		case stunAttrXORMapped:
			if ip, ok := adresseXOR(valeur); ok {
				mapped = ip
			}
		case stunAttrMapped:
			if ip, ok := adresseSimple(valeur); ok && mapped == "" {
				mapped = ip
			}
		}
		off += 4 + alen + (4-alen%4)%4
	}
	if mapped == "" {
		return "", fmt.Errorf("stun: no mapped address in the response")
	}
	return mapped, nil
}

// adresseXOR decodes XOR-MAPPED-ADDRESS. IPv6 is deliberately not decoded:
// the socket is udp4, and returning a v6 address here would contradict the
// IPv4-only guarantee this client exists to provide.
func adresseXOR(v []byte) (string, bool) {
	if len(v) < 8 || v[1] != 0x01 {
		return "", false
	}
	ip := make(net.IP, 4)
	cookie := make([]byte, 4)
	binary.BigEndian.PutUint32(cookie, stunMagicCookie)
	for i := 0; i < 4; i++ {
		ip[i] = v[4+i] ^ cookie[i]
	}
	return ip.String(), true
}

// adresseSimple decodes MAPPED-ADDRESS (no XOR).
func adresseSimple(v []byte) (string, bool) {
	if len(v) < 8 || v[1] != 0x01 {
		return "", false
	}
	return net.IP(v[4:8]).String(), true
}

// portDe is the port carried by a mapped-address attribute, for the log
// line: it tells an operator which source port the NAT translated, which is
// the first thing to check when media flows one way only.
func portDe(v []byte) string {
	if len(v) < 4 {
		return ""
	}
	return strconv.Itoa(int(binary.BigEndian.Uint16(v[2:4])))
}
