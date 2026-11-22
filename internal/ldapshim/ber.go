// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package ldapshim answers the ONE LDAP search OpenProject makes before it
// signs a user in through a header.
//
// WHY THIS EXISTS AT ALL. OpenProject's header single sign-on trusts a reverse
// proxy for the login name, but it still RESOLVES that name through an LDAP
// directory: `ApplicationController#perform_header_sso` calls
// `LdapAuthSource.find_user(login)` (app/controllers/concerns/auth_source_sso.rb
// in 17.9.8), and that lookup is the only path — `find_user_from_auth_source` is
// never reached in that mode. With no directory behind the source OpenProject is
// configured with, every sign-in ends in `auth_source_sso_failed`, and the log
// names a TCP connection:
//
//	Error during authentication: Connection refused - connect(2) for 127.0.0.1:389
//
// MEASURED on the acceptance run of 2026-11-21: an account provisioned by the
// module (active, administrator, linked to the source) could not sign in at all.
//
// WHAT IT IS NOT. It authenticates NOBODY: it checks no password, holds no
// directory, stores nothing, and builds every answer from the query itself. The
// password was already verified by the identity provider, and the authorization
// decision stays where it belongs — in OpenProject's own database, since the
// lookup only leads anywhere for a user row bound to the source (`mapped_user`,
// with `onthefly_register` off).
//
// WHY A RESPONDER RATHER THAN A DIRECTORY: a real directory (lldap, OpenLDAP)
// would add a second source of accounts to back up, keep in sync and protect.
// The alternative — patching the vendor image with a Rails initializer — is a
// fork of OpenProject disguised as a deployment. A read-only answer to a lookup
// costs a few hundred lines and no state.
package ldapshim

import (
	"bufio"
	"errors"
	"fmt"
	"io"
)

// LDAP tags, RFC 4511 §4. Every request and every response is one of them.
const (
	tagBoolean     = 0x01
	tagInteger     = 0x02
	tagOctetString = 0x04
	tagEnumerated  = 0x0a
	tagSequence    = 0x30
	tagSet         = 0x31

	appBind             = 0x60 // BindRequest
	appBindResponse     = 0x61 // BindResponse
	appUnbind           = 0x42 // UnbindRequest
	appSearch           = 0x63 // SearchRequest
	appSearchEntry      = 0x64 // SearchResultEntry
	appSearchDone       = 0x65 // SearchResultDone
	appAbandon          = 0x50 // AbandonRequest
	appExtended         = 0x77 // ExtendedRequest
	appExtendedResponse = 0x78 // ExtendedResponse
)

// filterEqualityMatch is [3] SEQUENCE { attributeDesc, assertionValue }.
const filterEqualityMatch = 0xa3

// Result codes, RFC 4511 §4.1.9 — only the three this server can return.
const (
	resultSuccess            = 0
	resultProtocolError      = 2
	resultInvalidCredentials = 49
)

// tlv is one BER element: its tag and its RAW content octets.
type tlv struct {
	tag     byte
	content []byte
}

// constructed reports whether the element has children, per the BER
// constructed bit.
func (t tlv) constructed() bool { return t.tag&0x20 != 0 }

// children decodes the children of a constructed element.
func (t tlv) children() ([]tlv, error) {
	if !t.constructed() {
		return nil, fmt.Errorf("ldap: tag 0x%02x is not constructed", t.tag)
	}
	return splitElements(t.content)
}

// splitElements decodes a run of elements that fills buf exactly.
func splitElements(buf []byte) ([]tlv, error) {
	var elements []tlv
	for len(buf) > 0 {
		element, rest, err := readTLV(buf)
		if err != nil {
			return nil, err
		}
		elements = append(elements, element)
		buf = rest
	}
	return elements, nil
}

// readTLV decodes one element from buf and returns the rest.
//
// DEFENSIVE ON PURPOSE: a length is peer-chosen input, up to three bytes of it.
// A length larger than what is left is refused rather than allocated, and the
// indefinite form (0x80) is refused because LDAP forbids it. Non-minimal forms
// are refused too: no encoder emits them, and accepting two spellings of the
// same frame is how parsers drift apart.
func readTLV(buf []byte) (tlv, []byte, error) {
	if len(buf) < 2 {
		return tlv{}, nil, errors.New("ldap: truncated element")
	}
	tag := buf[0]
	if tag == 0 || tag == 0xff {
		return tlv{}, nil, fmt.Errorf("ldap: reserved tag 0x%02x", tag)
	}
	first := buf[1]
	if first < 0x80 { // short form
		if int(first) > len(buf)-2 {
			return tlv{}, nil, errors.New("ldap: length exceeds the message")
		}
		return tlv{tag: tag, content: buf[2 : 2+int(first)]}, buf[2+int(first):], nil
	}
	if first == 0x80 {
		return tlv{}, nil, errors.New("ldap: indefinite length is forbidden")
	}
	count := int(first & 0x7f)
	if count > 3 {
		return tlv{}, nil, fmt.Errorf("ldap: length in %d octets is out of range", count)
	}
	if len(buf) < 2+count {
		return tlv{}, nil, errors.New("ldap: truncated length")
	}
	length := 0
	for i := 0; i < count; i++ {
		length = length<<8 | int(buf[2+i])
	}
	if length < 0x80 || length > len(buf)-2-count {
		return tlv{}, nil, errors.New("ldap: length is not minimal or exceeds the message")
	}
	start := 2 + count
	return tlv{tag: tag, content: buf[start : start+length]}, buf[start+length:], nil
}

// readMessage reads one complete LDAPMessage from the stream.
//
// THE LIMIT APPLIES TO THE FRAME, BEFORE THE CONTENT IS READ: an announced
// length is the only thing a peer controls before a byte of content arrives, so
// it is what the limit must bound. Nothing legitimate comes close — the largest
// request OpenProject sends is a search of a few dozen octets.
func readMessage(br *bufio.Reader, maximum int) (tlv, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(br, header); err != nil {
		return tlv{}, err
	}
	if header[1]&0x80 == 0 { // short form
		if int(header[1]) > maximum {
			return tlv{}, fmt.Errorf("ldap: message of %d octets exceeds the %d limit", header[1], maximum)
		}
		return readBody(br, header[0], int(header[1]))
	}
	count := int(header[1] & 0x7f)
	if count == 0 || count > 3 {
		return tlv{}, errors.New("ldap: unsupported length form")
	}
	lengthOctets := make([]byte, count)
	if _, err := io.ReadFull(br, lengthOctets); err != nil {
		return tlv{}, err
	}
	length := 0
	for _, octet := range lengthOctets {
		length = length<<8 | int(octet)
	}
	if length > maximum {
		return tlv{}, fmt.Errorf("ldap: message of %d octets exceeds the %d limit", length, maximum)
	}
	return readBody(br, header[0], length)
}

func readBody(br *bufio.Reader, tag byte, length int) (tlv, error) {
	content := make([]byte, length)
	if _, err := io.ReadFull(br, content); err != nil {
		return tlv{}, err
	}
	return tlv{tag: tag, content: content}, nil
}

// encoder builds BER, in the order the fields appear in RFC 4511.
type encoder struct{ bytes []byte }

func (e *encoder) tlv(tag byte, content []byte) {
	e.bytes = append(e.bytes, tag)
	switch {
	case len(content) < 0x80:
		e.bytes = append(e.bytes, byte(len(content)))
	case len(content) <= 0xff:
		e.bytes = append(e.bytes, 0x81, byte(len(content)))
	default:
		e.bytes = append(e.bytes, 0x82, byte(len(content)>>8), byte(len(content)))
	}
	e.bytes = append(e.bytes, content...)
}

// integer writes an INTEGER or an ENUMERATED, minimal, never negative.
func (e *encoder) integer(tag byte, value int) {
	var content []byte
	for {
		content = append([]byte{byte(value & 0xff)}, content...)
		value >>= 8
		if value == 0 {
			break
		}
	}
	// A positive value whose first octet has the high bit set needs a leading
	// zero, or it reads as negative.
	if content[0]&0x80 != 0 {
		content = append([]byte{0}, content...)
	}
	e.tlv(tag, content)
}

func (e *encoder) messageID(id int)    { e.integer(tagInteger, id) }
func (e *encoder) resultCode(code int) { e.integer(tagEnumerated, code) }
func (e *encoder) str(s string)        { e.tlv(tagOctetString, []byte(s)) }

// sequenceOf wraps content in a SEQUENCE.
func sequenceOf(content []byte) []byte {
	var e encoder
	e.tlv(tagSequence, content)
	return e.bytes
}
