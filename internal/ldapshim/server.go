// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package ldapshim

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Options are the server's limits. The zero value is usable: withDefaults fills
// every field, so a caller cannot forget one and get an unbounded server.
type Options struct {
	// Attribute is the attribute an equality filter must name for its value to
	// be taken as a login. OpenProject's source is configured with uid.
	Attribute string

	// MaxMessage is the largest LDAPMessage accepted, in octets.
	MaxMessage int

	// Timeout bounds BOTH the wait for the next message on a connection and the
	// time allowed to answer it. An idle connection holding a goroutine is the
	// cheapest way to exhaust a small pod.
	Timeout time.Duration

	// MaxConnections is the number of connections served at once. Beyond it a
	// connection is closed immediately: queueing would move the exhaustion from
	// memory to the accept backlog.
	MaxConnections int

	// Log receives one line per answered lookup. It is the only place an
	// operator can see the lookup chain, and it carries nothing but the login
	// the request already carried.
	Log io.Writer
}

// Defaults, all far above what OpenProject needs: one search per sign-in, a
// message of a few dozen octets.
const (
	defaultAttribute      = "uid"
	defaultMaxMessage     = 64 << 10
	defaultTimeout        = 30 * time.Second
	defaultMaxConnections = 32
)

func (o Options) withDefaults() Options {
	if o.Attribute == "" {
		o.Attribute = defaultAttribute
	}
	if o.MaxMessage <= 0 {
		o.MaxMessage = defaultMaxMessage
	}
	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}
	if o.MaxConnections <= 0 {
		o.MaxConnections = defaultMaxConnections
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
	return o
}

// Serve serves connections on l until ctx is cancelled. It returns nil after a
// clean shutdown, and the accept error otherwise.
//
// SHUTDOWN CLOSES THE LISTENER AND WAITS: a pod that terminates without draining
// turns its in-flight lookups into connection resets inside a sign-in, which
// reads as a broken single sign-on rather than as a restart.
func Serve(ctx context.Context, l net.Listener, opt Options) error {
	opt = opt.withDefaults()
	sem := make(chan struct{}, opt.MaxConnections)
	var wg sync.WaitGroup
	defer wg.Wait()

	// CLOSING THE LISTENER ON CANCELLATION IS WHAT UNBLOCKS Accept. The
	// goroutine is bounded by the same channel: once Accept returns, it is done.
	closed := make(chan struct{})
	defer close(closed)
	go func() {
		select {
		case <-ctx.Done():
			l.Close()
		case <-closed:
		}
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("ldap: accept: %w", err)
		}
		select {
		case sem <- struct{}{}:
		default:
			fmt.Fprintln(opt.Log, "ldap: refusing a connection: too many open at once")
			conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			serveConn(ctx, conn, opt)
		}()
	}
}

// serveConn handles one client: read a message, answer it, repeat until the
// client unbinds or the connection fails.
func serveConn(ctx context.Context, conn net.Conn, opt Options) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)

	for {
		if ctx.Err() != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(opt.Timeout))
		msg, err := readMessage(br, opt.MaxMessage)
		if err != nil {
			// A client that hangs up is not an incident: it is what closing a
			// page looks like from here.
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				fmt.Fprintf(opt.Log, "ldap: reading a message: %v\n", err)
			}
			return
		}
		_ = conn.SetWriteDeadline(time.Now().Add(opt.Timeout))
		keepGoing, err := handle(msg, bw, opt)
		if err != nil {
			fmt.Fprintf(opt.Log, "ldap: answering: %v\n", err)
			return
		}
		if err := bw.Flush(); err != nil {
			return
		}
		if !keepGoing {
			return
		}
	}
}

// handle answers one LDAPMessage. The boolean says whether the connection goes
// on.
func handle(msg tlv, bw *bufio.Writer, opt Options) (bool, error) {
	fields, err := msg.children()
	if err != nil {
		return false, err
	}
	if len(fields) < 2 {
		return false, errors.New("ldap: message without a protocol operation")
	}
	id, err := integerValue(fields[0])
	if err != nil {
		return false, err
	}
	operation := fields[1]

	switch operation.tag {
	case appBind:
		return true, handleBind(id, operation, bw)

	case appSearch:
		return true, handleSearch(id, operation, bw, opt)

	case appUnbind:
		// No response is defined for UnbindRequest, RFC 4511 §4.3.
		return false, nil

	case appAbandon:
		// Nothing is ever in flight here — every answer is immediate — so an
		// abandon has nothing to cancel.
		return true, nil

	case appExtended:
		// StartTLS and the like. The responder is plaintext on a
		// cluster-internal Service; refusing the extension says so once instead
		// of failing later inside a handshake.
		return true, write(bw, extendedResponse(id, resultProtocolError,
			"extensions are not supported by this read-only lookup responder"))

	default:
		return false, fmt.Errorf("ldap: unsupported request tag 0x%02x", operation.tag)
	}
}

// handleBind answers a bind.
//
// ANONYMOUS ONLY. OpenProject binds anonymously when the source has no account
// (the module configures none, so that the responder holds no credential), and a
// simple bind carrying a name or a password is answered with
// invalidCredentials: accepting a password it cannot check would be a claim the
// responder has no business making.
func handleBind(id int, bind tlv, bw *bufio.Writer) error {
	fields, err := bind.children()
	if err != nil || len(fields) != 3 {
		return write(bw, bindResponse(id, resultProtocolError, "malformed bind request"))
	}
	name := ""
	if fields[1].tag == tagOctetString {
		name = string(fields[1].content)
	}
	// authentication: [0] simple (an OCTET STRING) or [3] sasl (a SEQUENCE).
	hasSecret := true
	if fields[2].tag == 0x80 {
		hasSecret = len(fields[2].content) != 0
	}
	if name == "" && !hasSecret {
		return write(bw, bindResponse(id, resultSuccess, ""))
	}
	return write(bw, bindResponse(id, resultInvalidCredentials,
		"this responder answers anonymous binds only: credentials are verified by the identity provider"))
}

// handleSearch answers a search with at most one entry.
func handleSearch(id int, search tlv, bw *bufio.Writer, opt Options) error {
	fields, err := search.children()
	if err != nil || len(fields) < 7 {
		return write(bw, doneResponse(id, resultProtocolError, "malformed search request"))
	}
	base := ""
	if fields[0].tag == tagOctetString {
		base = string(fields[0].content)
	}
	login, ok := loginFromFilter(fields[6], opt.Attribute)
	if !ok || !validLogin(login) {
		// NO ENTRY, SUCCESS: the query was well formed, the answer is that
		// nobody matches. OpenProject turns that into a refused sign-in.
		fmt.Fprintf(opt.Log, "ldap: lookup without a usable %s value: no entry\n", opt.Attribute)
		return write(bw, doneResponse(id, resultSuccess, ""))
	}
	if err := write(bw, entryResponse(id, login, base)); err != nil {
		return err
	}
	fmt.Fprintf(opt.Log, "ldap: lookup %s=%s: one entry\n", opt.Attribute, login)
	return write(bw, doneResponse(id, resultSuccess, ""))
}

// write appends a full LDAPMessage (a SEQUENCE) to the buffered writer.
func write(bw *bufio.Writer, message []byte) error {
	_, err := bw.Write(message)
	return err
}

// integerValue decodes an INTEGER or an ENUMERATED.
func integerValue(t tlv) (int, error) {
	if t.tag != tagInteger && t.tag != tagEnumerated {
		return 0, fmt.Errorf("ldap: tag 0x%02x is not an integer", t.tag)
	}
	if len(t.content) == 0 || len(t.content) > 4 {
		return 0, errors.New("ldap: integer out of range")
	}
	value := 0
	for _, octet := range t.content {
		value = value<<8 | int(octet)
	}
	if t.content[0]&0x80 != 0 { // negative: only a message ID would be, and it may not
		return 0, errors.New("ldap: negative integer")
	}
	return value, nil
}

// response assembles an LDAPMessage whose protocol operation is built by fill.
func response(id int, opTag byte, fill func(*encoder)) []byte {
	var e encoder
	e.messageID(id)
	var op encoder
	fill(&op)
	e.tlv(opTag, op.bytes)
	return sequenceOf(e.bytes)
}

func bindResponse(id int, code int, diagnostic string) []byte {
	return response(id, appBindResponse, func(op *encoder) {
		op.resultCode(code)
		op.str("")
		op.str(diagnostic)
	})
}

func doneResponse(id int, code int, diagnostic string) []byte {
	return response(id, appSearchDone, func(op *encoder) {
		op.resultCode(code)
		op.str("")
		op.str(diagnostic)
	})
}

func extendedResponse(id int, code int, diagnostic string) []byte {
	return response(id, appExtendedResponse, func(op *encoder) {
		op.resultCode(code)
		op.str("")
		op.str(diagnostic)
	})
}

// entryResponse builds the single entry: the login as an attribute, the same
// value in the distinguished name, and the two object classes every entry has.
//
// THE ATTRIBUTES ARE THE MINIMUM OPENPROJECT READS. It asks for first name, last
// name and mail too; leaving them absent is deliberate — the responder knows
// nothing about the person, and the sync service only writes what the entry
// carries, so the database keeps what the administrator set.
func entryResponse(id int, login, base string) []byte {
	dn := "uid=" + escapeDN(login)
	if base != "" {
		dn += "," + base
	}
	return response(id, appSearchEntry, func(op *encoder) {
		op.str(dn)
		var attributes encoder
		attributes.tlv(tagSequence, attribute("uid", login))
		attributes.tlv(tagSequence, attribute("objectClass", "top", "person"))
		op.tlv(tagSequence, attributes.bytes)
	})
}

// attribute is a PartialAttribute: SEQUENCE { type, SET OF values }.
func attribute(name string, values ...string) []byte {
	var e encoder
	e.str(name)
	var set encoder
	for _, value := range values {
		set.str(value)
	}
	e.tlv(tagSet, set.bytes)
	return e.bytes
}
