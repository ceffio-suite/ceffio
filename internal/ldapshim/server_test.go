// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package ldapshim

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// THE REQUESTS ARE BUILT OCTET BY OCTET, per RFC 4511, and NOT with the
// package's own encoder: a test that reuses the code under test to build its
// input proves at best that the package agrees with itself. What is written here
// is what a real client — net/ldap, inside OpenProject — puts on the wire.

func bindMessage(id int) []byte {
	var e encoder
	e.messageID(id)
	var b encoder
	b.integer(tagInteger, 3) // version
	b.str("")
	b.tlv(0x80, nil) // authentication: [0] simple, empty
	e.tlv(appBind, b.bytes)
	return sequenceOf(e.bytes)
}

func bindMessageWithPassword(id int, name, password string) []byte {
	var e encoder
	e.messageID(id)
	var b encoder
	b.integer(tagInteger, 3)
	b.str(name)
	b.tlv(0x80, []byte(password))
	e.tlv(appBind, b.bytes)
	return sequenceOf(e.bytes)
}

// searchMessage builds the search OpenProject sends for a login: the source's
// base, the filter (attr=login AND objectClass=*), and the attributes
// search_attributes asks for.
func searchMessage(id int, base, attribute, login string) []byte {
	var filter encoder
	var equality encoder
	equality.str(attribute)
	equality.str(login)
	filter.tlv(filterEqualityMatch, equality.bytes)
	var presence encoder
	presence.str("objectClass")
	filter.tlv(0x87, presence.bytes)
	andFilter := sequenceOf(filter.bytes)

	var e encoder
	e.messageID(id)
	var r encoder
	r.str(base)
	r.integer(tagEnumerated, 2) // scope: wholeSubtree
	r.integer(tagEnumerated, 0) // derefAliases: never
	r.integer(tagInteger, 0)    // sizeLimit
	r.integer(tagInteger, 0)    // timeLimit
	r.tlv(tagBoolean, []byte{0x00})
	r.bytes = append(r.bytes, andFilter...)
	var attributes encoder
	for _, name := range []string{"dn", "uid", "givenName", "sn", "mail"} {
		attributes.str(name)
	}
	r.tlv(tagSequence, attributes.bytes)
	e.tlv(appSearch, r.bytes)
	return sequenceOf(e.bytes)
}

func searchMessageWithoutEquality(id int, base string) []byte {
	var presence encoder
	presence.str("objectClass")

	var e encoder
	e.messageID(id)
	var r encoder
	r.str(base)
	r.integer(tagEnumerated, 2)
	r.integer(tagEnumerated, 0)
	r.integer(tagInteger, 0)
	r.integer(tagInteger, 0)
	r.tlv(tagBoolean, []byte{0x00})
	r.tlv(0x87, presence.bytes)
	r.tlv(tagSequence, nil)
	e.tlv(appSearch, r.bytes)
	return sequenceOf(e.bytes)
}

func unbindMessage(id int) []byte {
	var e encoder
	e.messageID(id)
	e.tlv(appUnbind, nil)
	return sequenceOf(e.bytes)
}

// start launches a server on a loopback address and hands back its log and its
// shutdown.
func start(t *testing.T, opt Options) (net.Conn, *strings.Builder, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	log := &strings.Builder{}
	opt.Log = log
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, listener, opt) }()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	stop := func() {
		conn.Close()
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve returned %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after cancellation")
		}
	}
	return conn, log, stop
}

// readResponse reads exactly one LDAPMessage from the connection.
func readResponse(t *testing.T, conn net.Conn, br *bufio.Reader) tlv {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	msg, err := readMessage(br, 1<<20)
	if err != nil {
		t.Fatalf("reading a response: %v", err)
	}
	return msg
}

// operation returns the message ID and the protocol operation of a response.
func operation(t *testing.T, msg tlv) (int, tlv) {
	t.Helper()
	fields, err := msg.children()
	if err != nil || len(fields) < 2 {
		t.Fatalf("malformed response: %v", err)
	}
	id, err := integerValue(fields[0])
	if err != nil {
		t.Fatal(err)
	}
	return id, fields[1]
}

// resultOf reads the resultCode of a BindResponse, SearchResultDone or
// ExtendedResponse: its first field.
func resultOf(t *testing.T, op tlv) int {
	t.Helper()
	fields, err := op.children()
	if err != nil || len(fields) == 0 {
		t.Fatalf("malformed protocol operation: %v", err)
	}
	code, err := integerValue(fields[0])
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// TestOpenProjectLookupSucceeds replays exactly the sequence OpenProject sends on
// a header sign-in: anonymous bind, lookup of the user, unbind. It is the test
// that says whether the module can ship.
func TestOpenProjectLookupSucceeds(t *testing.T) {
	conn, log, stop := start(t, Options{Attribute: "uid"})
	defer stop()
	br := bufio.NewReader(conn)

	if _, err := conn.Write(bindMessage(1)); err != nil {
		t.Fatal(err)
	}
	id, op := operation(t, readResponse(t, conn, br))
	if op.tag != appBindResponse || id != 1 {
		t.Fatalf("expected a BindResponse for message 1, got tag 0x%02x", op.tag)
	}
	if code := resultOf(t, op); code != resultSuccess {
		t.Fatalf("anonymous bind refused with code %d", code)
	}

	if _, err := conn.Write(searchMessage(2, "dc=ceffio", "uid", "adminceffio")); err != nil {
		t.Fatal(err)
	}
	id, op = operation(t, readResponse(t, conn, br))
	if op.tag != appSearchEntry || id != 2 {
		t.Fatalf("expected a SearchResultEntry for message 2, got tag 0x%02x", op.tag)
	}
	// The entry must carry the requested login, under the requested base.
	fields, err := op.children()
	if err != nil || len(fields) < 2 {
		t.Fatalf("malformed entry: %v", err)
	}
	dn := string(fields[0].content)
	if dn != "uid=adminceffio,dc=ceffio" {
		t.Errorf("dn = %q", dn)
	}
	if !strings.Contains(string(op.content), "adminceffio") {
		t.Error("the entry does not carry the requested login")
	}

	_, op = operation(t, readResponse(t, conn, br))
	if op.tag != appSearchDone {
		t.Fatalf("expected SearchResultDone, got tag 0x%02x", op.tag)
	}
	if code := resultOf(t, op); code != resultSuccess {
		t.Fatalf("search failed with code %d", code)
	}

	if _, err := conn.Write(unbindMessage(3)); err != nil {
		t.Fatal(err)
	}
	if _, err := br.Peek(1); !errors.Is(err, io.EOF) {
		t.Errorf("the server did not close the connection after Unbind: %v", err)
	}
	if !strings.Contains(log.String(), "lookup uid=adminceffio: one entry") {
		t.Errorf("log does not record the answered lookup: %q", log.String())
	}
}

// TestAnUnknownLoginIsStillAnswered: the responder answers by name. Whether the
// user exists is OpenProject's decision — its database, not this server — so a
// name it has never heard of is answered as the entry for that name.
func TestAnUnknownLoginIsStillAnswered(t *testing.T) {
	conn, log, stop := start(t, Options{})
	defer stop()
	br := bufio.NewReader(conn)

	conn.Write(bindMessage(1))
	readResponse(t, conn, br)
	conn.Write(searchMessage(2, "dc=ceffio", "uid", "inconnu"))
	_, op := operation(t, readResponse(t, conn, br))
	if op.tag != appSearchEntry {
		t.Fatalf("expected a SearchResultEntry, got tag 0x%02x", op.tag)
	}
	if !strings.Contains(log.String(), "lookup uid=inconnu: one entry") {
		t.Errorf("log: %q", log.String())
	}
}

// TestAFilterWithoutEqualityReturnsNobody: the server does not interpret a
// filter language, it answers the shape OpenProject sends.
func TestAFilterWithoutEqualityReturnsNobody(t *testing.T) {
	conn, log, stop := start(t, Options{})
	defer stop()
	br := bufio.NewReader(conn)

	conn.Write(bindMessage(1))
	readResponse(t, conn, br)
	conn.Write(searchMessageWithoutEquality(2, "dc=ceffio"))
	_, op := operation(t, readResponse(t, conn, br))
	if op.tag != appSearchDone {
		t.Fatalf("expected SearchResultDone, got tag 0x%02x", op.tag)
	}
	if !strings.Contains(log.String(), "no entry") {
		t.Errorf("log does not record the refused lookup: %q", log.String())
	}
}

// TestAPasswordIsNotAccepted: the responder verifies no secret, so it must not
// pretend to verify one.
func TestAPasswordIsNotAccepted(t *testing.T) {
	conn, _, stop := start(t, Options{})
	defer stop()
	br := bufio.NewReader(conn)

	conn.Write(bindMessageWithPassword(1, "cn=admin", "secret"))
	_, op := operation(t, readResponse(t, conn, br))
	if op.tag != appBindResponse {
		t.Fatalf("expected a BindResponse, got tag 0x%02x", op.tag)
	}
	if code := resultOf(t, op); code != resultInvalidCredentials {
		t.Errorf("a simple bind with a password was answered with code %d", code)
	}
}

// TestAnImpossibleLoginIsNotEchoed: the answer is built from the request, so the
// value is validated before it enters a DN and an attribute.
func TestAnImpossibleLoginIsNotEchoed(t *testing.T) {
	for _, login := range []string{"", "a)(uid=*", "ad min", strings.Repeat("x", 256)} {
		if validLogin(login) {
			t.Errorf("%q was accepted as a login", login)
		}
	}
	for _, good := range []string{"adminceffio", "jean.dupont", "a.b-c_d@example.com", "x"} {
		if !validLogin(good) {
			t.Errorf("%q was refused", good)
		}
	}
	// DN escaping protects even a value a later version of validLogin lets
	// through.
	if got := escapeDN("a,b+c"); got != `a\,b\+c` {
		t.Errorf("escapeDN = %q", got)
	}
}

// TestTheServerStops: shutdown must return, without leaving a connection open. A
// pod that terminates must stop accepting.
func TestTheServerStops(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, listener, Options{}) }()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after cancellation")
	}
}

// TestASilentConnectionIsClosed: without a deadline, a connection that sends
// nothing holds a goroutine for ever — the pod has only a few dozen places.
func TestASilentConnectionIsClosed(t *testing.T) {
	conn, _, stop := start(t, Options{Timeout: 100 * time.Millisecond})
	defer stop()
	br := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := br.Peek(1); err == nil {
		t.Fatal("an idle connection was not closed")
	}
}
