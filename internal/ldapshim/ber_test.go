// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package ldapshim

import (
	"bufio"
	"bytes"
	"testing"
)

// TestReadTLV: the decoder accepts every length form a real client produces and
// refuses the ones an attacker would try.
func TestReadTLV(t *testing.T) {
	cases := []struct {
		name    string
		octets  []byte
		tag     byte
		content string
	}{
		{"short form", []byte{0x04, 0x03, 'a', 'b', 'c'}, tagOctetString, "abc"},
		{"empty value", []byte{0x04, 0x00}, tagOctetString, ""},
		// 130 octets: the shortest value that needs the long form at all.
		{"long form, one octet", append([]byte{0x04, 0x81, 0x82}, bytes.Repeat([]byte{'z'}, 130)...), tagOctetString, string(bytes.Repeat([]byte{'z'}, 130))},
		{"long form, two octets", append([]byte{0x04, 0x82, 0x01, 0x00}, bytes.Repeat([]byte{'x'}, 256)...), tagOctetString, string(bytes.Repeat([]byte{'x'}, 256))},
	}
	for _, c := range cases {
		element, rest, err := readTLV(c.octets)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if element.tag != c.tag || string(element.content) != c.content {
			t.Errorf("%s: got tag 0x%02x %q", c.name, element.tag, element.content)
		}
		if len(rest) != 0 {
			t.Errorf("%s: %d octets left over", c.name, len(rest))
		}
	}

	// Non-minimal lengths are refused too: 0x81 0x01 for a one-octet value is
	// not what any encoder emits, and two spellings of one frame is how parsers
	// drift apart.
	bad := map[string][]byte{
		"truncated":            {0x04},
		"length past the end":  {0x04, 0x05, 'a'},
		"indefinite length":    {0x04, 0x80, 0x00, 0x00},
		"reserved tag zero":    {0x00, 0x00},
		"non-minimal length":   {0x04, 0x81, 0x01, 'a'},
		"length in four bytes": {0x04, 0x84, 0x00, 0x00, 0x00, 0x01, 'a'},
	}
	for name, octets := range bad {
		if _, _, err := readTLV(octets); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// TestReadMessageRefusesAnOversizedMessage: the limit applies to the ANNOUNCED
// length, before any content is allocated. A peer must not be able to make the
// process reserve memory by claiming a size.
func TestReadMessageRefusesAnOversizedMessage(t *testing.T) {
	// Announced length 0x82 0xff 0xff = 65535 octets, under a 1024 limit, with
	// no content sent at all: the refusal must come from the header.
	stream := bufio.NewReader(bytes.NewReader([]byte{0x30, 0x82, 0xff, 0xff}))
	if _, err := readMessage(stream, 1024); err == nil {
		t.Fatal("a message announcing 65535 octets was accepted under a 1024 limit")
	}
	// Short form announcing 127 octets under a 64 limit: refused for its length
	// or truncated, but never read as a success.
	if _, err := readMessage(bufio.NewReader(bytes.NewReader([]byte{0x30, 0x7f})), 64); err == nil {
		t.Fatal("a 127-octet message was accepted under a 64 limit")
	}
}

// TestIntegerValue accepts the encodings a client can send for a message ID and
// refuses the ones that are not a positive value.
func TestIntegerValue(t *testing.T) {
	for _, c := range []struct {
		octets []byte
		value  int
	}{
		{[]byte{0x02, 0x01, 0x01}, 1},
		{[]byte{0x02, 0x01, 0x7f}, 127},
		{[]byte{0x02, 0x02, 0x00, 0x80}, 128},
		{[]byte{0x02, 0x04, 0x7f, 0xff, 0xff, 0xff}, 0x7fffffff},
	} {
		element, _, err := readTLV(c.octets)
		if err != nil {
			t.Fatal(err)
		}
		got, err := integerValue(element)
		if err != nil {
			t.Fatalf("%v: %v", c.octets, err)
		}
		if got != c.value {
			t.Errorf("%v: got %d, want %d", c.octets, got, c.value)
		}
	}

	for _, bad := range [][]byte{
		{0x02, 0x00},                // empty
		{0x02, 0x05, 1, 2, 3, 4, 5}, // too wide
		{0x02, 0x01, 0xff},          // negative
		{0x04, 0x01, 0x00},          // not an integer
	} {
		element, _, err := readTLV(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := integerValue(element); err == nil {
			t.Errorf("%v was accepted", bad)
		}
	}
}

// TestEncodingRoundTrip: what the encoder writes, the decoder reads back —
// including a value long enough to need the long length form.
func TestEncodingRoundTrip(t *testing.T) {
	var e encoder
	e.messageID(7)
	e.str(string(bytes.Repeat([]byte{'y'}, 300)))
	message := sequenceOf(e.bytes)

	element, rest, err := readTLV(message)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 {
		t.Fatalf("%d octets left over", len(rest))
	}
	fields, err := element.children()
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 2 {
		t.Fatalf("got %d children", len(fields))
	}
	id, err := integerValue(fields[0])
	if err != nil || id != 7 {
		t.Fatalf("id = %d, %v", id, err)
	}
	if len(fields[1].content) != 300 {
		t.Errorf("value of %d octets", len(fields[1].content))
	}
}
