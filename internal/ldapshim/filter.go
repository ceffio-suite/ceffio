// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package ldapshim

// loginFromFilter returns the value an equality filter asserts for attribute.
//
// OPENPROJECT SENDS EXACTLY ONE SHAPE, and this function covers it rather than
// pretending to be a directory: `login_filter(login)` is
// `Filter.eq(attr_login, login) & Filter.eq("objectClass", "*")`, which travels
// as
//
//	AND { equalityMatch { uid, "<login>" }, presence { objectClass } }
//
// so the value is found by walking the tree for an equalityMatch on the
// configured attribute. A filter of any other shape matches nothing — the same
// answer a directory gives for an entry it does not hold, and it keeps this
// server from inventing an interpretation of a filter language it does not
// implement.
func loginFromFilter(filter tlv, attribute string) (string, bool) {
	if filter.tag == filterEqualityMatch {
		fields, err := filter.children()
		if err != nil || len(fields) != 2 {
			return "", false
		}
		if fields[0].tag != tagOctetString || string(fields[0].content) != attribute {
			return "", false
		}
		if fields[1].tag != tagOctetString {
			return "", false
		}
		return string(fields[1].content), true
	}
	if !filter.constructed() {
		return "", false
	}
	fields, err := filter.children()
	if err != nil {
		return "", false
	}
	for _, field := range fields {
		if value, ok := loginFromFilter(field, attribute); ok {
			return value, true
		}
	}
	return "", false
}

// validLogin refuses a value that could not be a login, BEFORE it is echoed into
// a distinguished name and an attribute.
//
// THE POINT IS NOT AUTHENTICATION — the responder checks no secret — but the
// answer is built from the request, and an empty or unprintable value would
// produce an entry that is about nobody. OpenProject's own logins are ASCII
// identifiers; anything else is answered with no entry, which fails the sign-in
// instead of inventing a user.
func validLogin(login string) bool {
	if login == "" || len(login) > 255 {
		return false
	}
	for _, r := range login {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_' || r == '@' || r == '+':
		default:
			return false
		}
	}
	return true
}

// escapeDN escapes a value for a distinguished name, RFC 4514 §2.4. A login
// needs none of it in practice; escaping anyway means a value a later version of
// validLogin lets through cannot turn into a second RDN.
func escapeDN(value string) string {
	var b []byte
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch c {
		case ',', '+', '"', '\\', '<', '>', ';', '=', '#':
			b = append(b, '\\', c)
		case ' ':
			// A space is significant only at the ends; escaping every one is
			// legal and simpler than tracking positions.
			b = append(b, '\\', ' ')
		default:
			b = append(b, c)
		}
	}
	return string(b)
}
