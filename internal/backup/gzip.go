// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package backup

import (
	"compress/gzip"
	"io"
)

func newGzip(w io.Writer) *gzip.Writer { return gzip.NewWriter(w) }

func newGunzip(r io.Reader) (io.Reader, error) { return gzip.NewReader(r) }
