// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package bootstrap

import "testing"

func TestNormalizeArch(t *testing.T) {
	for _, a := range []string{"amd64", "arm64", "386", "riscv64"} {
		if got := normalizeArch(a); got != a {
			t.Errorf("normalizeArch(%q) = %q, want %q", a, got, a)
		}
	}
}

func TestSupportedArch(t *testing.T) {
	for _, a := range []string{"amd64", "arm64"} {
		if !SupportedArch(a) {
			t.Errorf("SupportedArch(%q) should be true", a)
		}
	}
	for _, a := range []string{"386", "riscv64", "ppc64le", ""} {
		if SupportedArch(a) {
			t.Errorf("SupportedArch(%q) should be false", a)
		}
	}
}

func TestSupportedOS(t *testing.T) {
	for _, o := range []string{"linux", "darwin"} {
		if !SupportedOS(o) {
			t.Errorf("SupportedOS(%q) should be true", o)
		}
	}
	for _, o := range []string{"windows", "freebsd", ""} {
		if SupportedOS(o) {
			t.Errorf("SupportedOS(%q) should be false", o)
		}
	}
}

func TestValidate(t *testing.T) {
	for _, c := range [][2]string{{"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "arm64"}} {
		if err := Validate(c[0], c[1]); err != nil {
			t.Errorf("Validate(%q,%q) should pass, got error: %v", c[0], c[1], err)
		}
	}
	for _, c := range [][2]string{{"windows", "amd64"}, {"linux", "386"}, {"darwin", "riscv64"}} {
		if err := Validate(c[0], c[1]); err == nil {
			t.Errorf("Validate(%q,%q) should fail", c[0], c[1])
		}
	}
}

func TestMinHardware(t *testing.T) {
	m := MinHardware()
	if m.CPUs < 1 {
		t.Errorf("MinHardware.CPUs = %d, want >= 1", m.CPUs)
	}
	if m.MemoryTotalMB == 0 {
		t.Error("MinHardware.MemoryTotalMB must not be zero")
	}
}
