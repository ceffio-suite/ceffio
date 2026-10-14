// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package bootstrap detects the hardware/OS profile of the target machine and
// validates that it can host Ceffio.
package bootstrap

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// Hardware summarizes the machine Ceffio will run on.
type Hardware struct {
	OS            string // "linux" | "darwin" | …
	Arch          string // "amd64" | "arm64" | …
	CPUs          int
	MemoryTotalMB uint64 // 0 if not detected
}

// Detect returns the hardware/OS profile of the current machine.
func Detect() Hardware {
	mem, _ := detectMemory()
	return Hardware{
		OS:            runtime.GOOS,
		Arch:          normalizeArch(runtime.GOARCH),
		CPUs:          runtime.NumCPU(),
		MemoryTotalMB: mem,
	}
}

// normalizeArch aligns GOARCH with the values expected by the installer.
func normalizeArch(goarch string) string {
	return goarch
}

// SupportedOS says whether the OS is supported.
// darwin is accepted only for development (k3d); production targets Linux.
func SupportedOS(osName string) bool {
	return osName == "linux" || osName == "darwin"
}

// SupportedArch says whether the architecture is supported.
func SupportedArch(arch string) bool {
	return arch == "amd64" || arch == "arm64"
}

// Validate checks that an (OS, arch) pair is usable by Ceffio.
func Validate(osName, arch string) error {
	if !SupportedOS(osName) {
		return fmt.Errorf("unsupported OS %q (expected linux or darwin)", osName)
	}
	if !SupportedArch(arch) {
		return fmt.Errorf("unsupported architecture %q (expected amd64 or arm64)", arch)
	}
	return nil
}

// MinHardware is the design minimum (a budget, not a benchmark).
func MinHardware() Hardware {
	return Hardware{CPUs: 2, MemoryTotalMB: 2048}
}

func detectMemory() (uint64, error) {
	switch runtime.GOOS {
	case "linux":
		b, err := os.ReadFile("/proc/meminfo")
		if err != nil {
			return 0, err
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				if f := strings.Fields(line); len(f) >= 2 {
					kb, _ := strconv.ParseUint(f[1], 10, 64)
					return kb / 1024, nil // kB → MB
				}
			}
		}
		return 0, nil
	case "darwin":
		out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
		if err != nil {
			return 0, err
		}
		by, _ := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
		return by / 1024 / 1024, nil // bytes → MB
	default:
		return 0, nil
	}
}
