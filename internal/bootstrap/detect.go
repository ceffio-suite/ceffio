// Package bootstrap détecte le profil matériel/OS de la machine cible et
// valide qu'elle peut héberger Ceffio.
package bootstrap

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// Hardware résume la machine sur laquelle Ceffio va tourner.
type Hardware struct {
	OS            string // "linux" | "darwin" | …
	Arch          string // "amd64" | "arm64" | …
	CPUs          int
	MemoryTotalMB uint64 // 0 si non détecté
}

// Detect retourne le profil matériel/OS de la machine courante.
func Detect() Hardware {
	mem, _ := detectMemory()
	return Hardware{
		OS:            runtime.GOOS,
		Arch:          normalizeArch(runtime.GOARCH),
		CPUs:          runtime.NumCPU(),
		MemoryTotalMB: mem,
	}
}

// normalizeArch aligne GOARCH sur les valeurs attendues par l'installateur.
func normalizeArch(goarch string) string {
	return goarch
}

// SupportedOS indique si l'OS est supporté.
// darwin est accepté uniquement pour le développement (k3d) ; la production vise Linux.
func SupportedOS(osName string) bool {
	return osName == "linux" || osName == "darwin"
}

// SupportedArch indique si l'architecture est supportée.
func SupportedArch(arch string) bool {
	return arch == "amd64" || arch == "arm64"
}

// Validate vérifie qu'un couple (OS, arch) est exploitable par Ceffio.
func Validate(osName, arch string) error {
	if !SupportedOS(osName) {
		return fmt.Errorf("OS non supporté %q (attendu linux ou darwin)", osName)
	}
	if !SupportedArch(arch) {
		return fmt.Errorf("architecture non supportée %q (attendu amd64 ou arm64)", arch)
	}
	return nil
}

// MinHardware est le minimum de conception (budget, pas un benchmark).
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
		return by / 1024 / 1024, nil // octets → MB
	default:
		return 0, nil
	}
}
