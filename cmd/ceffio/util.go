package main

import (
	"fmt"
)

func notImplemented(command string) error {
	return fmt.Errorf("commande %q : pas encore implémentée (roadmap Phase 0+)", command)
}

func yesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}
