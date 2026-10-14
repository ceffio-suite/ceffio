package data

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation"
)

// TestValkeyLabelsValides : un label k8s n'accepte ni espace ni caractere special.
// Ce defaut a fait echouer un deploiement reel :
//
//	The Service "ceffio-redis" is invalid: metadata.labels: Invalid value:
//	"renamed to ceffio-valkey"
func TestValkeyLabelsValides(t *testing.T) {
	// reproduit les labels du manifeste genere
	labels := map[string]string{
		"app.kubernetes.io/part-of": "ceffio",
		"ceffio.io/deprecated":      "true",
	}
	for k, v := range labels {
		if errs := validation.IsValidLabelValue(v); len(errs) > 0 {
			t.Errorf("label %s = %q rejected by Kubernetes: %v", k, v, errs)
		}
	}
	// et la valeur fautive DOIT etre rejetee : le test attrape le defaut
	if errs := validation.IsValidLabelValue("renamed to ceffio-valkey"); len(errs) == 0 {
		t.Error("the invalid value was accepted: this check would not have caught the bug")
	} else {
		t.Logf("valeur fautive bien rejetee : %v", strings.Join(errs, "; ")[:60])
	}
}
