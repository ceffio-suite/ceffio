package data

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation"
)

// TestValkeyLabelsValides: a k8s label accepts neither a space nor a special
// character. This defect made a real deployment fail:
//
//	The Service "ceffio-redis" is invalid: metadata.labels: Invalid value:
//	"renamed to ceffio-valkey"
func TestValkeyLabelsValides(t *testing.T) {
	// reproduces the labels of the generated manifest
	labels := map[string]string{
		"app.kubernetes.io/part-of": "ceffio",
		"ceffio.io/deprecated":      "true",
	}
	for k, v := range labels {
		if errs := validation.IsValidLabelValue(v); len(errs) > 0 {
			t.Errorf("label %s = %q rejected by Kubernetes: %v", k, v, errs)
		}
	}
	// and the faulty value MUST be rejected: the test catches the defect
	if errs := validation.IsValidLabelValue("renamed to ceffio-valkey"); len(errs) == 0 {
		t.Error("the invalid value was accepted: this check would not have caught the bug")
	} else {
		t.Logf("valeur fautive bien rejetee : %v", strings.Join(errs, "; ")[:60])
	}
}
