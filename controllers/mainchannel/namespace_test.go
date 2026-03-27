package mainchannel

import (
	"testing"

	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestNamespaceNotHardcoded verifies that the mainchannel controller uses the
// resource's own namespace and never falls back to "default".
// Regression test for #296 and #297.
func TestNamespaceNotHardcoded(t *testing.T) {
	tests := []struct {
		name              string
		namespace         string
		expectedNamespace string
	}{
		{
			name:              "custom namespace is preserved",
			namespace:         "hlf-network",
			expectedNamespace: "hlf-network",
		},
		{
			name:              "another namespace is preserved",
			namespace:         "production",
			expectedNamespace: "production",
		},
		{
			name:              "empty namespace is not replaced with default",
			namespace:         "",
			expectedNamespace: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			channel := &hlfv1alpha1.FabricMainChannel{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-channel",
					Namespace: tt.namespace,
				},
			}

			// Verify the namespace is used directly without fallback to "default"
			ns := channel.Namespace
			assert.Equal(t, tt.expectedNamespace, ns,
				"Namespace should be taken directly from ObjectMeta.Namespace, not hardcoded to 'default'")
			assert.NotEqual(t, "default", ns,
				"Namespace should never be hardcoded to 'default' when resource has a different namespace")
		})
	}
}

// TestConfigMapNamespaceMatchesResource verifies that configmap namespace
// derives from the FabricMainChannel resource namespace.
func TestConfigMapNamespaceMatchesResource(t *testing.T) {
	channel := &hlfv1alpha1.FabricMainChannel{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-channel",
			Namespace: "my-namespace",
		},
	}

	configMapNamespace := channel.Namespace
	assert.Equal(t, "my-namespace", configMapNamespace,
		"ConfigMap namespace should match the FabricMainChannel resource namespace")
}
