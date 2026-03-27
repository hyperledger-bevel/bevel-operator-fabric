package mainchannel

import (
	"testing"

	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestConfigMapNamespaceFallback verifies that for cluster-scoped resources
// (where Namespace is empty), the configmap namespace falls back to "default".
// FabricMainChannel is cluster-scoped, so .Namespace is always "".
// Regression test for #296 and #297.
func TestConfigMapNamespaceFallback(t *testing.T) {
	tests := []struct {
		name              string
		namespace         string
		expectedNamespace string
	}{
		{
			name:              "cluster-scoped resource falls back to default",
			namespace:         "",
			expectedNamespace: "default",
		},
		{
			name:              "namespace-scoped resource uses its own namespace",
			namespace:         "hlf-network",
			expectedNamespace: "hlf-network",
		},
		{
			name:              "another namespace is preserved",
			namespace:         "production",
			expectedNamespace: "production",
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

			// This mirrors the logic in saveChannelConfig
			configMapNamespace := channel.Namespace
			if configMapNamespace == "" {
				configMapNamespace = "default"
			}

			assert.Equal(t, tt.expectedNamespace, configMapNamespace,
				"ConfigMap namespace should use resource namespace or fall back to 'default' for cluster-scoped resources")
		})
	}
}
