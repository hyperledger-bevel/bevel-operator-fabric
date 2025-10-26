package networkconfig_test

import (
	"testing"

	"github.com/kfsoftware/hlf-operator/controllers/networkconfig"
	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/stretchr/testify/assert"
)

func newTestNetworkConfig(secret, org string, identities []hlfv1alpha1.FabricNetworkConfigIdentity) *hlfv1alpha1.FabricNetworkConfig {
	return &hlfv1alpha1.FabricNetworkConfig{
		Spec: hlfv1alpha1.FabricNetworkConfigSpec{
			SecretName:   secret,
			Organization: org,
			Identities:   identities,
		},
	}
}

func assertValidation(t *testing.T, err error, expectError bool, expectedMsg string) {
	t.Helper()
	if expectError {
		assert.Error(t, err)
		if expectedMsg != "" {
			assert.Contains(t, err.Error(), expectedMsg)
		}
	} else {
		assert.NoError(t, err)
	}
}

// --- Tests ---

func TestValidateNetworkConfig(t *testing.T) {
	tests := []struct {
		name        string
		nc          *hlfv1alpha1.FabricNetworkConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "All validations pass",
			nc: newTestNetworkConfig(
				"hlf-secret",
				"Org1MSP",
				[]hlfv1alpha1.FabricNetworkConfigIdentity{
					{Name: "admin", Namespace: "default"},
				},
			),
			expectError: false,
		},
		{
			name: "Missing secret name",
			nc: newTestNetworkConfig(
				"",
				"Org1MSP",
				[]hlfv1alpha1.FabricNetworkConfigIdentity{
					{Name: "admin", Namespace: "default"},
				},
			),
			expectError: true,
			errorMsg:    "secret name is required",
		},
		{
			name: "Missing organization",
			nc: newTestNetworkConfig(
				"hlf-secret",
				"",
				[]hlfv1alpha1.FabricNetworkConfigIdentity{
					{Name: "admin", Namespace: "default"},
				},
			),
			expectError: true,
			errorMsg:    "organization is required",
		},
		{
			name: "Identity missing name",
			nc: newTestNetworkConfig(
				"hlf-secret",
				"Org1MSP",
				[]hlfv1alpha1.FabricNetworkConfigIdentity{
					{Name: "", Namespace: "default"},
				},
			),
			expectError: true,
			errorMsg:    "identity name is required",
		},
		{
			name: "Identity missing namespace",
			nc: newTestNetworkConfig(
				"hlf-secret",
				"Org1MSP",
				[]hlfv1alpha1.FabricNetworkConfigIdentity{
					{Name: "admin", Namespace: ""},
				},
			),
			expectError: true,
			errorMsg:    "identity namespace is required",
		},
		{
			name: "Multiple validation errors (secret, org, identity)",
			nc: newTestNetworkConfig(
				"",
				"",
				[]hlfv1alpha1.FabricNetworkConfigIdentity{
					{Name: "", Namespace: ""},
				},
			),
			expectError: true,
			errorMsg:    "validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			validator := &networkconfig.ConfigValidator{}
			err := validator.ValidateNetworkConfig(tt.nc)
			assertValidation(t, err, tt.expectError, tt.errorMsg)
		})
	}
}
