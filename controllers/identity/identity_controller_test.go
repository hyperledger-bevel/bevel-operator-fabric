package identity_test

import (
	"testing"

	"github.com/kfsoftware/hlf-operator/controllers/identity"
	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/stretchr/testify/assert"
)

func newTestIdentity(store hlfv1alpha1.CredentialStore, vault *hlfv1alpha1.VaultComponent, cahost, enrollID, enrollSecret, mspID string) *hlfv1alpha1.FabricIdentity {
	return &hlfv1alpha1.FabricIdentity{
		Spec: hlfv1alpha1.FabricIdentitySpec{
			CredentialStore: store,
			Vault:           vault,
			Cahost:          cahost,
			Enrollid:        enrollID,
			Enrollsecret:    enrollSecret,
			MSPID:           mspID,
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

func TestValidateIdentity(t *testing.T) {
	tests := []struct {
		name        string
		identity    *hlfv1alpha1.FabricIdentity
		expectError bool
		errorMsg    string
	}{
		{
			name: "All validations pass (Kubernetes credential store)",
			identity: newTestIdentity(
				hlfv1alpha1.CredentialStoreKubernetes,
				nil,
				"ca.example.com",
				"admin",
				"adminpw",
				"Org1MSP",
			),
			expectError: false,
		},
		{
			name: "Unsupported credential store",
			identity: newTestIdentity(
				"invalid-store",
				nil,
				"ca.example.com",
				"admin",
				"adminpw",
				"Org1MSP",
			),
			expectError: true,
			errorMsg:    "unsupported credential store",
		},
		{
			name: "Vault credential store without vault config",
			identity: newTestIdentity(
				hlfv1alpha1.CredentialStoreVault,
				nil,
				"",
				"",
				"",
				"Org1MSP",
			),
			expectError: true,
			errorMsg:    "vault configuration is required",
		},
		{
			name: "Vault credential store with vault config but missing MSPID",
			identity: newTestIdentity(
				hlfv1alpha1.CredentialStoreVault,
				&hlfv1alpha1.VaultComponent{},
				"",
				"",
				"",
				"",
			),
			expectError: true,
			errorMsg:    "MSP ID is required",
		},
		{
			name: "Kubernetes store missing CA host",
			identity: newTestIdentity(
				hlfv1alpha1.CredentialStoreKubernetes,
				nil,
				"",
				"admin",
				"adminpw",
				"Org1MSP",
			),
			expectError: true,
			errorMsg:    "CA host is required",
		},
		{
			name: "Kubernetes store missing enrollment ID",
			identity: newTestIdentity(
				hlfv1alpha1.CredentialStoreKubernetes,
				nil,
				"ca.example.com",
				"",
				"adminpw",
				"Org1MSP",
			),
			expectError: true,
			errorMsg:    "enrollment ID is required",
		},
		{
			name: "Kubernetes store missing enrollment secret",
			identity: newTestIdentity(
				hlfv1alpha1.CredentialStoreKubernetes,
				nil,
				"ca.example.com",
				"admin",
				"",
				"Org1MSP",
			),
			expectError: true,
			errorMsg:    "enrollment secret is required",
		},
		{
			name: "Missing MSP ID",
			identity: newTestIdentity(
				hlfv1alpha1.CredentialStoreKubernetes,
				nil,
				"ca.example.com",
				"admin",
				"adminpw",
				"",
			),
			expectError: true,
			errorMsg:    "MSP ID is required",
		},
		{
			name: "Empty credential store defaults to Kubernetes",
			identity: newTestIdentity(
				"", // defaults to Kubernetes
				nil,
				"ca.example.com",
				"admin",
				"adminpw",
				"Org1MSP",
			),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			validator := &identity.ConfigValidator{}
			err := validator.ValidateIdentity(tt.identity)
			assertValidation(t, err, tt.expectError, tt.errorMsg)
		})
	}
}
