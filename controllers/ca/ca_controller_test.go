package ca_test

import (
	"testing"

	"github.com/kfsoftware/hlf-operator/controllers/ca"
	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/stretchr/testify/assert"
)

func newTestCA(store hlfv1alpha1.CredentialStore, vault *hlfv1alpha1.FabricCAVaultSpec) *hlfv1alpha1.FabricCA {
	return &hlfv1alpha1.FabricCA{
		Spec: hlfv1alpha1.FabricCASpec{
			CredentialStore: store,
			Vault:           vault,
			Storage: hlfv1alpha1.Storage{
				Size:         "1G",
				StorageClass: "standard",
				AccessMode:   "ReadWriteOnce",
			},
			Hosts: []string{"host1", "host2", "host3"},
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

func TestValidateCA(t *testing.T) {
	tests := []struct {
		name        string
		ca          *hlfv1alpha1.FabricCA
		expectError bool
		errorMsg    string
	}{
		{
			name:        "All validations pass",
			ca:          newTestCA(hlfv1alpha1.CredentialStoreKubernetes, nil),
			expectError: false,
		},
		{
			name:        "Unsupported credential store",
			ca:          newTestCA("unknown-store", nil),
			expectError: true,
			errorMsg:    "unsupported credential store",
		},
		{
			name:        "Vault credential store without config",
			ca:          newTestCA(hlfv1alpha1.CredentialStoreVault, nil),
			expectError: true,
			errorMsg:    "vault configuration is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v := &ca.ConfigValidator{}
			err := v.ValidateCA(tt.ca)
			assertValidation(t, err, tt.expectError, tt.errorMsg)
		})
	}
}

func TestValidateVaultConfig(t *testing.T) {
	tests := []struct {
		name        string
		ca          *hlfv1alpha1.FabricCA
		expectError bool
		expectedMsg string
	}{
		{
			name:        "Missing vault config",
			ca:          newTestCA(hlfv1alpha1.CredentialStoreVault, nil),
			expectError: true,
			expectedMsg: "vault configuration is required",
		},
		{
			name:        "Valid vault config provided",
			ca:          newTestCA(hlfv1alpha1.CredentialStoreVault, &hlfv1alpha1.FabricCAVaultSpec{}),
			expectError: false,
		},
	}

	v := &ca.ConfigValidator{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := v.ValidateCA(tt.ca)
			assertValidation(t, err, tt.expectError, tt.expectedMsg)
		})
	}
}
