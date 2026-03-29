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

func TestBuildIstioConfig(t *testing.T) {
	tests := []struct {
		name     string
		input    *hlfv1alpha1.FabricIstio
		expected ca.Istio
	}{
		{
			name:  "Nil spec returns defaults",
			input: nil,
			expected: ca.Istio{
				Port:           443,
				Hosts:          []string{},
				IngressGateway: "ingressgateway",
			},
		},
		{
			name: "Custom IngressGateway is preserved",
			input: &hlfv1alpha1.FabricIstio{
				Port:           443,
				Hosts:          []string{"ca.example.com"},
				IngressGateway: "istio",
			},
			expected: ca.Istio{
				Port:           443,
				Hosts:          []string{"ca.example.com"},
				IngressGateway: "istio",
			},
		},
		{
			name: "Empty IngressGateway gets default",
			input: &hlfv1alpha1.FabricIstio{
				Port:           8443,
				Hosts:          []string{"ca.example.com"},
				IngressGateway: "",
			},
			expected: ca.Istio{
				Port:           8443,
				Hosts:          []string{"ca.example.com"},
				IngressGateway: "ingressgateway",
			},
		},
		{
			name: "Zero port gets default 443",
			input: &hlfv1alpha1.FabricIstio{
				Port:           0,
				Hosts:          []string{},
				IngressGateway: "my-gw",
			},
			expected: ca.Istio{
				Port:           443,
				Hosts:          []string{},
				IngressGateway: "my-gw",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := ca.BuildIstioConfig(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildGatewayApiConfig(t *testing.T) {
	tests := []struct {
		name     string
		input    *hlfv1alpha1.FabricGatewayApi
		expected ca.GatewayApi
	}{
		{
			name:  "Nil spec returns empty defaults",
			input: nil,
			expected: ca.GatewayApi{
				Port:             443,
				Hosts:            []string{},
				GatewayName:      "",
				GatewayNamespace: "",
			},
		},
		{
			name: "Values are passed through",
			input: &hlfv1alpha1.FabricGatewayApi{
				Port:             8443,
				Hosts:            []string{"ca.example.com"},
				GatewayName:      "my-gw",
				GatewayNamespace: "istio-system",
			},
			expected: ca.GatewayApi{
				Port:             8443,
				Hosts:            []string{"ca.example.com"},
				GatewayName:      "my-gw",
				GatewayNamespace: "istio-system",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := ca.BuildGatewayApiConfig(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
