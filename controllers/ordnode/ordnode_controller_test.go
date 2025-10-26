package ordnode_test

import (
	"testing"

	"github.com/kfsoftware/hlf-operator/controllers/ordnode"
	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/stretchr/testify/assert"
)

func newTestOrdererNode(store hlfv1alpha1.CredentialStore, mspID, caHost, enrollID, enrollSecret, storageSize string, replicas int,
	vaultComponent *hlfv1alpha1.VaultComponent, vaultTLS *hlfv1alpha1.VaultComponent) *hlfv1alpha1.FabricOrdererNode {

	return &hlfv1alpha1.FabricOrdererNode{
		Spec: hlfv1alpha1.FabricOrdererNodeSpec{
			CredentialStore: store,
			MspID:           mspID,
			Replicas:        replicas,
			Storage: hlfv1alpha1.Storage{
				Size: storageSize,
			},
			Secret: &hlfv1alpha1.Secret{
				Enrollment: hlfv1alpha1.Enrollment{
					Component: hlfv1alpha1.Component{
						Cahost:       caHost,
						Enrollid:     enrollID,
						Enrollsecret: enrollSecret,
						Vault:        vaultComponent,
					},
					TLS: hlfv1alpha1.TLSComponent{
						Vault: vaultTLS,
					},
				},
			},
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

func TestValidateOrdererNode(t *testing.T) {
	tests := []struct {
		name        string
		node        *hlfv1alpha1.FabricOrdererNode
		expectError bool
		errorMsg    string
	}{
		{
			name: "All validations pass (Kubernetes store)",
			node: newTestOrdererNode(
				hlfv1alpha1.CredentialStoreKubernetes,
				"Org1MSP",
				"ca.example.com",
				"admin",
				"adminpw",
				"1Gi",
				1,
				nil,
				nil,
			),
			expectError: false,
		},
		{
			name: "Unsupported credential store",
			node: newTestOrdererNode(
				"invalid-store",
				"Org1MSP",
				"ca.example.com",
				"admin",
				"adminpw",
				"1Gi",
				1,
				nil,
				nil,
			),
			expectError: true,
			errorMsg:    "unsupported credential store",
		},
		{
			name: "Vault store missing component vault config",
			node: newTestOrdererNode(
				hlfv1alpha1.CredentialStoreVault,
				"Org1MSP",
				"",
				"",
				"",
				"1Gi",
				1,
				nil,
				&hlfv1alpha1.VaultComponent{},
			),
			expectError: true,
			errorMsg:    "vault configuration is required",
		},
		{
			name: "Vault store missing TLS vault config",
			node: newTestOrdererNode(
				hlfv1alpha1.CredentialStoreVault,
				"Org1MSP",
				"",
				"",
				"",
				"1Gi",
				1,
				&hlfv1alpha1.VaultComponent{},
				nil,
			),
			expectError: true,
			errorMsg:    "vault TLS configuration is required",
		},
		{
			name: "Kubernetes store missing CA host",
			node: newTestOrdererNode(
				hlfv1alpha1.CredentialStoreKubernetes,
				"Org1MSP",
				"",
				"admin",
				"adminpw",
				"1Gi",
				1,
				nil,
				nil,
			),
			expectError: true,
			errorMsg:    "CA host is required",
		},
		{
			name: "Kubernetes store missing enroll ID",
			node: newTestOrdererNode(
				hlfv1alpha1.CredentialStoreKubernetes,
				"Org1MSP",
				"ca.example.com",
				"",
				"adminpw",
				"1Gi",
				1,
				nil,
				nil,
			),
			expectError: true,
			errorMsg:    "enrollment ID is required",
		},
		{
			name: "Kubernetes store missing enroll secret",
			node: newTestOrdererNode(
				hlfv1alpha1.CredentialStoreKubernetes,
				"Org1MSP",
				"ca.example.com",
				"admin",
				"",
				"1Gi",
				1,
				nil,
				nil,
			),
			expectError: true,
			errorMsg:    "enrollment secret is required",
		},
		{
			name: "Missing MSP ID (networking validation)",
			node: newTestOrdererNode(
				hlfv1alpha1.CredentialStoreKubernetes,
				"",
				"ca.example.com",
				"admin",
				"adminpw",
				"1Gi",
				1,
				nil,
				nil,
			),
			expectError: true,
			errorMsg:    "MSP ID is required",
		},
		{
			name: "Missing storage size",
			node: newTestOrdererNode(
				hlfv1alpha1.CredentialStoreKubernetes,
				"Org1MSP",
				"ca.example.com",
				"admin",
				"adminpw",
				"",
				1,
				nil,
				nil,
			),
			expectError: true,
			errorMsg:    "storage size is required",
		},
		{
			name: "Invalid replicas (less than 1)",
			node: newTestOrdererNode(
				hlfv1alpha1.CredentialStoreKubernetes,
				"Org1MSP",
				"ca.example.com",
				"admin",
				"adminpw",
				"1Gi",
				0,
				nil,
				nil,
			),
			expectError: true,
			errorMsg:    "replicas must be at least 1",
		},
		{
			name: "Multiple validation failures aggregated",
			node: newTestOrdererNode(
				hlfv1alpha1.CredentialStoreKubernetes,
				"",
				"",
				"",
				"",
				"",
				0,
				nil,
				nil,
			),
			expectError: true,
			errorMsg:    "validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v := &ordnode.ConfigValidator{}
			err := v.ValidateOrdererNode(tt.node)
			assertValidation(t, err, tt.expectError, tt.errorMsg)
		})
	}
}
