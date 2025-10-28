package peer_test

import (
	"github.com/kfsoftware/hlf-operator/controllers/peer"
	"testing"

	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/stretchr/testify/assert"
)

func newTestPeer(store hlfv1alpha1.CredentialStore, mspID, caHost, enrollID, enrollSecret, peerStorage string,
	vaultComponent *hlfv1alpha1.VaultComponent, vaultTLS *hlfv1alpha1.VaultComponent) *hlfv1alpha1.FabricPeer {

	return &hlfv1alpha1.FabricPeer{
		Spec: hlfv1alpha1.FabricPeerSpec{
			CredentialStore: store,
			MspID:           mspID,
			Storage: hlfv1alpha1.FabricPeerStorage{
				Peer: hlfv1alpha1.Storage{
					Size: peerStorage,
				},
			},
			Secret: hlfv1alpha1.Secret{
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

func TestValidatePeer(t *testing.T) {
	tests := []struct {
		name        string
		peer        *hlfv1alpha1.FabricPeer
		expectError bool
		errorMsg    string
	}{
		{
			name: "All validations pass (Kubernetes store)",
			peer: newTestPeer(
				hlfv1alpha1.CredentialStoreKubernetes,
				"Org1MSP",
				"ca.example.com",
				"peerAdmin",
				"peerAdminpw",
				"5Gi",
				nil,
				nil,
			),
			expectError: false,
		},
		{
			name: "Unsupported credential store",
			peer: newTestPeer(
				"unsupported-store",
				"Org1MSP",
				"ca.example.com",
				"peerAdmin",
				"peerAdminpw",
				"5Gi",
				nil,
				nil,
			),
			expectError: true,
			errorMsg:    "unsupported credential store",
		},
		{
			name: "Vault store missing component vault config",
			peer: newTestPeer(
				hlfv1alpha1.CredentialStoreVault,
				"Org1MSP",
				"",
				"",
				"",
				"5Gi",
				nil, // missing component vault
				&hlfv1alpha1.VaultComponent{},
			),
			expectError: true,
			errorMsg:    "vault configuration is required",
		},
		{
			name: "Vault store missing TLS vault config",
			peer: newTestPeer(
				hlfv1alpha1.CredentialStoreVault,
				"Org1MSP",
				"",
				"",
				"",
				"5Gi",
				&hlfv1alpha1.VaultComponent{}, // OK component vault
				nil,                           // missing TLS vault
			),
			expectError: true,
			errorMsg:    "vault TLS configuration is required",
		},
		{
			name: "Kubernetes store missing CA host",
			peer: newTestPeer(
				hlfv1alpha1.CredentialStoreKubernetes,
				"Org1MSP",
				"", // missing
				"peerAdmin",
				"peerAdminpw",
				"5Gi",
				nil,
				nil,
			),
			expectError: true,
			errorMsg:    "CA host is required",
		},
		{
			name: "Kubernetes store missing enrollment ID",
			peer: newTestPeer(
				hlfv1alpha1.CredentialStoreKubernetes,
				"Org1MSP",
				"ca.example.com",
				"", // missing
				"peerAdminpw",
				"5Gi",
				nil,
				nil,
			),
			expectError: true,
			errorMsg:    "enrollment ID is required",
		},
		{
			name: "Kubernetes store missing enrollment secret",
			peer: newTestPeer(
				hlfv1alpha1.CredentialStoreKubernetes,
				"Org1MSP",
				"ca.example.com",
				"peerAdmin",
				"", // missing
				"5Gi",
				nil,
				nil,
			),
			expectError: true,
			errorMsg:    "enrollment secret is required",
		},
		{
			name: "Missing MSP ID",
			peer: newTestPeer(
				hlfv1alpha1.CredentialStoreKubernetes,
				"", // missing
				"ca.example.com",
				"peerAdmin",
				"peerAdminpw",
				"5Gi",
				nil,
				nil,
			),
			expectError: true,
			errorMsg:    "MSP ID is required",
		},
		{
			name: "Missing peer storage size",
			peer: newTestPeer(
				hlfv1alpha1.CredentialStoreKubernetes,
				"Org1MSP",
				"ca.example.com",
				"peerAdmin",
				"peerAdminpw",
				"", // missing
				nil,
				nil,
			),
			expectError: true,
			errorMsg:    "peer storage size is required",
		},
		{
			name: "Multiple validation failures aggregated",
			peer: newTestPeer(
				hlfv1alpha1.CredentialStoreKubernetes,
				"",  // missing MSP
				"",  // missing CA host
				"",  // missing enroll ID
				"",  // missing enroll secret
				"",  // missing peer storage
				nil, // vaults nil
				nil,
			),
			expectError: true,
			errorMsg:    "validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v := &peer.ConfigValidator{}
			err := v.ValidatePeer(tt.peer)
			assertValidation(t, err, tt.expectError, tt.errorMsg)
		})
	}
}
