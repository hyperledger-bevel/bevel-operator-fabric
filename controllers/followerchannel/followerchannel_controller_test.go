package followerchannel

import (
	"testing"

	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/stretchr/testify/assert"
)

func newTestFollowerChannel(
	name string,
	mspID string,
	secretName string,
	secretKey string,
	peers []hlfv1alpha1.FabricFollowerChannelPeer,
	externalPeers []hlfv1alpha1.FabricFollowerChannelExternalPeer,
) *hlfv1alpha1.FabricFollowerChannel {
	return &hlfv1alpha1.FabricFollowerChannel{
		Spec: hlfv1alpha1.FabricFollowerChannelSpec{
			Name:  name,
			MSPID: mspID,
			HLFIdentity: hlfv1alpha1.HLFIdentity{
				SecretName: secretName,
				SecretKey:  secretKey,
			},
			PeersToJoin:         peers,
			ExternalPeersToJoin: externalPeers,
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

func TestValidateFollowerChannelConfig(t *testing.T) {
	tests := []struct {
		name        string
		channel     *hlfv1alpha1.FabricFollowerChannel
		expectError bool
		errorMsg    string
	}{
		{
			name: "All validations pass",
			channel: newTestFollowerChannel(
				"mychannel",
				"Org1MSP",
				"my-secret",
				"user.yaml",
				[]hlfv1alpha1.FabricFollowerChannelPeer{
					{Name: "peer0", Namespace: "default"},
				},
				nil,
			),
			expectError: false,
		},
		{
			name: "Empty channel name",
			channel: newTestFollowerChannel(
				"",
				"Org1MSP",
				"my-secret",
				"user.yaml",
				[]hlfv1alpha1.FabricFollowerChannelPeer{
					{Name: "peer0", Namespace: "default"},
				},
				nil,
			),
			expectError: true,
			errorMsg:    "channel name cannot be empty",
		},
		{
			name: "Empty MSPID",
			channel: newTestFollowerChannel(
				"mychannel",
				"",
				"my-secret",
				"user.yaml",
				[]hlfv1alpha1.FabricFollowerChannelPeer{
					{Name: "peer0", Namespace: "default"},
				},
				nil,
			),
			expectError: true,
			errorMsg:    "MSPID cannot be empty",
		},
		{
			name: "Empty HLF identity secret name",
			channel: newTestFollowerChannel(
				"mychannel",
				"Org1MSP",
				"",
				"user.yaml",
				[]hlfv1alpha1.FabricFollowerChannelPeer{
					{Name: "peer0", Namespace: "default"},
				},
				nil,
			),
			expectError: true,
			errorMsg:    "HLF identity secret name cannot be empty",
		},
		{
			name: "Empty HLF identity secret key",
			channel: newTestFollowerChannel(
				"mychannel",
				"Org1MSP",
				"my-secret",
				"",
				[]hlfv1alpha1.FabricFollowerChannelPeer{
					{Name: "peer0", Namespace: "default"},
				},
				nil,
			),
			expectError: true,
			errorMsg:    "HLF identity secret key cannot be empty",
		},
		{
			name: "No peers specified",
			channel: newTestFollowerChannel(
				"mychannel",
				"Org1MSP",
				"my-secret",
				"user.yaml",
				nil,
				nil,
			),
			expectError: true,
			errorMsg:    "at least one peer must be specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := &FabricFollowerChannelReconciler{}
			err := r.validateFollowerChannelConfig(tt.channel)
			assertValidation(t, err, tt.expectError, tt.errorMsg)
		})
	}
}
