package mainchannel_test

import (
	"testing"

	"github.com/kfsoftware/hlf-operator/controllers/mainchannel"
	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/stretchr/testify/assert"
)

func newTestMainChannel(
	name string,
	ordererOrgs []hlfv1alpha1.FabricMainChannelOrdererOrganization,
	adminOrdererOrgs []hlfv1alpha1.FabricMainChannelAdminOrdererOrganizationSpec,
	peerOrgs []hlfv1alpha1.FabricMainChannelPeerOrganization,
	identities map[string]hlfv1alpha1.FabricMainChannelIdentity,
) *hlfv1alpha1.FabricMainChannel {
	return &hlfv1alpha1.FabricMainChannel{
		Spec: hlfv1alpha1.FabricMainChannelSpec{
			Name:                      name,
			OrdererOrganizations:      ordererOrgs,
			AdminOrdererOrganizations: adminOrdererOrgs,
			PeerOrganizations:         peerOrgs,
			Identities:                identities,
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

func TestValidateMainChannelConfig(t *testing.T) {
	validOrdererOrgs := []hlfv1alpha1.FabricMainChannelOrdererOrganization{
		{MSPID: "OrdererMSP"},
	}
	validAdminOrdererOrgs := []hlfv1alpha1.FabricMainChannelAdminOrdererOrganizationSpec{
		{MSPID: "OrdererMSP"},
	}
	validPeerOrgs := []hlfv1alpha1.FabricMainChannelPeerOrganization{
		{MSPID: "Org1MSP"},
	}
	validIdentities := map[string]hlfv1alpha1.FabricMainChannelIdentity{
		"OrdererMSP-sign": {
			SecretNamespace: "default",
			SecretName:      "orderer-identity",
			SecretKey:       "identity.yaml",
		},
	}

	tests := []struct {
		name        string
		channel     *hlfv1alpha1.FabricMainChannel
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid configuration",
			channel:     newTestMainChannel("mychannel", validOrdererOrgs, validAdminOrdererOrgs, validPeerOrgs, validIdentities),
			expectError: false,
		},
		{
			name:        "empty channel name",
			channel:     newTestMainChannel("", validOrdererOrgs, validAdminOrdererOrgs, validPeerOrgs, validIdentities),
			expectError: true,
			errorMsg:    "channel name cannot be empty",
		},
		{
			name:        "missing orderer organizations",
			channel:     newTestMainChannel("mychannel", nil, validAdminOrdererOrgs, validPeerOrgs, validIdentities),
			expectError: true,
			errorMsg:    "at least one orderer organization must be specified",
		},
		{
			name: "missing admin orderer organizations",
			channel: newTestMainChannel("mychannel", validOrdererOrgs, nil, validPeerOrgs, map[string]hlfv1alpha1.FabricMainChannelIdentity{
				"OrdererMSP-sign": {
					SecretNamespace: "default",
					SecretName:      "orderer-identity",
					SecretKey:       "identity.yaml",
				},
			}),
			expectError: true,
			errorMsg:    "at least one admin orderer organization must be specified",
		},
		{
			name: "admin orderer org not in orderer organizations list",
			channel: newTestMainChannel(
				"mychannel",
				validOrdererOrgs,
				[]hlfv1alpha1.FabricMainChannelAdminOrdererOrganizationSpec{
					{MSPID: "UnknownMSP"},
				},
				validPeerOrgs,
				map[string]hlfv1alpha1.FabricMainChannelIdentity{
					"UnknownMSP-sign": {
						SecretNamespace: "default",
						SecretName:      "unknown-identity",
						SecretKey:       "identity.yaml",
					},
				},
			),
			expectError: true,
			errorMsg:    "admin orderer organization UnknownMSP not found in orderer organizations",
		},
		{
			name: "missing identity for admin orderer organization",
			channel: newTestMainChannel(
				"mychannel",
				validOrdererOrgs,
				validAdminOrdererOrgs,
				validPeerOrgs,
				map[string]hlfv1alpha1.FabricMainChannelIdentity{},
			),
			expectError: true,
			errorMsg:    "identity not found for admin orderer organization OrdererMSP",
		},
		{
			name: "identity found with MSPID key instead of MSPID-sign",
			channel: newTestMainChannel(
				"mychannel",
				validOrdererOrgs,
				validAdminOrdererOrgs,
				validPeerOrgs,
				map[string]hlfv1alpha1.FabricMainChannelIdentity{
					"OrdererMSP": {
						SecretNamespace: "default",
						SecretName:      "orderer-identity",
						SecretKey:       "identity.yaml",
					},
				},
			),
			expectError: false,
		},
		{
			name: "multiple orderer orgs with valid admin subset",
			channel: newTestMainChannel(
				"mychannel",
				[]hlfv1alpha1.FabricMainChannelOrdererOrganization{
					{MSPID: "Orderer1MSP"},
					{MSPID: "Orderer2MSP"},
				},
				[]hlfv1alpha1.FabricMainChannelAdminOrdererOrganizationSpec{
					{MSPID: "Orderer1MSP"},
				},
				validPeerOrgs,
				map[string]hlfv1alpha1.FabricMainChannelIdentity{
					"Orderer1MSP-sign": {
						SecretNamespace: "default",
						SecretName:      "orderer1-identity",
						SecretKey:       "identity.yaml",
					},
				},
			),
			expectError: false,
		},
		{
			name: "multiple admin orgs one missing from orderer organizations",
			channel: newTestMainChannel(
				"mychannel",
				[]hlfv1alpha1.FabricMainChannelOrdererOrganization{
					{MSPID: "Orderer1MSP"},
				},
				[]hlfv1alpha1.FabricMainChannelAdminOrdererOrganizationSpec{
					{MSPID: "Orderer1MSP"},
					{MSPID: "Orderer2MSP"},
				},
				validPeerOrgs,
				map[string]hlfv1alpha1.FabricMainChannelIdentity{
					"Orderer1MSP-sign": {
						SecretNamespace: "default",
						SecretName:      "orderer1-identity",
						SecretKey:       "identity.yaml",
					},
					"Orderer2MSP-sign": {
						SecretNamespace: "default",
						SecretName:      "orderer2-identity",
						SecretKey:       "identity.yaml",
					},
				},
			),
			expectError: true,
			errorMsg:    "admin orderer organization Orderer2MSP not found in orderer organizations",
		},
		{
			name: "multiple admin orgs one missing identity",
			channel: newTestMainChannel(
				"mychannel",
				[]hlfv1alpha1.FabricMainChannelOrdererOrganization{
					{MSPID: "Orderer1MSP"},
					{MSPID: "Orderer2MSP"},
				},
				[]hlfv1alpha1.FabricMainChannelAdminOrdererOrganizationSpec{
					{MSPID: "Orderer1MSP"},
					{MSPID: "Orderer2MSP"},
				},
				validPeerOrgs,
				map[string]hlfv1alpha1.FabricMainChannelIdentity{
					"Orderer1MSP-sign": {
						SecretNamespace: "default",
						SecretName:      "orderer1-identity",
						SecretKey:       "identity.yaml",
					},
				},
			),
			expectError: true,
			errorMsg:    "identity not found for admin orderer organization Orderer2MSP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v := &mainchannel.ConfigValidator{}
			err := v.ValidateMainChannel(tt.channel)
			assertValidation(t, err, tt.expectError, tt.errorMsg)
		})
	}
}
