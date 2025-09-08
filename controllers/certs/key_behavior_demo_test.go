package certs

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/kfsoftware/hlf-operator/internal/github.com/hyperledger/fabric-ca/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKeyBehaviorDemonstration is a focused test that specifically demonstrates
// the key behaviors requested: 
// - Re-enrollment preserves the public key
// - Fresh enrollment generates new public keys
func TestKeyBehaviorDemonstration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()
	
	// Setup Fabric CA container
	caContainer, err := setupFabricCA(ctx)
	require.NoError(t, err, "Failed to setup Fabric CA container")
	defer func() {
		assert.NoError(t, caContainer.Terminate(ctx), "Failed to terminate container")
	}()

	t.Run("key behavior demonstration", func(t *testing.T) {
		// === PART 1: DEMONSTRATE RE-ENROLLMENT PRESERVES PUBLIC KEY ===
		
		// Register and enroll first user
		userA := "demo_user_a"
		secretA := "demo_secret_a"
		
		_, err := RegisterUser(RegisterUserRequest{
			TLSCert:      "",
			URL:          caContainer.URI,
			Name:         caName,
			MSPID:        mspID,
			EnrollID:     adminUser,
			EnrollSecret: adminPass,
			User:         userA,
			Secret:       secretA,
			Type:         "client",
			Attributes:   []api.Attribute{},
		})
		require.NoError(t, err, "Failed to register user A")

		// Initial enrollment of user A
		certA1, keyA1, _, err := EnrollUser(EnrollUserRequest{
			TLSCert:    "",
			URL:        caContainer.URI,
			Name:       caName,
			MSPID:      mspID,
			User:       userA,
			Secret:     secretA,
			Hosts:      []string{"localhost"},
			CN:         userA,
			Profile:    "",
			Attributes: []*api.AttributeRequest{},
		})
		require.NoError(t, err, "Failed to perform initial enrollment of user A")

		// Re-enrollment of user A (should preserve public key)
		certPEMA1 := fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n",
			base64.StdEncoding.EncodeToString(certA1.Raw))

		certA2, _, err := ReenrollUser(ReenrollUserRequest{
			EnrollID:   userA,
			TLSCert:    "",
			URL:        caContainer.URI,
			Name:       caName,
			MSPID:      mspID,
			Hosts:      []string{"localhost"},
			CN:         userA,
			Profile:    "",
			Attributes: []*api.AttributeRequest{},
		}, certPEMA1, keyA1)
		require.NoError(t, err, "Failed to re-enroll user A")

		// Extract public keys
		pubKeyA1 := getPublicKeyFromCert(certA1)
		pubKeyA2 := getPublicKeyFromCert(certA2)

		// ✅ CRITICAL ASSERTION: Re-enrollment should preserve public key
		assert.True(t, compareECDSAPublicKeys(pubKeyA1, pubKeyA2),
			"❌ FAILED: Re-enrollment should preserve the same public key\n"+
				"Initial cert public key: %v\n"+
				"Re-enrolled cert public key: %v",
			pubKeyA1, pubKeyA2)
		
		fmt.Printf("✅ PASS: Re-enrollment preserved public key for user %s\n", userA)

		// === PART 2: DEMONSTRATE FRESH ENROLLMENT GENERATES NEW PUBLIC KEYS ===
		
		// Register and enroll second user (fresh enrollment)
		userB := "demo_user_b"
		secretB := "demo_secret_b"
		
		_, err = RegisterUser(RegisterUserRequest{
			TLSCert:      "",
			URL:          caContainer.URI,
			Name:         caName,
			MSPID:        mspID,
			EnrollID:     adminUser,
			EnrollSecret: adminPass,
			User:         userB,
			Secret:       secretB,
			Type:         "client",
			Attributes:   []api.Attribute{},
		})
		require.NoError(t, err, "Failed to register user B")

		// Fresh enrollment of user B
		certB1, _, _, err := EnrollUser(EnrollUserRequest{
			TLSCert:    "",
			URL:        caContainer.URI,
			Name:       caName,
			MSPID:      mspID,
			User:       userB,
			Secret:     secretB,
			Hosts:      []string{"localhost"},
			CN:         userB,
			Profile:    "",
			Attributes: []*api.AttributeRequest{},
		})
		require.NoError(t, err, "Failed to perform fresh enrollment of user B")

		// Extract user B's public key
		pubKeyB1 := getPublicKeyFromCert(certB1)

		// ✅ CRITICAL ASSERTION: Fresh enrollment should generate different public key
		assert.False(t, compareECDSAPublicKeys(pubKeyA1, pubKeyB1),
			"❌ FAILED: Fresh enrollment should generate a different public key\n"+
				"User A public key: %v\n"+
				"User B public key: %v",
			pubKeyA1, pubKeyB1)
		
		fmt.Printf("✅ PASS: Fresh enrollment generated new public key for user %s\n", userB)

		// === PART 3: DEMONSTRATE REPEATED FRESH ENROLLMENTS GENERATE NEW KEYS ===
		
		// Second enrollment of user A (should generate new key since it's a fresh enrollment)
		certA3, _, _, err := EnrollUser(EnrollUserRequest{
			TLSCert:    "",
			URL:        caContainer.URI,
			Name:       caName,
			MSPID:      mspID,
			User:       userA,
			Secret:     secretA,
			Hosts:      []string{"localhost"},
			CN:         userA,
			Profile:    "",
			Attributes: []*api.AttributeRequest{},
		})
		require.NoError(t, err, "Failed to perform second fresh enrollment of user A")

		pubKeyA3 := getPublicKeyFromCert(certA3)

		// ✅ CRITICAL ASSERTION: Another fresh enrollment should generate yet another different key
		assert.False(t, compareECDSAPublicKeys(pubKeyA1, pubKeyA3),
			"❌ FAILED: Second fresh enrollment should generate a different key from first enrollment")
		assert.False(t, compareECDSAPublicKeys(pubKeyA2, pubKeyA3),
			"❌ FAILED: Second fresh enrollment should generate a different key from re-enrollment")
		
		fmt.Printf("✅ PASS: Second fresh enrollment of user %s generated a new public key\n", userA)

		// === SUMMARY OUTPUT ===
		fmt.Printf("\n🎯 KEY BEHAVIOR DEMONSTRATION COMPLETE:\n")
		fmt.Printf("   - Re-enrollment: PRESERVES public key ✅\n")
		fmt.Printf("   - Fresh enrollment: GENERATES new public key ✅\n")
		fmt.Printf("   - Multiple fresh enrollments: Each gets UNIQUE public key ✅\n")
	})
}