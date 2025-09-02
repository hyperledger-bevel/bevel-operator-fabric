package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/kfsoftware/hlf-operator/internal/github.com/hyperledger/fabric-ca/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	// Hyperledger Fabric CA Docker image
	fabricCAImage = "hyperledger/fabric-ca:1.5.15"

	// CA server configuration
	caPort    = "7054"
	adminUser = "admin"
	adminPass = "adminpw"
	caName    = "ca.example.com"
	mspID     = "ExampleMSP"

	// Test user credentials
	testUser   = "testuser"
	testSecret = "testpass"
)

// FabricCAContainer wraps the testcontainer and provides methods to interact with the Fabric CA
type FabricCAContainer struct {
	testcontainers.Container
	URI     string
	TLSCert string
}

// setupFabricCA starts a Fabric CA container and returns connection details
func setupFabricCA(ctx context.Context) (*FabricCAContainer, error) {
	// Start the Fabric CA container with minimal configuration
	req := testcontainers.ContainerRequest{
		Image:        fabricCAImage,
		ExposedPorts: []string{caPort + "/tcp"},
		WaitingFor:   wait.ForListeningPort(caPort).WithStartupTimeout(120 * time.Second),
		Cmd: []string{
			"sh", "-c",
			fmt.Sprintf("fabric-ca-server start -b %s:%s --ca.name %s --tls.enabled=false",
				adminUser, adminPass, caName),
		},
		Env: map[string]string{
			"FABRIC_CA_SERVER_CA_NAME":     caName,
			"FABRIC_CA_SERVER_TLS_ENABLED": "false",
			"FABRIC_CA_SERVER_PORT":        caPort,
		},
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	// Get the mapped port
	mappedPort, err := container.MappedPort(ctx, caPort)
	if err != nil {
		return nil, fmt.Errorf("failed to get mapped port: %w", err)
	}

	// Get the host
	host, err := container.Host(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get host: %w", err)
	}

	uri := fmt.Sprintf("http://%s:%s", host, mappedPort.Port())

	// Wait a bit more for the CA to be fully ready
	time.Sleep(5 * time.Second)

	return &FabricCAContainer{
		Container: container,
		URI:       uri,
		TLSCert:   "", // No TLS for this test setup
	}, nil
}

// Helper function to compare ECDSA public keys
func compareECDSAPublicKeys(key1, key2 *ecdsa.PublicKey) bool {
	if key1 == nil || key2 == nil {
		return key1 == key2
	}
	return key1.X.Cmp(key2.X) == 0 && key1.Y.Cmp(key2.Y) == 0
}

// Helper function to extract public key from certificate
func getPublicKeyFromCert(cert *x509.Certificate) *ecdsa.PublicKey {
	if ecdsaKey, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		return ecdsaKey
	}
	return nil
}

func TestMain(m *testing.M) {
	// Run tests
	code := m.Run()
	os.Exit(code)
}

func TestEnrollUser(t *testing.T) {
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

	t.Run("successful enrollment", func(t *testing.T) {
		// First, register a new user
		secret, err := RegisterUser(RegisterUserRequest{
			TLSCert:      "",
			URL:          caContainer.URI,
			Name:         caName,
			MSPID:        mspID,
			EnrollID:     adminUser,
			EnrollSecret: adminPass,
			User:         testUser,
			Secret:       testSecret,
			Type:         "client",
			Attributes:   []api.Attribute{},
		})
		require.NoError(t, err, "Failed to register user")
		assert.Equal(t, testSecret, secret, "Secret should match")

		// Now enroll the user
		userCert, userKey, rootCert, err := EnrollUser(EnrollUserRequest{
			TLSCert:    "",
			URL:        caContainer.URI,
			Name:       caName,
			MSPID:      mspID,
			User:       testUser,
			Secret:     testSecret,
			Hosts:      []string{"localhost", "example.com"},
			CN:         testUser,
			Profile:    "",
			Attributes: []*api.AttributeRequest{},
		})
		require.NoError(t, err, "Failed to enroll user")

		// Validate the returned certificates
		assert.NotNil(t, userCert, "User certificate should not be nil")
		assert.NotNil(t, userKey, "User private key should not be nil")
		assert.NotNil(t, rootCert, "Root certificate should not be nil")

		// Validate certificate properties
		assert.Equal(t, testUser, userCert.Subject.CommonName, "Certificate CN should match")
		assert.True(t, userCert.NotAfter.After(time.Now()), "Certificate should not be expired")
		assert.True(t, userCert.NotBefore.Before(time.Now()), "Certificate should be valid now")

		// Validate the private key
		assert.IsType(t, &ecdsa.PrivateKey{}, userKey, "Private key should be ECDSA")

		// Validate root certificate (the CA might use its default name)
		assert.NotEmpty(t, rootCert.Subject.CommonName, "Root certificate CN should not be empty")
	})

	t.Run("multiple enrollments have different public keys", func(t *testing.T) {
		// Register a second user
		secondUser := "testuser2"
		secondSecret := "testpass2"
		secret, err := RegisterUser(RegisterUserRequest{
			TLSCert:      "",
			URL:          caContainer.URI,
			Name:         caName,
			MSPID:        mspID,
			EnrollID:     adminUser,
			EnrollSecret: adminPass,
			User:         secondUser,
			Secret:       secondSecret,
			Type:         "client",
			Attributes:   []api.Attribute{},
		})
		require.NoError(t, err, "Failed to register second user")
		assert.Equal(t, secondSecret, secret, "Second user secret should match")

		// Enroll the second user
		userCert2, userKey2, rootCert2, err := EnrollUser(EnrollUserRequest{
			TLSCert:    "",
			URL:        caContainer.URI,
			Name:       caName,
			MSPID:      mspID,
			User:       secondUser,
			Secret:     secondSecret,
			Hosts:      []string{"localhost", "example2.com"},
			CN:         secondUser,
			Profile:    "",
			Attributes: []*api.AttributeRequest{},
		})
		require.NoError(t, err, "Failed to enroll second user")

		// Get the first user's certificates (from previous test)
		// We need to enroll the first user again to compare
		userCert1, userKey1, _, err := EnrollUser(EnrollUserRequest{
			TLSCert:    "",
			URL:        caContainer.URI,
			Name:       caName,
			MSPID:      mspID,
			User:       testUser,
			Secret:     testSecret,
			Hosts:      []string{"localhost", "example.com"},
			CN:         testUser,
			Profile:    "",
			Attributes: []*api.AttributeRequest{},
		})
		require.NoError(t, err, "Failed to re-enroll first user")

		// CRITICAL: Different enrollments should have different public keys
		pubKey1 := getPublicKeyFromCert(userCert1)
		pubKey2 := getPublicKeyFromCert(userCert2)
		assert.False(t, compareECDSAPublicKeys(pubKey1, pubKey2),
			"Different enrollments should have different public keys")

		// Also verify private keys are different
		assert.NotEqual(t, userKey1.D.Cmp(userKey2.D), 0,
			"Different enrollments should have different private keys")

		// Both should be valid certificates from the same CA
		assert.NotNil(t, userCert1)
		assert.NotNil(t, userCert2)
		assert.Equal(t, rootCert2.SerialNumber, rootCert2.SerialNumber,
			"Both should have the same root certificate")
	})

	t.Run("enrollment with invalid credentials", func(t *testing.T) {
		_, _, _, err := EnrollUser(EnrollUserRequest{
			TLSCert:    "",
			URL:        caContainer.URI,
			Name:       caName,
			MSPID:      mspID,
			User:       "nonexistent",
			Secret:     "wrongpass",
			Hosts:      []string{"localhost"},
			CN:         "nonexistent",
			Profile:    "",
			Attributes: []*api.AttributeRequest{},
		})
		assert.Error(t, err, "Enrollment with invalid credentials should fail")
	})
}

func TestReenrollUser(t *testing.T) {
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

	// First register and enroll a user
	secret, err := RegisterUser(RegisterUserRequest{
		TLSCert:      "",
		URL:          caContainer.URI,
		Name:         caName,
		MSPID:        mspID,
		EnrollID:     adminUser,
		EnrollSecret: adminPass,
		User:         testUser,
		Secret:       testSecret,
		Type:         "client",
		Attributes:   []api.Attribute{},
	})
	require.NoError(t, err, "Failed to register user")
	require.Equal(t, testSecret, secret, "Secret should match")

	// Initial enrollment
	initialCert, initialKey, initialRootCert, err := EnrollUser(EnrollUserRequest{
		TLSCert:    "",
		URL:        caContainer.URI,
		Name:       caName,
		MSPID:      mspID,
		User:       testUser,
		Secret:     testSecret,
		Hosts:      []string{"localhost", "example.com"},
		CN:         testUser,
		Profile:    "",
		Attributes: []*api.AttributeRequest{},
	})
	require.NoError(t, err, "Failed to perform initial enrollment")

	t.Run("successful reenrollment", func(t *testing.T) {
		// Convert certificate to PEM format for reenrollment
		certPEM := fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n",
			base64.StdEncoding.EncodeToString(initialCert.Raw))

		// Perform reenrollment
		reenrolledCert, reenrolledRootCert, err := ReenrollUser(ReenrollUserRequest{
			EnrollID:   testUser,
			TLSCert:    "",
			URL:        caContainer.URI,
			Name:       caName,
			MSPID:      mspID,
			Hosts:      []string{"localhost", "reenroll.example.com"},
			CN:         testUser,
			Profile:    "",
			Attributes: []*api.AttributeRequest{},
		}, certPEM, initialKey)

		require.NoError(t, err, "Reenrollment should succeed")

		// Validate the reenrolled certificates
		assert.NotNil(t, reenrolledCert, "Reenrolled certificate should not be nil")
		assert.NotNil(t, reenrolledRootCert, "Reenrolled root certificate should not be nil")

		// The reenrolled certificate should be different from the initial one
		assert.NotEqual(t, initialCert.SerialNumber, reenrolledCert.SerialNumber,
			"Reenrolled certificate should have different serial number")

		// But should have the same subject
		assert.Equal(t, initialCert.Subject.CommonName, reenrolledCert.Subject.CommonName,
			"Reenrolled certificate should have same CN")

		// CRITICAL: When reenrolling, the public key should remain the same
		initialPubKey := getPublicKeyFromCert(initialCert)
		reenrolledPubKey := getPublicKeyFromCert(reenrolledCert)
		assert.True(t, compareECDSAPublicKeys(initialPubKey, reenrolledPubKey),
			"Reenrolled certificate should have the same public key as the original")

		// Both certificates should be valid
		assert.True(t, reenrolledCert.NotAfter.After(time.Now()), "Reenrolled certificate should not be expired")
		assert.True(t, reenrolledCert.NotBefore.Before(time.Now()), "Reenrolled certificate should be valid now")

		// Root certificates should be the same
		assert.Equal(t, initialRootCert.SerialNumber, reenrolledRootCert.SerialNumber,
			"Root certificate should be the same")
	})

	t.Run("reenrollment with invalid certificate", func(t *testing.T) {
		invalidCertPEM := `-----BEGIN CERTIFICATE-----
MIIBdTCCARugAwIBAgIBATAKBggqhkjOPQQDAjAYMRYwFAYDVQQDEw1jYS5leGFt
cGxlLmNvbTAeFw0yMzEyMDEwMDAwMDBaFw0yNDEyMDEwMDAwMDBaMBgxFjAUBgNV
BAMTDWNhLmV4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
-----END CERTIFICATE-----`

		_, _, err := ReenrollUser(ReenrollUserRequest{
			EnrollID:   testUser,
			TLSCert:    "",
			URL:        caContainer.URI,
			Name:       caName,
			MSPID:      mspID,
			Hosts:      []string{"localhost"},
			CN:         testUser,
			Profile:    "",
			Attributes: []*api.AttributeRequest{},
		}, invalidCertPEM, initialKey)

		assert.Error(t, err, "Reenrollment with invalid certificate should fail")
	})
}

func TestEnrollThenReenroll(t *testing.T) {
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

	// Test user for this integration test
	integrationUser := "integration_user"
	integrationSecret := "integration_pass"

	t.Run("complete enroll and reenroll workflow", func(t *testing.T) {
		// Step 1: Register user
		secret, err := RegisterUser(RegisterUserRequest{
			TLSCert:      "",
			URL:          caContainer.URI,
			Name:         caName,
			MSPID:        mspID,
			EnrollID:     adminUser,
			EnrollSecret: adminPass,
			User:         integrationUser,
			Secret:       integrationSecret,
			Type:         "client",
			Attributes:   []api.Attribute{},
		})
		require.NoError(t, err, "User registration should succeed")
		assert.Equal(t, integrationSecret, secret, "Secret should match")

		// Step 2: Initial enrollment
		userCert, userKey, rootCert, err := EnrollUser(EnrollUserRequest{
			TLSCert:    "",
			URL:        caContainer.URI,
			Name:       caName,
			MSPID:      mspID,
			User:       integrationUser,
			Secret:     integrationSecret,
			Hosts:      []string{"localhost", "initial.example.com"},
			CN:         integrationUser,
			Profile:    "",
			Attributes: []*api.AttributeRequest{},
		})
		require.NoError(t, err, "Initial enrollment should succeed")

		// Validate initial enrollment results
		assert.Equal(t, integrationUser, userCert.Subject.CommonName)
		assert.IsType(t, &ecdsa.PrivateKey{}, userKey)
		assert.NotNil(t, rootCert)

		// Step 3: Reenrollment with the same key
		certPEM := fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n",
			base64.StdEncoding.EncodeToString(userCert.Raw))

		reenrolledCert, reenrolledRootCert, err := ReenrollUser(ReenrollUserRequest{
			EnrollID:   integrationUser,
			TLSCert:    "",
			URL:        caContainer.URI,
			Name:       caName,
			MSPID:      mspID,
			Hosts:      []string{"localhost", "reenroll.example.com", "updated.example.com"},
			CN:         integrationUser,
			Profile:    "",
			Attributes: []*api.AttributeRequest{},
		}, certPEM, userKey)

		require.NoError(t, err, "Reenrollment should succeed")

		// Validate reenrollment results
		assert.Equal(t, integrationUser, reenrolledCert.Subject.CommonName)
		assert.NotEqual(t, userCert.SerialNumber, reenrolledCert.SerialNumber,
			"Reenrolled cert should have different serial number")
		assert.Equal(t, rootCert.SerialNumber, reenrolledRootCert.SerialNumber,
			"Root cert should remain the same")

		// Step 4: Validate public key behavior
		initialPubKey := getPublicKeyFromCert(userCert)
		reenrolledPubKey := getPublicKeyFromCert(reenrolledCert)

		// CRITICAL: Reenrollment should preserve the public key
		assert.True(t, compareECDSAPublicKeys(initialPubKey, reenrolledPubKey),
			"Reenrollment should preserve the same public key")

		// Step 5: Test fresh enrollment to show key changes
		freshUser := "fresh_user"
		freshSecret := "fresh_pass"

		// Register fresh user
		_, err = RegisterUser(RegisterUserRequest{
			TLSCert:      "",
			URL:          caContainer.URI,
			Name:         caName,
			MSPID:        mspID,
			EnrollID:     adminUser,
			EnrollSecret: adminPass,
			User:         freshUser,
			Secret:       freshSecret,
			Type:         "client",
			Attributes:   []api.Attribute{},
		})
		require.NoError(t, err, "Fresh user registration should succeed")

		// Enroll fresh user
		freshCert, _, _, err := EnrollUser(EnrollUserRequest{
			TLSCert:    "",
			URL:        caContainer.URI,
			Name:       caName,
			MSPID:      mspID,
			User:       freshUser,
			Secret:     freshSecret,
			Hosts:      []string{"localhost", "fresh.example.com"},
			CN:         freshUser,
			Profile:    "",
			Attributes: []*api.AttributeRequest{},
		})
		require.NoError(t, err, "Fresh user enrollment should succeed")

		freshPubKey := getPublicKeyFromCert(freshCert)

		// CRITICAL: Fresh enrollment should generate a different public key
		assert.False(t, compareECDSAPublicKeys(initialPubKey, freshPubKey),
			"Fresh enrollment should generate a different public key")
		assert.False(t, compareECDSAPublicKeys(reenrolledPubKey, freshPubKey),
			"Fresh enrollment should have different key from reenrolled cert")

		// Step 6: Verify certificates are valid and come from the same CA
		assert.True(t, userCert.NotAfter.After(time.Now()), "Initial certificate should be valid")
		assert.True(t, reenrolledCert.NotAfter.After(time.Now()), "Reenrolled certificate should be valid")
		assert.True(t, freshCert.NotAfter.After(time.Now()), "Fresh certificate should be valid")

		// All certificates should have the same issuer
		assert.Equal(t, userCert.Issuer.String(), reenrolledCert.Issuer.String(),
			"Initial and reenrolled certificates should have same issuer")
		assert.Equal(t, userCert.Issuer.String(), freshCert.Issuer.String(),
			"All certificates should have same issuer")

		// All certificates should be verifiable against the root certificate
		roots := x509.NewCertPool()
		roots.AddCert(rootCert)

		_, err = userCert.Verify(x509.VerifyOptions{Roots: roots})
		assert.NoError(t, err, "Initial certificate should verify against root")

		_, err = reenrolledCert.Verify(x509.VerifyOptions{Roots: roots})
		assert.NoError(t, err, "Reenrolled certificate should verify against root")

		_, err = freshCert.Verify(x509.VerifyOptions{Roots: roots})
		assert.NoError(t, err, "Fresh certificate should verify against root")
	})
}

func TestGetCAInfo(t *testing.T) {
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

	t.Run("successful CA info retrieval", func(t *testing.T) {
		caInfo, err := GetCAInfo(GetCAInfoRequest{
			TLSCert: "",
			URL:     caContainer.URI,
			Name:    caName,
			MSPID:   mspID,
		})

		require.NoError(t, err, "GetCAInfo should succeed")
		assert.NotNil(t, caInfo, "CA info should not be nil")
		assert.NotEmpty(t, caInfo.CAName, "CA name should not be empty")
		assert.NotEmpty(t, caInfo.CAChain, "CA chain should not be empty")
		assert.Equal(t, caName, caInfo.CAName, "CA name should match")
	})

	t.Run("CA info with invalid URL", func(t *testing.T) {
		_, err := GetCAInfo(GetCAInfoRequest{
			TLSCert: "",
			URL:     "http://localhost:99999",
			Name:    caName,
			MSPID:   mspID,
		})

		assert.Error(t, err, "GetCAInfo with invalid URL should fail")
	})
}
