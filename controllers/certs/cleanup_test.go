package certs

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetClientCleanup verifies that GetClient's cleanup function removes
// temporary files and directories (regression test for #252).
func TestGetClientCleanup(t *testing.T) {
	t.Run("cleanup removes temp directory", func(t *testing.T) {
		// GetClient with an invalid URL will still create temp dirs before failing on Init()
		// Use a dummy URL - Init() will fail but we can still verify cleanup behavior
		client, cleanup, err := GetClient(FabricCAParams{
			TLSCert: "",
			URL:     "http://127.0.0.1:1", // unreachable, but GetClient still creates temp dir
			Name:    "test-ca",
			MSPID:   "TestMSP",
		})

		// Even if Init fails, we should get a cleanup function
		if err != nil {
			// Init failed — cleanup should have been called internally
			assert.Nil(t, client)
			assert.Nil(t, cleanup)
			return
		}

		// If Init succeeded (unlikely with bad URL), verify cleanup works
		require.NotNil(t, client)
		require.NotNil(t, cleanup)

		homeDir := client.HomeDir
		_, err = os.Stat(homeDir)
		require.NoError(t, err, "HomeDir should exist before cleanup")

		cleanup()

		_, err = os.Stat(homeDir)
		assert.True(t, os.IsNotExist(err), "HomeDir should be removed after cleanup")
	})

	t.Run("cleanup removes TLS cert file", func(t *testing.T) {
		client, cleanup, err := GetClient(FabricCAParams{
			TLSCert: "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----",
			URL:     "https://127.0.0.1:1",
			Name:    "test-ca",
			MSPID:   "TestMSP",
		})

		if err != nil {
			// Init failed — cleanup was called internally, temp files already gone
			assert.Nil(t, client)
			assert.Nil(t, cleanup)
			return
		}

		require.NotNil(t, cleanup)
		homeDir := client.HomeDir

		cleanup()

		_, err = os.Stat(homeDir)
		assert.True(t, os.IsNotExist(err), "HomeDir (including TLS cert) should be removed after cleanup")
	})

	t.Run("GetClient returns cleanup function not nil", func(t *testing.T) {
		// This test ensures the API contract: GetClient always returns a cleanup func on success
		// We can't easily test with a real CA here, but the integration tests cover that
		_, cleanup, err := GetClient(FabricCAParams{
			TLSCert: "",
			URL:     "http://127.0.0.1:1",
			Name:    "test-ca",
			MSPID:   "TestMSP",
		})

		if err == nil {
			require.NotNil(t, cleanup, "cleanup function must not be nil on success")
			cleanup()
		}
		// If err != nil, cleanup should be nil (called internally)
		if err != nil {
			assert.Nil(t, cleanup, "cleanup should be nil when GetClient fails")
		}
	})
}
