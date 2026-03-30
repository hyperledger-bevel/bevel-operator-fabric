package install

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateChaincodePackage(t *testing.T) {
	opts := ChaincodePackageOptions{
		ChaincodeName:  "mycc",
		ChaincodeLabel: "mycc_1.0",
		Address:        "chaincode-service:7052",
	}

	filePath, err := generateChaincodePackage(opts)
	require.NoError(t, err)
	defer os.Remove(filePath)

	// The returned path is non-empty
	assert.NotEmpty(t, filePath)

	// The file exists on disk
	info, err := os.Stat(filePath)
	require.NoError(t, err)
	assert.True(t, info.Size() > 0)

	// Open and verify it is a valid tar.gz
	f, err := os.Open(filePath)
	require.NoError(t, err)
	defer f.Close()

	gr, err := gzip.NewReader(f)
	require.NoError(t, err)
	defer gr.Close()

	tr := tar.NewReader(gr)

	var foundMetadata, foundCodeTarGz bool
	var metadataBytes []byte
	var codeTarGzBytes []byte

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)

		switch hdr.Name {
		case "metadata.json":
			foundMetadata = true
			metadataBytes, err = io.ReadAll(tr)
			require.NoError(t, err)
		case "code.tar.gz":
			foundCodeTarGz = true
			codeTarGzBytes, err = io.ReadAll(tr)
			require.NoError(t, err)
		}
	}

	// metadata.json must be present with correct values
	assert.True(t, foundMetadata, "metadata.json not found in archive")
	var meta Metadata
	err = json.Unmarshal(metadataBytes, &meta)
	require.NoError(t, err)
	assert.Equal(t, "ccaas", meta.Type)
	assert.Equal(t, "mycc_1.0", meta.Label)

	// code.tar.gz must be present
	assert.True(t, foundCodeTarGz, "code.tar.gz not found in archive")

	// Unpack code.tar.gz and verify connection.json
	codeTarGzReader, err := gzip.NewReader(bytesReader(codeTarGzBytes))
	require.NoError(t, err)
	defer codeTarGzReader.Close()

	codeTar := tar.NewReader(codeTarGzReader)

	var foundConnection bool
	var connectionBytes []byte

	for {
		hdr, err := codeTar.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)

		if hdr.Name == "connection.json" {
			foundConnection = true
			connectionBytes, err = io.ReadAll(codeTar)
			require.NoError(t, err)
		}
	}

	assert.True(t, foundConnection, "connection.json not found inside code.tar.gz")
	var conn Connection
	err = json.Unmarshal(connectionBytes, &conn)
	require.NoError(t, err)
	assert.Equal(t, "chaincode-service:7052", conn.Address)
	assert.Equal(t, "10s", conn.DialTimeout)
	assert.False(t, conn.TLSRequired)
}

func TestGenerateChaincodePackageEdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		opts          ChaincodePackageOptions
		expectedLabel string
		expectedAddr  string
	}{
		{
			name: "Empty label produces package with empty label in metadata",
			opts: ChaincodePackageOptions{
				ChaincodeName:  "cc",
				ChaincodeLabel: "",
				Address:        "host:7052",
			},
			expectedLabel: "",
			expectedAddr:  "host:7052",
		},
		{
			name: "Empty address produces package with empty address in connection",
			opts: ChaincodePackageOptions{
				ChaincodeName:  "cc",
				ChaincodeLabel: "cc_v1",
				Address:        "",
			},
			expectedLabel: "cc_v1",
			expectedAddr:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			filePath, err := generateChaincodePackage(tt.opts)
			require.NoError(t, err)
			defer os.Remove(filePath)

			meta, conn := extractPackageContents(t, filePath)

			assert.Equal(t, "ccaas", meta.Type)
			assert.Equal(t, tt.expectedLabel, meta.Label)
			assert.Equal(t, tt.expectedAddr, conn.Address)
			assert.Equal(t, "10s", conn.DialTimeout)
		})
	}
}

// extractPackageContents opens a chaincode .tgz, reads metadata.json and
// unpacks code.tar.gz to read connection.json, returning both decoded structs.
func extractPackageContents(t *testing.T, filePath string) (Metadata, Connection) {
	t.Helper()

	f, err := os.Open(filePath)
	require.NoError(t, err)
	defer f.Close()

	gr, err := gzip.NewReader(f)
	require.NoError(t, err)
	defer gr.Close()

	tr := tar.NewReader(gr)

	var metadataBytes, codeTarGzBytes []byte

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)

		switch hdr.Name {
		case "metadata.json":
			metadataBytes, err = io.ReadAll(tr)
			require.NoError(t, err)
		case "code.tar.gz":
			codeTarGzBytes, err = io.ReadAll(tr)
			require.NoError(t, err)
		}
	}

	require.NotNil(t, metadataBytes, "metadata.json not found in archive")
	require.NotNil(t, codeTarGzBytes, "code.tar.gz not found in archive")

	var meta Metadata
	err = json.Unmarshal(metadataBytes, &meta)
	require.NoError(t, err)

	codeGr, err := gzip.NewReader(bytesReader(codeTarGzBytes))
	require.NoError(t, err)
	defer codeGr.Close()

	codeTr := tar.NewReader(codeGr)

	var connectionBytes []byte

	for {
		hdr, err := codeTr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)

		if hdr.Name == "connection.json" {
			connectionBytes, err = io.ReadAll(codeTr)
			require.NoError(t, err)
		}
	}

	require.NotNil(t, connectionBytes, "connection.json not found inside code.tar.gz")

	var conn Connection
	err = json.Unmarshal(connectionBytes, &conn)
	require.NoError(t, err)

	return meta, conn
}

// bytesReader wraps a byte slice into an io.Reader.
func bytesReader(b []byte) io.Reader {
	return io.NopCloser(io.NewSectionReader(readerAt(b), 0, int64(len(b))))
}

type readerAt []byte

func (r readerAt) ReadAt(p []byte, off int64) (n int, err error) {
	if off >= int64(len(r)) {
		return 0, io.EOF
	}
	n = copy(p, r[off:])
	if n < len(p) {
		err = io.EOF
	}
	return
}
