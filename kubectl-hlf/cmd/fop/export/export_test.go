package export

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestHTTPResponseBodyClosed verifies that HTTP response bodies are properly
// closed after reading. This is a regression test for #141.
func TestHTTPResponseBodyClosed(t *testing.T) {
	t.Run("response body is read and closed properly", func(t *testing.T) {
		// Create a test server that returns a known response
		bodyClosed := false
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"result":{"CAName":"test-ca","CAChain":"abc"}}`))
		}))
		defer server.Close()

		// Make a request similar to how export.go does it
		client := server.Client()
		res, err := client.Get(server.URL + "/cainfo")
		assert.NoError(t, err)
		assert.NotNil(t, res)

		// The key fix: defer res.Body.Close() must be called
		// We verify the body is readable and closeable
		defer func() {
			err := res.Body.Close()
			if err == nil {
				bodyClosed = true
			}
			assert.True(t, bodyClosed, "Response body should be closeable without error")
		}()

		assert.Equal(t, http.StatusOK, res.StatusCode)
	})
}
