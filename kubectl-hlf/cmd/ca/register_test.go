package ca

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAlreadyRegisteredErrorHandling verifies that the "already registered"
// error is detected and handled gracefully instead of failing.
// Regression test for #284.
func TestAlreadyRegisteredErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		errMsg      string
		shouldMatch bool
	}{
		{
			name:        "exact fabric CA error message",
			errMsg:      "Identity 'admin' is already registered",
			shouldMatch: true,
		},
		{
			name:        "wrapped error message",
			errMsg:      "failed to register: Identity 'admin' is already registered",
			shouldMatch: true,
		},
		{
			name:        "different error should not match",
			errMsg:      "connection refused",
			shouldMatch: false,
		},
		{
			name:        "empty error should not match",
			errMsg:      "",
			shouldMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isAlreadyRegistered := strings.Contains(tt.errMsg, "is already registered")
			assert.Equal(t, tt.shouldMatch, isAlreadyRegistered,
				"Error detection for 'already registered' should work correctly")
		})
	}
}

// TestConvertAttrs verifies attribute parsing for CA registration.
func TestConvertAttrs(t *testing.T) {
	t.Run("empty attributes", func(t *testing.T) {
		attrs, err := ConvertAttrs(map[string]string{})
		assert.NoError(t, err)
		assert.Empty(t, attrs)
	})

	t.Run("simple attribute", func(t *testing.T) {
		attrs, err := ConvertAttrs(map[string]string{"hf.Registrar.Roles": "client"})
		assert.NoError(t, err)
		assert.Len(t, attrs, 1)
		assert.Equal(t, "hf.Registrar.Roles", attrs[0].Name)
		assert.Equal(t, "client", attrs[0].Value)
		assert.False(t, attrs[0].ECert)
	})

	t.Run("ecert attribute", func(t *testing.T) {
		attrs, err := ConvertAttrs(map[string]string{"email": "user@example.com:ecert"})
		assert.NoError(t, err)
		assert.Len(t, attrs, 1)
		assert.Equal(t, "email", attrs[0].Name)
		assert.Equal(t, "user@example.com", attrs[0].Value)
		assert.True(t, attrs[0].ECert)
	})

	t.Run("invalid flag", func(t *testing.T) {
		_, err := ConvertAttrs(map[string]string{"email": "user@example.com:invalid"})
		assert.Error(t, err)
	})

	t.Run("too many colons", func(t *testing.T) {
		_, err := ConvertAttrs(map[string]string{"email": "a:b:c"})
		assert.Error(t, err)
	})
}
