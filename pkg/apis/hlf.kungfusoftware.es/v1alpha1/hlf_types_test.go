package v1alpha1

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// initRequired=false must survive a round trip through the Go types, otherwise
// the operator drops it when it updates the resource (e.g. adding a finalizer).
func TestChaincodeInitRequiredFalseIsSerialized(t *testing.T) {
	for name, spec := range map[string]interface{}{
		"approve": FabricChaincodeApproveSpec{InitRequired: false},
		"commit":  FabricChaincodeCommitSpec{InitRequired: false},
	} {
		t.Run(name, func(t *testing.T) {
			b, err := json.Marshal(spec)
			require.NoError(t, err)
			var m map[string]interface{}
			require.NoError(t, json.Unmarshal(b, &m))
			assert.Contains(t, m, "initRequired")
			assert.Equal(t, false, m["initRequired"])
		})
	}
}
