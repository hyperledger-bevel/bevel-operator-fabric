package install

import (
	"testing"
	"time"

	"github.com/hyperledger/fabric-sdk-go/pkg/fab/ccpackager/lifecycle"
	"os"
)

// The package ID must be a pure function of the spec: two builds of the same
// options, separated by more than tar's 1-second mtime resolution, must hash
// identically. See #323.
func TestGenerateChaincodePackageDeterministic(t *testing.T) {
	opts := ChaincodePackageOptions{
		ChaincodeName:  "probe",
		ChaincodeLabel: "probe",
		Address:        "probe-cc.example:9999",
	}
	p1, err := generateChaincodePackage(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(p1)
	time.Sleep(1100 * time.Millisecond)
	p2, err := generateChaincodePackage(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(p2)

	b1, err := os.ReadFile(p1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := os.ReadFile(p2)
	if err != nil {
		t.Fatal(err)
	}
	id1 := lifecycle.ComputePackageID(opts.ChaincodeLabel, b1)
	id2 := lifecycle.ComputePackageID(opts.ChaincodeLabel, b2)
	if id1 != id2 {
		t.Fatalf("package ID not deterministic:\n  %s\n  %s", id1, id2)
	}
}
