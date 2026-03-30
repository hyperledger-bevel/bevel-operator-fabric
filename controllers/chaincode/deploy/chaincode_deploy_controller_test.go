package deploy

import (
	"fmt"
	"strings"
	"testing"

	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newFabricChaincode(name string) *hlfv1alpha1.FabricChaincode {
	return &hlfv1alpha1.FabricChaincode{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
}

func TestResourceNaming(t *testing.T) {
	r := &FabricChaincodeDeployReconciler{}

	tests := []struct {
		name               string
		chaincodeName      string
		wantDeploymentName string
		wantServiceName    string
		wantSecretName     string
	}{
		{
			name:               "normal name",
			chaincodeName:      "my-chaincode",
			wantDeploymentName: "my-chaincode",
			wantServiceName:    "my-chaincode",
			wantSecretName:     "my-chaincode-certs",
		},
		{
			name:               "name with dots",
			chaincodeName:      "org1.chaincode.v1",
			wantDeploymentName: "org1.chaincode.v1",
			wantServiceName:    "org1.chaincode.v1",
			wantSecretName:     "org1.chaincode.v1-certs",
		},
		{
			name:               "name with underscores",
			chaincodeName:      "my_chaincode_v2",
			wantDeploymentName: "my_chaincode_v2",
			wantServiceName:    "my_chaincode_v2",
			wantSecretName:     "my_chaincode_v2-certs",
		},
		{
			name:               "long name",
			chaincodeName:      strings.Repeat("a", 63),
			wantDeploymentName: strings.Repeat("a", 63),
			wantServiceName:    strings.Repeat("a", 63),
			wantSecretName:     fmt.Sprintf("%s-certs", strings.Repeat("a", 63)),
		},
		{
			name:               "single character name",
			chaincodeName:      "x",
			wantDeploymentName: "x",
			wantServiceName:    "x",
			wantSecretName:     "x-certs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := newFabricChaincode(tt.chaincodeName)

			gotDeployment := r.getDeploymentName(fc)
			if gotDeployment != tt.wantDeploymentName {
				t.Errorf("getDeploymentName() = %q, want %q", gotDeployment, tt.wantDeploymentName)
			}

			gotService := r.getServiceName(fc)
			if gotService != tt.wantServiceName {
				t.Errorf("getServiceName() = %q, want %q", gotService, tt.wantServiceName)
			}

			gotSecret := r.getSecretName(fc)
			if gotSecret != tt.wantSecretName {
				t.Errorf("getSecretName() = %q, want %q", gotSecret, tt.wantSecretName)
			}
		})
	}
}

func TestResourceNamingConsistency(t *testing.T) {
	r := &FabricChaincodeDeployReconciler{}
	fc := newFabricChaincode("my-chaincode")

	// Calling the same function multiple times must return the same result.
	first := r.getDeploymentName(fc)
	second := r.getDeploymentName(fc)
	if first != second {
		t.Errorf("getDeploymentName() not consistent: first=%q, second=%q", first, second)
	}

	firstSvc := r.getServiceName(fc)
	secondSvc := r.getServiceName(fc)
	if firstSvc != secondSvc {
		t.Errorf("getServiceName() not consistent: first=%q, second=%q", firstSvc, secondSvc)
	}

	firstSecret := r.getSecretName(fc)
	secondSecret := r.getSecretName(fc)
	if firstSecret != secondSecret {
		t.Errorf("getSecretName() not consistent: first=%q, second=%q", firstSecret, secondSecret)
	}
}

func TestSecretNameSuffix(t *testing.T) {
	r := &FabricChaincodeDeployReconciler{}
	fc := newFabricChaincode("my-chaincode")

	secretName := r.getSecretName(fc)
	if !strings.HasSuffix(secretName, "-certs") {
		t.Errorf("getSecretName() = %q, expected suffix '-certs'", secretName)
	}
	if !strings.HasPrefix(secretName, fc.Name) {
		t.Errorf("getSecretName() = %q, expected prefix %q", secretName, fc.Name)
	}
}

func TestDeploymentAndServiceNameMatch(t *testing.T) {
	r := &FabricChaincodeDeployReconciler{}
	fc := newFabricChaincode("my-chaincode")

	deploymentName := r.getDeploymentName(fc)
	serviceName := r.getServiceName(fc)
	if deploymentName != serviceName {
		t.Errorf("deployment name %q and service name %q should match", deploymentName, serviceName)
	}
}
