package console

import (
	"testing"

	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/api/networking/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newTestConsole(name, image, tag string) *hlfv1alpha1.FabricOperationsConsole {
	return &hlfv1alpha1.FabricOperationsConsole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Spec: hlfv1alpha1.FabricOperationsConsoleSpec{
			Image:           image,
			Tag:             tag,
			ImagePullPolicy: corev1.PullIfNotPresent,
			Replicas:        1,
			Port:            3000,
			HostURL:         "https://console.example.com",
			Auth: hlfv1alpha1.FabricOperationsConsoleAuth{
				Scheme:   "couchdb",
				Username: "admin",
				Password: "adminpw",
			},
			CouchDB: hlfv1alpha1.FabricOperationsConsoleCouchDB{
				Image:           "couchdb",
				Tag:             "3.1.1",
				ImagePullPolicy: corev1.PullIfNotPresent,
				Username:        "couchuser",
				Password:        "couchpass",
				Storage: hlfv1alpha1.Storage{
					Size:         "10Gi",
					StorageClass: "standard",
					AccessMode:   corev1.ReadWriteOnce,
				},
			},
			Ingress: hlfv1alpha1.Ingress{
				Enabled:   true,
				ClassName: "nginx",
				Annotations: map[string]string{
					"nginx.ingress.kubernetes.io/proxy-body-size": "50m",
				},
				TLS: []v1beta1.IngressTLS{
					{
						Hosts:      []string{"console.example.com"},
						SecretName: "console-tls",
					},
				},
				Hosts: []hlfv1alpha1.IngressHost{
					{
						Host: "console.example.com",
						Paths: []hlfv1alpha1.IngressPath{
							{
								Path:     "/",
								PathType: "Prefix",
							},
						},
					},
				},
			},
		},
	}
}

func TestValidateConsoleConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		console     *hlfv1alpha1.FabricOperationsConsole
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid configuration",
			console:     newTestConsole("my-console", "ghcr.io/hyperledger-labs/fabric-console", "latest"),
			expectError: false,
		},
		{
			name:        "Empty image",
			console:     newTestConsole("my-console", "", "latest"),
			expectError: true,
			errorMsg:    "console image cannot be empty",
		},
		{
			name:        "Empty tag",
			console:     newTestConsole("my-console", "ghcr.io/hyperledger-labs/fabric-console", ""),
			expectError: true,
			errorMsg:    "console image tag cannot be empty",
		},
		{
			name:        "Empty name",
			console:     newTestConsole("", "ghcr.io/hyperledger-labs/fabric-console", "latest"),
			expectError: true,
			errorMsg:    "console name cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := &FabricOperationsConsoleReconciler{}
			err := r.validateConsoleConfig(tt.console)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetConfig(t *testing.T) {
	t.Parallel()

	t.Run("Maps spec fields to chart values correctly", func(t *testing.T) {
		t.Parallel()
		console := newTestConsole("my-console", "ghcr.io/hyperledger-labs/fabric-console", "latest")
		chart, err := GetConfig(console)

		assert.NoError(t, err)
		assert.NotNil(t, chart)

		// Image mapping
		assert.Equal(t, "ghcr.io/hyperledger-labs/fabric-console", chart.Image.Repository)
		assert.Equal(t, "latest", chart.Image.Tag)
		assert.Equal(t, corev1.PullIfNotPresent, chart.Image.PullPolicy)

		// Basic fields
		assert.Equal(t, 1, chart.Replicas)
		assert.Equal(t, 3000, chart.Port)
		assert.Equal(t, "https://console.example.com", chart.HostUrl)
	})

	t.Run("Auth settings are mapped correctly", func(t *testing.T) {
		t.Parallel()
		console := newTestConsole("my-console", "ghcr.io/hyperledger-labs/fabric-console", "latest")
		chart, err := GetConfig(console)

		assert.NoError(t, err)
		assert.Equal(t, "couchdb", chart.Auth.Scheme)
		assert.Equal(t, "admin", chart.Auth.Username)
		assert.Equal(t, "adminpw", chart.Auth.Password)
	})

	t.Run("CouchDB settings are mapped correctly", func(t *testing.T) {
		t.Parallel()
		console := newTestConsole("my-console", "ghcr.io/hyperledger-labs/fabric-console", "latest")
		chart, err := GetConfig(console)

		assert.NoError(t, err)
		assert.Equal(t, "couchdb", chart.CouchDB.Image)
		assert.Equal(t, "3.1.1", chart.CouchDB.Tag)
		assert.Equal(t, corev1.PullIfNotPresent, chart.CouchDB.PullPolicy)
		assert.Equal(t, "couchuser", chart.CouchDB.Username)
		assert.Equal(t, "couchpass", chart.CouchDB.Password)

		// Persistence defaults
		assert.True(t, chart.CouchDB.Persistence.Enabled)
		assert.Equal(t, "standard", chart.CouchDB.Persistence.StorageClass)
		assert.Equal(t, corev1.ReadWriteOnce, chart.CouchDB.Persistence.AccessMode)
		assert.Equal(t, "10Gi", chart.CouchDB.Persistence.Size)

		// External CouchDB defaults to disabled
		assert.False(t, chart.CouchDB.External.Enabled)
		assert.Equal(t, "", chart.CouchDB.External.Host)
		assert.Equal(t, 0, chart.CouchDB.External.Port)
	})

	t.Run("Ingress with hosts and TLS is mapped correctly", func(t *testing.T) {
		t.Parallel()
		console := newTestConsole("my-console", "ghcr.io/hyperledger-labs/fabric-console", "latest")
		chart, err := GetConfig(console)

		assert.NoError(t, err)
		assert.True(t, chart.Ingress.Enabled)
		assert.Equal(t, "nginx", chart.Ingress.ClassName)
		assert.Equal(t, "50m", chart.Ingress.Annotations["nginx.ingress.kubernetes.io/proxy-body-size"])

		// TLS
		assert.Len(t, chart.Ingress.TLS, 1)
		assert.Equal(t, "console-tls", chart.Ingress.TLS[0].SecretName)
		assert.Equal(t, []string{"console.example.com"}, chart.Ingress.TLS[0].Hosts)

		// Hosts
		assert.Len(t, chart.Ingress.Hosts, 1)
		assert.Equal(t, "console.example.com", chart.Ingress.Hosts[0].Host)
		assert.Len(t, chart.Ingress.Hosts[0].Paths, 1)
		assert.Equal(t, "/", chart.Ingress.Hosts[0].Paths[0].Path)
		assert.Equal(t, "Prefix", chart.Ingress.Hosts[0].Paths[0].PathType)
	})

	t.Run("Disabled ingress returns empty ingress struct", func(t *testing.T) {
		t.Parallel()
		console := newTestConsole("my-console", "ghcr.io/hyperledger-labs/fabric-console", "latest")
		console.Spec.Ingress.Enabled = false
		chart, err := GetConfig(console)

		assert.NoError(t, err)
		assert.False(t, chart.Ingress.Enabled)
		assert.Empty(t, chart.Ingress.Hosts)
		assert.Empty(t, chart.Ingress.TLS)
		assert.Empty(t, chart.Ingress.Annotations)
	})

	t.Run("PodAnnotations default to empty map", func(t *testing.T) {
		t.Parallel()
		console := newTestConsole("my-console", "ghcr.io/hyperledger-labs/fabric-console", "latest")
		chart, err := GetConfig(console)

		assert.NoError(t, err)
		assert.NotNil(t, chart.PodAnnotations)
		assert.Empty(t, chart.PodAnnotations)
	})
}
