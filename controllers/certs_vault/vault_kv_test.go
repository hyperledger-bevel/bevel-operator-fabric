package certs_vault

import (
	"context"
	"testing"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestMapFromInterface(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]interface{}
		expected map[string]string
	}{
		{
			name:     "Empty map",
			input:    map[string]interface{}{},
			expected: map[string]string{},
		},
		{
			name: "String values are copied as-is",
			input: map[string]interface{}{
				"username": "admin",
				"password": "pw123",
			},
			expected: map[string]string{
				"username": "admin",
				"password": "pw123",
			},
		},
		{
			name: "Byte slice values are converted to strings",
			input: map[string]interface{}{
				"cert": []byte("certificate-data"),
			},
			expected: map[string]string{
				"cert": "certificate-data",
			},
		},
		{
			name: "Non-string scalar values are stringified",
			input: map[string]interface{}{
				"ttl":       int64(3600),
				"max_uses":  float64(5),
				"enabled":   true,
				"nested":    map[string]interface{}{"a": "b"},
				"nil_value": nil,
			},
			expected: map[string]string{
				"ttl":       "3600",
				"max_uses":  "5",
				"enabled":   "true",
				"nested":    "map[a:b]",
				"nil_value": "<nil>",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapFromInterface(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestCreateOrUpdateK8sSecret(t *testing.T) {
	ctx := context.Background()
	secretData := map[string][]byte{
		"username": []byte("admin"),
		"password": []byte("pw123"),
	}

	t.Run("Creates secret when it does not exist", func(t *testing.T) {
		clientset := fake.NewClientset()
		err := CreateOrUpdateK8sSecret(ctx, clientset, "default", "my-secret", secretData)
		require.NoError(t, err)

		secret, err := clientset.CoreV1().Secrets("default").Get(ctx, "my-secret", metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, secretData, secret.Data)
		assert.Equal(t, corev1.SecretTypeOpaque, secret.Type)
	})

	t.Run("Updates data of existing secret", func(t *testing.T) {
		existing := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-secret",
				Namespace: "default",
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				"username": []byte("old-user"),
			},
		}
		clientset := fake.NewClientset(existing)

		err := CreateOrUpdateK8sSecret(ctx, clientset, "default", "my-secret", secretData)
		require.NoError(t, err)

		secret, err := clientset.CoreV1().Secrets("default").Get(ctx, "my-secret", metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, secretData, secret.Data)
	})
}

func TestResolveSecretRefValue(t *testing.T) {
	ctx := context.Background()
	enrollSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "peer-enroll-secret",
			Namespace: "default",
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"secret": []byte("peerAdminpw"),
		},
	}

	t.Run("Returns nil value for nil secret ref", func(t *testing.T) {
		clientset := fake.NewClientset(enrollSecret)
		value, err := ResolveSecretRefValue(ctx, clientset, nil, nil)
		require.NoError(t, err)
		assert.Nil(t, value)
	})

	t.Run("Returns value when secret and key exist", func(t *testing.T) {
		clientset := fake.NewClientset(enrollSecret)
		value, err := ResolveSecretRefValue(ctx, clientset, &hlfv1alpha1.SecretRefNSKey{
			Name:      "peer-enroll-secret",
			Namespace: "default",
			Key:       "secret",
		}, nil)
		require.NoError(t, err)
		assert.Equal(t, []byte("peerAdminpw"), value)
	})

	t.Run("Returns error when key is missing from secret", func(t *testing.T) {
		clientset := fake.NewClientset(enrollSecret)
		value, err := ResolveSecretRefValue(ctx, clientset, &hlfv1alpha1.SecretRefNSKey{
			Name:      "peer-enroll-secret",
			Namespace: "default",
			Key:       "missing-key",
		}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `key "missing-key" not found`)
		assert.Nil(t, value)
	})

	t.Run("Returns error when secret does not exist and no vault config", func(t *testing.T) {
		clientset := fake.NewClientset()
		value, err := ResolveSecretRefValue(ctx, clientset, &hlfv1alpha1.SecretRefNSKey{
			Name:      "nonexistent-secret",
			Namespace: "default",
			Key:       "secret",
		}, nil)
		require.Error(t, err)
		assert.True(t, k8serrors.IsNotFound(err), "expected NotFound error, got: %v", err)
		assert.Nil(t, value)
	})

	t.Run("Defaults namespace to default when empty", func(t *testing.T) {
		clientset := fake.NewClientset(enrollSecret)
		value, err := ResolveSecretRefValue(ctx, clientset, &hlfv1alpha1.SecretRefNSKey{
			Name: "peer-enroll-secret",
			Key:  "secret",
		}, nil)
		require.NoError(t, err)
		assert.Equal(t, []byte("peerAdminpw"), value)
	})

	t.Run("Reads existing secret without contacting Vault when vault config is set", func(t *testing.T) {
		clientset := fake.NewClientset(enrollSecret)
		vaultConf := &hlfv1alpha1.VaultSpecConf{
			URL:           "http://vault.example.com:8200",
			Path:          "secret",
			KVVersion:     2,
			TLSSkipVerify: true,
			TokenSecretRef: &hlfv1alpha1.VaultSecretRef{
				Name:      "vault-token",
				Namespace: "default",
				Key:       "token",
			},
		}
		value, err := ResolveSecretRefValue(ctx, clientset, &hlfv1alpha1.SecretRefNSKey{
			Name:      "peer-enroll-secret",
			Namespace: "default",
			Key:       "secret",
		}, vaultConf)
		require.NoError(t, err)
		assert.Equal(t, []byte("peerAdminpw"), value)
	})
}

func TestGetKVSecretRequiresPath(t *testing.T) {
	ctx := context.Background()
	vaultConf := &hlfv1alpha1.VaultSpecConf{
		URL:       "http://vault.example.com:8200",
		KVVersion: 2,
		TokenSecretRef: &hlfv1alpha1.VaultSecretRef{
			Name:      "vault-token",
			Namespace: "default",
			Key:       "token",
		},
	}
	clientset := fake.NewClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vault-token",
			Namespace: "default",
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"token": []byte("test-root-token"),
		},
	})
	_, err := GetKVSecret(ctx, vaultConf, "peer-enroll-secret", clientset)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "vault path is required")
}

func TestGetKVSecretVault(t *testing.T) {
	ctx := context.Background()
	vaultContainer, err := setupVaultDev(ctx)
	require.NoError(t, err, "Failed to setup vault")
	defer func() {
		assert.NoError(t, vaultContainer.Terminate(ctx), "Failed to terminate container")
	}()

	vaultClient, err := vault.New(
		vault.WithAddress(vaultContainer.Address),
		vault.WithRequestTimeout(requestTimeout),
	)
	require.NoError(t, err, "Failed to create Vault client")
	err = vaultClient.SetToken(vaultContainer.RootToken)
	require.NoError(t, err, "Failed to set Vault token")

	vaultConf := &hlfv1alpha1.VaultSpecConf{
		URL:           vaultContainer.Address,
		TLSSkipVerify: true,
		TokenSecretRef: &hlfv1alpha1.VaultSecretRef{
			Name:      vaultTokenSecret,
			Namespace: vaultNamespace,
			Key:       "token",
		},
	}
	clientset := GetFakeClientsetWithVaultToken()

	t.Run("KV v1", func(t *testing.T) {
		_, err = vaultClient.System.MountsEnableSecretsEngine(ctx, "kv1", schema.MountsEnableSecretsEngineRequest{
			Type: "kv",
			Options: map[string]interface{}{
				"version": "1",
			},
		})
		require.NoError(t, err, "Failed to enable KV v1 mount")

		_, err = vaultClient.Secrets.KvV1Write(ctx, "peer-enroll-secret", map[string]interface{}{
			"username": "peerAdmin",
			"secret":   "peerAdminpw",
		}, vault.WithMountPath("kv1"))
		require.NoError(t, err, "Failed to write KV v1 secret")

		vaultConf.Path = "kv1"
		vaultConf.KVVersion = 1
		data, err := GetKVSecret(ctx, vaultConf, "peer-enroll-secret", clientset)
		require.NoError(t, err)
		assert.Equal(t, map[string]string{
			"username": "peerAdmin",
			"secret":   "peerAdminpw",
		}, data)
	})

	t.Run("KV v2", func(t *testing.T) {
		_, err = vaultClient.Secrets.KvV2Write(ctx, "orderer-enroll-secret", schema.KvV2WriteRequest{
			Data: map[string]interface{}{
				"username": "ordererAdmin",
				"secret":   "ordererAdminpw",
			},
		}, vault.WithMountPath("secret"))
		require.NoError(t, err, "Failed to write KV v2 secret")

		vaultConf.Path = "secret"
		vaultConf.KVVersion = 2
		data, err := GetKVSecret(ctx, vaultConf, "orderer-enroll-secret", clientset)
		require.NoError(t, err)
		assert.Equal(t, map[string]string{
			"username": "ordererAdmin",
			"secret":   "ordererAdminpw",
		}, data)
	})
}

func TestSyncVaultKVSecretToK8sVault(t *testing.T) {
	ctx := context.Background()
	vaultContainer, err := setupVaultDev(ctx)
	require.NoError(t, err, "Failed to setup vault")
	defer func() {
		assert.NoError(t, vaultContainer.Terminate(ctx), "Failed to terminate container")
	}()

	vaultClient, err := vault.New(
		vault.WithAddress(vaultContainer.Address),
		vault.WithRequestTimeout(requestTimeout),
	)
	require.NoError(t, err, "Failed to create Vault client")
	err = vaultClient.SetToken(vaultContainer.RootToken)
	require.NoError(t, err, "Failed to set Vault token")

	_, err = vaultClient.Secrets.KvV2Write(ctx, "peer-enroll-secret", schema.KvV2WriteRequest{
		Data: map[string]interface{}{
			"username": "peerAdmin",
			"secret":   "peerAdminpw",
		},
	}, vault.WithMountPath("secret"))
	require.NoError(t, err, "Failed to write KV v2 secret")

	vaultConf := &hlfv1alpha1.VaultSpecConf{
		URL:           vaultContainer.Address,
		TLSSkipVerify: true,
		Path:          "secret",
		KVVersion:     2,
		TokenSecretRef: &hlfv1alpha1.VaultSecretRef{
			Name:      vaultTokenSecret,
			Namespace: vaultNamespace,
			Key:       "token",
		},
	}
	clientset := GetFakeClientsetWithVaultToken()

	data, err := SyncVaultKVSecretToK8s(ctx, vaultConf, "peer-enroll-secret", vaultNamespace, "peer-enroll-secret", clientset)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"username": "peerAdmin",
		"secret":   "peerAdminpw",
	}, data)

	secret, err := clientset.CoreV1().Secrets(vaultNamespace).Get(ctx, "peer-enroll-secret", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, map[string][]byte{
		"username": []byte("peerAdmin"),
		"secret":   []byte("peerAdminpw"),
	}, secret.Data)
}

func TestResolveSecretRefValueVaultAutoSync(t *testing.T) {
	ctx := context.Background()
	vaultContainer, err := setupVaultDev(ctx)
	require.NoError(t, err, "Failed to setup vault")
	defer func() {
		assert.NoError(t, vaultContainer.Terminate(ctx), "Failed to terminate container")
	}()

	vaultClient, err := vault.New(
		vault.WithAddress(vaultContainer.Address),
		vault.WithRequestTimeout(requestTimeout),
	)
	require.NoError(t, err, "Failed to create Vault client")
	err = vaultClient.SetToken(vaultContainer.RootToken)
	require.NoError(t, err, "Failed to set Vault token")

	_, err = vaultClient.Secrets.KvV2Write(ctx, "peer-enroll-secret", schema.KvV2WriteRequest{
		Data: map[string]interface{}{
			"secret": "peerAdminpw",
		},
	}, vault.WithMountPath("secret"))
	require.NoError(t, err, "Failed to write KV v2 secret")

	vaultConf := &hlfv1alpha1.VaultSpecConf{
		URL:           vaultContainer.Address,
		TLSSkipVerify: true,
		Path:          "secret",
		KVVersion:     2,
		TokenSecretRef: &hlfv1alpha1.VaultSecretRef{
			Name:      vaultTokenSecret,
			Namespace: vaultNamespace,
			Key:       "token",
		},
	}
	clientset := GetFakeClientsetWithVaultToken()

	value, err := ResolveSecretRefValue(ctx, clientset, &hlfv1alpha1.SecretRefNSKey{
		Name:      "peer-enroll-secret",
		Namespace: vaultNamespace,
		Key:       "secret",
	}, vaultConf)
	require.NoError(t, err)
	assert.Equal(t, []byte("peerAdminpw"), value)

	secret, err := clientset.CoreV1().Secrets(vaultNamespace).Get(ctx, "peer-enroll-secret", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, []byte("peerAdminpw"), secret.Data["secret"])
}
