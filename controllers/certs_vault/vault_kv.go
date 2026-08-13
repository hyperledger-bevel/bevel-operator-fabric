package certs_vault

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault-client-go"
	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// GetKVSecret reads a secret from the Vault KV backend (v1 or v2) and returns
// its data as a map of string keys to string values. The mount path is taken
// from vaultConf.Path and the secret location from secretPath.
func GetKVSecret(ctx context.Context, vaultConf *hlfv1alpha1.VaultSpecConf, secretPath string, clientset kubernetes.Interface) (map[string]string, error) {
	vaultClient, err := GetClient(vaultConf, clientset)
	if err != nil {
		return nil, err
	}
	mountPath := vaultConf.Path
	if mountPath == "" {
		return nil, fmt.Errorf("vault path is required to read KV secrets")
	}
	if vaultConf.KVVersion == 1 {
		resp, err := vaultClient.Secrets.KvV1Read(ctx, secretPath, vault.WithMountPath(mountPath))
		if err != nil {
			return nil, fmt.Errorf("failed to read KV v1 secret %q from Vault: %w", secretPath, err)
		}
		return mapFromInterface(resp.Data), nil
	}
	resp, err := vaultClient.Secrets.KvV2Read(ctx, secretPath, vault.WithMountPath(mountPath))
	if err != nil {
		return nil, fmt.Errorf("failed to read KV v2 secret %q from Vault: %w", secretPath, err)
	}
	return mapFromInterface(resp.Data.Data), nil
}

func mapFromInterface(data map[string]interface{}) map[string]string {
	result := make(map[string]string, len(data))
	for k, v := range data {
		switch value := v.(type) {
		case string:
			result[k] = value
		case []byte:
			result[k] = string(value)
		default:
			result[k] = fmt.Sprintf("%v", value)
		}
	}
	return result
}

// CreateOrUpdateK8sSecret creates a Kubernetes Secret in the given namespace if
// it does not exist, or updates the data of the existing one.
func CreateOrUpdateK8sSecret(ctx context.Context, clientset kubernetes.Interface, namespace, name string, data map[string][]byte) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}
	existing, err := clientset.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			_, err = clientset.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{})
			return err
		}
		return err
	}
	existing.Data = data
	_, err = clientset.CoreV1().Secrets(namespace).Update(ctx, existing, metav1.UpdateOptions{})
	return err
}

// SyncVaultKVSecretToK8s reads a secret from the Vault KV backend and creates
// or updates a Kubernetes Secret in the given namespace with the retrieved
// data. It returns the synced data so callers can use it directly.
func SyncVaultKVSecretToK8s(ctx context.Context, vaultConf *hlfv1alpha1.VaultSpecConf, secretPath, namespace, secretName string, clientset kubernetes.Interface) (map[string]string, error) {
	data, err := GetKVSecret(ctx, vaultConf, secretPath, clientset)
	if err != nil {
		return nil, err
	}
	secretData := make(map[string][]byte, len(data))
	for k, v := range data {
		secretData[k] = []byte(v)
	}
	if err := CreateOrUpdateK8sSecret(ctx, clientset, namespace, secretName, secretData); err != nil {
		return nil, err
	}
	return data, nil
}

// ResolveSecretRefValue returns the value stored under secretRef.Key in the
// Kubernetes Secret referenced by secretRef. When the referenced Secret does
// not exist yet and a Vault configuration is provided, the Secret is first
// synchronized from the Vault KV backend at secretRef.Name before reading.
func ResolveSecretRefValue(ctx context.Context, clientset kubernetes.Interface, secretRef *hlfv1alpha1.SecretRefNSKey, vaultConf *hlfv1alpha1.VaultSpecConf) ([]byte, error) {
	if secretRef == nil {
		return nil, nil
	}
	namespace := secretRef.Namespace
	if namespace == "" {
		namespace = "default"
	}
	secret, err := clientset.CoreV1().Secrets(namespace).Get(ctx, secretRef.Name, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) && vaultConf != nil {
			if _, syncErr := SyncVaultKVSecretToK8s(ctx, vaultConf, secretRef.Name, namespace, secretRef.Name, clientset); syncErr != nil {
				return nil, fmt.Errorf("failed to sync secret %q from Vault KV: %w", secretRef.Name, syncErr)
			}
			secret, err = clientset.CoreV1().Secrets(namespace).Get(ctx, secretRef.Name, metav1.GetOptions{})
		}
		if err != nil {
			return nil, err
		}
	}
	value, ok := secret.Data[secretRef.Key]
	if !ok {
		return nil, fmt.Errorf("key %q not found in secret %s/%s", secretRef.Key, namespace, secretRef.Name)
	}
	return value, nil
}
