package certs_vault

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"testing"
	"time"
)

const (
	vaultImage       = "hashicorp/vault:1.7.2"
	vaultPort        = "8200"
	vaultRootToken   = "test-root-token"
	vaultTokenSecret = "vault-token"
	vaultNamespace   = "default"
	pkiMountPath     = "test"
	caIssuerName     = "test-ca"
	caCommonName     = "Test CA"
	caTTL            = "87600h"
	roleName         = "fabric"
	roleMaxTTL       = "87600h"
	roleKeyType      = "ec"
	roleKeyBits      = 256
	roleOU           = "peer"
	roleOrg          = "Org1MSP"
	certTTL          = "24h"
	certUser         = "testUser"
	certUserCN       = "testUserCN"
	certHost         = "localhost"
	certMSPID        = "Org1MSP"
	startupTimeout   = 60 * time.Second
	internalSleep    = 2 * time.Second
	requestTimeout   = 30 * time.Second
	certExpiryMargin = time.Hour
)

type VaultContainer struct {
	testcontainers.Container
	Address   string
	RootToken string
}

func setupVaultDev(ctx context.Context) (*VaultContainer, error) {
	req := testcontainers.ContainerRequest{
		Image:        vaultImage,
		ExposedPorts: []string{vaultPort + "/tcp"},
		Env: map[string]string{
			"VAULT_DEV_ROOT_TOKEN_ID": vaultRootToken,
		},
		Cmd: []string{
			"server",
			"-dev",
			"-dev-root-token-id=" + vaultRootToken,
			"-dev-listen-address=0.0.0.0:" + vaultPort,
		},
		WaitingFor: wait.ForHTTP("/v1/sys/health").
			WithPort(vaultPort + "/tcp").
			WithStartupTimeout(startupTimeout).
			WithStatusCodeMatcher(func(code int) bool {
				return code == 200 || code == 429
			}),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("starting vault container: %w", err)
	}

	mappedPort, err := container.MappedPort(ctx, vaultPort)
	if err != nil {
		return nil, fmt.Errorf("getting mapped port: %w", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting container host: %w", err)
	}

	address := fmt.Sprintf("http://%s:%s", host, mappedPort.Port())
	time.Sleep(internalSleep)

	return &VaultContainer{
		Container: container,
		Address:   address,
		RootToken: vaultRootToken,
	}, nil
}

func TestEnrollUser(t *testing.T) {

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

	err = EnablePKI(ctx, vaultClient, pkiMountPath, caTTL)
	require.NoError(t, err, "Failed to enable PKI")

	err = CreateVaultIssuer(ctx, vaultClient, pkiMountPath, caIssuerName, map[string]interface{}{
		"key_type":    roleKeyType,
		"key_bits":    roleKeyBits,
		"ttl":         caTTL,
		"common_name": caCommonName,
	})
	require.NoError(t, err, "Failed to create Vault issuer")

	err = CreateVaultRole(ctx, vaultClient, roleName, map[string]interface{}{
		"issuer_ref":       caIssuerName,
		"allow_subdomains": true,
		"allow_any_name":   true,
		"max_ttl":          roleMaxTTL,
		"key_type":         roleKeyType,
		"key_bits":         roleKeyBits,
		"ou":               roleOU,
		"organization":     roleOrg,
	})
	require.NoError(t, err, "Failed to create Vault role")

	clientSet := GetFakeClientsetWithVaultToken()

	vaultConf := &hlfv1alpha1.VaultSpecConf{
		URL:           vaultContainer.Address,
		TLSSkipVerify: true,
		TokenSecretRef: &hlfv1alpha1.VaultSecretRef{
			Name:      vaultTokenSecret,
			Namespace: vaultNamespace,
			Key:       "token",
		},
	}
	request := &hlfv1alpha1.VaultPKICertificateRequest{
		PKI:  pkiMountPath,
		Role: roleName,
		TTL:  certTTL,
	}
	params := EnrollUserRequest{
		MSPID: certMSPID,
		User:  certUser,
		Hosts: []string{certHost},
		CN:    certUserCN,
	}

	cert, privateKey, caCert, err := EnrollUser(clientSet, vaultConf, request, params)
	require.NoError(t, err, "Failed to enroll user")
	assert.NotNil(t, cert, "Certificate should not be nil")
	assert.NotNil(t, privateKey, "Private key should not be nil")
	assert.NotNil(t, caCert, "CA certificate should not be nil")
	expiry := cert.NotAfter
	expectedExpiry := time.Now().Add(24 * time.Hour)
	assert.WithinDuration(t, expectedExpiry, expiry, certExpiryMargin, "Certificate expiry does not match expected TTL")
}

func TestReenrollUser(t *testing.T) {
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

	err = EnablePKI(ctx, vaultClient, pkiMountPath, caTTL)
	require.NoError(t, err, "Failed to enable PKI")

	err = CreateVaultIssuer(ctx, vaultClient, pkiMountPath, caIssuerName, map[string]interface{}{
		"key_type":    roleKeyType,
		"key_bits":    roleKeyBits,
		"ttl":         caTTL,
		"common_name": caCommonName,
	})
	require.NoError(t, err, "Failed to create Vault issuer")

	err = CreateVaultRole(ctx, vaultClient, roleName, map[string]interface{}{
		"issuer_ref":       caIssuerName,
		"allow_subdomains": true,
		"allow_any_name":   true,
		"max_ttl":          roleMaxTTL,
		"key_type":         roleKeyType,
		"key_bits":         roleKeyBits,
		"ou":               roleOU,
		"organization":     roleOrg,
	})
	require.NoError(t, err, "Failed to create Vault role")

	clientSet := GetFakeClientsetWithVaultToken()
	vaultConf := &hlfv1alpha1.VaultSpecConf{
		URL:           vaultContainer.Address,
		TLSSkipVerify: true,
		TokenSecretRef: &hlfv1alpha1.VaultSecretRef{
			Name:      vaultTokenSecret,
			Namespace: vaultNamespace,
			Key:       "token",
		},
	}
	request := &hlfv1alpha1.VaultPKICertificateRequest{
		PKI:  pkiMountPath,
		Role: roleName,
		TTL:  certTTL,
	}
	enrollUserRequest := EnrollUserRequest{
		MSPID: certMSPID,
		User:  certUser,
		Hosts: []string{certHost},
		CN:    certUserCN,
	}

	cert1, privateKey1, caCert1, err := EnrollUser(clientSet, vaultConf, request, enrollUserRequest)
	require.NoError(t, err, "Failed to enroll user")
	require.NotNil(t, cert1, "Certificate should not be nil")
	require.NotNil(t, privateKey1, "Private key should not be nil")
	require.NotNil(t, caCert1, "CA certificate should not be nil")

	certPEM1 := fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n",
		base64.StdEncoding.EncodeToString(cert1.Raw))

	reenrollUserRequest := ReenrollUserRequest{
		MSPID:    certMSPID,
		EnrollID: certUserCN,
		Hosts:    []string{certHost},
		CN:       certUserCN,
	}

	cert2, caCert2, err := ReenrollUser(clientSet, vaultConf, request, reenrollUserRequest, certPEM1, privateKey1)
	require.NoError(t, err, "Failed to reenroll user")
	require.NotNil(t, cert2, "Reenrolled certificate should not be nil")
	require.NotNil(t, caCert2, "Reenrolled CA certificate should not be nil")

	assert.Equal(t, cert1.PublicKey, cert2.PublicKey, "Private keys should be the same after reenrollment")
}

func GetFakeClientsetWithVaultToken() kubernetes.Interface {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      vaultTokenSecret,
			Namespace: vaultNamespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"token": []byte(vaultRootToken),
		},
	}
	return fake.NewClientset(secret)
}

// CreateVaultRole creates a new role in Vault PKI with the given parameters
// TestAppRoleAuth validates end-to-end Vault AppRole authentication via GetClient
func TestAppRoleAuth(t *testing.T) {
	ctx := context.Background()

	vaultContainer, err := setupVaultDev(ctx)
	require.NoError(t, err, "Failed to setup vault")
	defer func() {
		assert.NoError(t, vaultContainer.Terminate(ctx), "Failed to terminate container")
	}()

	// Create a privileged client with the root token to configure AppRole
	vaultClient, err := vault.New(
		vault.WithAddress(vaultContainer.Address),
		vault.WithRequestTimeout(requestTimeout),
	)
	require.NoError(t, err)
	err = vaultClient.SetToken(vaultContainer.RootToken)
	require.NoError(t, err)

	// Enable AppRole auth at the default mount path
	err = EnableAppRole(ctx, vaultClient, "approle")
	require.NoError(t, err, "Failed to enable AppRole auth")

	// Write a minimal ACL policy for the test role
	policy := `path "sys/mounts" { capabilities = ["read", "list"] }`
	_, err = vaultClient.System.PoliciesWriteAclPolicy(ctx, "test-approle-policy", schema.PoliciesWriteAclPolicyRequest{
		Policy: policy,
	})
	require.NoError(t, err, "Failed to write ACL policy")

	// Create an AppRole with the policy attached
	err = CreateAppRole(ctx, vaultClient, "test-role", map[string]interface{}{
		"token_policies": "test-approle-policy",
		"token_ttl":      "1h",
		"token_max_ttl":  "24h",
	})
	require.NoError(t, err, "Failed to create AppRole")

	// Retrieve the RoleID
	roleID, err := GetAppRoleRoleID(ctx, vaultClient, "test-role")
	require.NoError(t, err, "Failed to read AppRole RoleID")
	require.NotEmpty(t, roleID, "RoleID must not be empty")

	// Generate a SecretID
	secretID, err := GenerateAppRoleSecretID(ctx, vaultClient, "test-role")
	require.NoError(t, err, "Failed to generate AppRole SecretID")
	require.NotEmpty(t, secretID, "SecretID must not be empty")

	// Build fake K8s secrets for the AppRole credentials
	roleSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vault-approle-role-id",
			Namespace: "default",
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"role-id": []byte(roleID),
		},
	}
	secretIDSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vault-approle-secret-id",
			Namespace: "default",
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"secret-id": []byte(secretID),
		},
	}
	clientSet := fake.NewClientset(roleSecret, secretIDSecret)

	// Configure VaultSpecConf with AppRole auth using RoleIdSecretRef
	vaultConf := &hlfv1alpha1.VaultSpecConf{
		URL:           vaultContainer.Address,
		TLSSkipVerify: true,
		RoleIdSecretRef: &hlfv1alpha1.VaultSecretRef{
			Name:      "vault-approle-role-id",
			Namespace: "default",
			Key:       "role-id",
		},
		SecretIdSecretRef: &hlfv1alpha1.VaultSecretRef{
			Name:      "vault-approle-secret-id",
			Namespace: "default",
			Key:       "secret-id",
		},
		AuthPath:   "approle",
		MaxRetries: 0,
		Timeout:    "10s",
	}

	// Exercise GetClient with AppRole auth
	client, err := GetClient(vaultConf, clientSet)
	require.NoError(t, err, "GetClient should succeed with valid AppRole credentials")
	require.NotNil(t, client, "GetClient must return a non-nil client")

	// Verify the client is authenticated by reading sys/mounts (our policy allows it)
	_, err = client.Read(ctx, "sys/mounts")
	assert.NoError(t, err, "Authenticated client should be able to read sys/mounts")
}

// EnableAppRole enables the AppRole auth method at the given mount path
func EnableAppRole(ctx context.Context, vaultClient *vault.Client, mountPath string) error {
	if mountPath == "" {
		mountPath = "approle"
	}
	req := schema.AuthEnableMethodRequest{
		Type: "approle",
	}
	_, err := vaultClient.System.AuthEnableMethod(ctx, mountPath, req)
	if err != nil {
		return fmt.Errorf("failed to enable AppRole auth: %w", err)
	}
	return nil
}

// CreateAppRole creates a new AppRole with the given parameters
func CreateAppRole(ctx context.Context, vaultClient *vault.Client, roleName string, params map[string]interface{}) error {
	if roleName == "" {
		return fmt.Errorf("roleName cannot be empty")
	}
	rolePath := fmt.Sprintf("auth/approle/role/%s", roleName)
	_, err := vaultClient.Write(ctx, rolePath, params)
	if err != nil {
		return fmt.Errorf("failed to create AppRole: %w", err)
	}
	return nil
}

// GetAppRoleRoleID reads the RoleID for the given AppRole
func GetAppRoleRoleID(ctx context.Context, vaultClient *vault.Client, roleName string) (string, error) {
	if roleName == "" {
		return "", fmt.Errorf("roleName cannot be empty")
	}
	roleIDPath := fmt.Sprintf("auth/approle/role/%s/role-id", roleName)
	resp, err := vaultClient.Read(ctx, roleIDPath)
	if err != nil {
		return "", fmt.Errorf("failed to read AppRole RoleID: %w", err)
	}
	if resp == nil || resp.Data == nil {
		return "", fmt.Errorf("empty response when reading RoleID")
	}
	roleID, ok := resp.Data["role_id"].(string)
	if !ok || roleID == "" {
		return "", fmt.Errorf("role_id not found or not a string in response")
	}
	return roleID, nil
}

// GenerateAppRoleSecretID generates a new SecretID for the given AppRole
func GenerateAppRoleSecretID(ctx context.Context, vaultClient *vault.Client, roleName string) (string, error) {
	if roleName == "" {
		return "", fmt.Errorf("roleName cannot be empty")
	}
	secretIDPath := fmt.Sprintf("auth/approle/role/%s/secret-id", roleName)
	resp, err := vaultClient.Write(ctx, secretIDPath, map[string]interface{}{})
	if err != nil {
		return "", fmt.Errorf("failed to generate AppRole SecretID: %w", err)
	}
	if resp == nil || resp.Data == nil {
		return "", fmt.Errorf("empty response when generating SecretID")
	}
	secretID, ok := resp.Data["secret_id"].(string)
	if !ok || secretID == "" {
		return "", fmt.Errorf("secret_id not found or not a string in response")
	}
	return secretID, nil
}

func CreateVaultRole(ctx context.Context, vaultClient *vault.Client, roleName string, params map[string]interface{}) error {
	if roleName == "" {
		return fmt.Errorf("roleName cannot be empty")
	}
	if params == nil {
		return fmt.Errorf("params cannot be nil")
	}

	rolePath := fmt.Sprintf("%s/roles/%s", pkiMountPath, roleName)
	_, err := vaultClient.Write(ctx, rolePath, params)
	if err != nil {
		return fmt.Errorf("failed to create role in Vault: %w", err)
	}

	return nil
}

// EnablePKI enables the PKI secrets engine at the given mount path
func EnablePKI(ctx context.Context, vaultClient *vault.Client, mountPath string, maxLeaseTTL string) error {
	if mountPath == "" {
		return fmt.Errorf("mountPath cannot be empty")
	}
	if maxLeaseTTL == "" {
		maxLeaseTTL = "87600h"
	}

	req := schema.MountsEnableSecretsEngineRequest{
		Type: "pki",
		Config: map[string]interface{}{
			"max_lease_ttl": maxLeaseTTL,
		},
	}

	_, err := vaultClient.System.MountsEnableSecretsEngine(ctx, mountPath, req)
	if err != nil {
		return fmt.Errorf("failed to enable PKI engine: %w", err)
	}

	return nil
}

// CreateVaultIssuer creates a new issuer (CA) in Vault PKI
func CreateVaultIssuer(ctx context.Context, vaultClient *vault.Client, pki, issuerName string, params map[string]interface{}) error {
	if pki == "" {
		return fmt.Errorf("pki mount path cannot be empty")
	}
	if issuerName == "" {
		return fmt.Errorf("issuerName cannot be empty")
	}
	if params == nil {
		return fmt.Errorf("params cannot be nil")
	}

	issuerPath := fmt.Sprintf("%s/root/generate/internal", pki)
	params["issuer_name"] = issuerName
	_, err := vaultClient.Write(ctx, issuerPath, params)
	if err != nil {
		return fmt.Errorf("failed to create issuer in Vault: %w", err)
	}

	return nil
}
