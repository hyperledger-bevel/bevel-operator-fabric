package vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault-client-go"
	"github.com/kfsoftware/hlf-operator/pkg/pki"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func init() {
	// Register the Vault provider factory
	pki.RegisterProvider(pki.ProviderTypeVault, func(config *pki.ProviderConfig) (pki.Provider, error) {
		return NewProvider(config.Vault, config.ClientSet)
	})
}

// Provider implements the pki.Provider interface for HashiCorp Vault
type Provider struct {
	config    *pki.VaultConfig
	client    *vault.Client
	clientSet kubernetes.Interface
}

// Ensure Provider implements the pki.Provider interface
var _ pki.Provider = (*Provider)(nil)
var _ pki.RegistrationSupporter = (*Provider)(nil)
var _ pki.RevocationSupporter = (*Provider)(nil)

// NewProvider creates a new Vault PKI provider
func NewProvider(config *pki.VaultConfig, clientSet kubernetes.Interface) (*Provider, error) {
	if config == nil {
		return nil, errors.New("vault config is required")
	}
	if config.URL == "" {
		return nil, errors.New("vault URL is required")
	}
	if config.PKIPath == "" {
		return nil, errors.New("vault PKI path is required")
	}
	if config.Role == "" {
		return nil, errors.New("vault PKI role is required")
	}
	if clientSet == nil {
		return nil, errors.New("kubernetes clientset is required")
	}

	client, err := createVaultClient(config, clientSet)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create Vault client")
	}

	return &Provider{
		config:    config,
		client:    client,
		clientSet: clientSet,
	}, nil
}

// Type returns the provider type
func (p *Provider) Type() pki.ProviderType {
	return pki.ProviderTypeVault
}

// SupportsRegistration returns false as Vault PKI doesn't have native identity registration
func (p *Provider) SupportsRegistration() bool {
	return false
}

// SupportsRevocation returns true as Vault PKI supports certificate revocation
func (p *Provider) SupportsRevocation() bool {
	return true
}

// Enroll enrolls a new identity using Vault PKI
func (p *Provider) Enroll(ctx context.Context, req pki.EnrollRequest) (*pki.EnrollResponse, error) {
	// Generate a new private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate private key")
	}

	// Create CSR
	commonName := req.User
	if req.CN != "" {
		commonName = req.CN
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
	}

	if len(req.Hosts) > 0 {
		template.DNSNames = req.Hosts
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create CSR")
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	// Prepare request data for Vault
	csrData := map[string]interface{}{
		"csr":                 string(csrPEM),
		"common_name":         commonName,
		"use_csr_common_name": true,
		"use_csr_sans":        true,
	}

	if p.config.TTL != "" {
		csrData["ttl"] = p.config.TTL
	}

	logrus.Infof("Enrolling user %s with Vault PKI", req.User)

	// Request certificate from Vault PKI
	secret, err := p.client.Write(
		ctx,
		fmt.Sprintf("%s/sign/%s", p.config.PKIPath, p.config.Role),
		csrData,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign CSR with Vault PKI")
	}

	// Parse the signed certificate
	certPEM, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, errors.New("failed to get certificate from Vault response")
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse certificate")
	}

	// Parse the CA certificate
	caPEM, ok := secret.Data["issuing_ca"].(string)
	if !ok {
		return nil, errors.New("failed to get issuing CA from Vault response")
	}

	caBlock, _ := pem.Decode([]byte(caPEM))
	if caBlock == nil {
		return nil, errors.New("failed to decode CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse CA certificate")
	}

	return &pki.EnrollResponse{
		Certificate:     cert,
		PrivateKey:      privateKey,
		RootCertificate: caCert,
	}, nil
}

// Reenroll re-enrolls an existing identity using the existing key
func (p *Provider) Reenroll(ctx context.Context, req pki.ReenrollRequest) (*pki.ReenrollResponse, error) {
	if req.ExistingKey == nil {
		return nil, errors.New("existing private key is required for re-enrollment")
	}

	commonName := req.EnrollID
	if req.CN != "" {
		commonName = req.CN
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, req.ExistingKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create CSR")
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	csrData := map[string]interface{}{
		"csr":                 string(csrPEM),
		"common_name":         commonName,
		"use_csr_common_name": true,
		"use_csr_sans":        true,
		"key_type":            "ec",
	}

	if len(req.Hosts) > 0 {
		csrData["alt_names"] = strings.Join(req.Hosts, ",")
	}

	if p.config.TTL != "" {
		csrData["ttl"] = p.config.TTL
	}

	logrus.Infof("Re-enrolling user %s with Vault PKI", req.EnrollID)

	secret, err := p.client.Write(
		ctx,
		fmt.Sprintf("%s/sign/%s", p.config.PKIPath, p.config.Role),
		csrData,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign CSR with Vault PKI")
	}

	// Parse the signed certificate
	certPEM, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, errors.New("failed to get certificate from Vault response")
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse certificate")
	}

	// Parse the CA certificate
	caPEM, ok := secret.Data["issuing_ca"].(string)
	if !ok {
		return nil, errors.New("failed to get issuing CA from Vault response")
	}

	caBlock, _ := pem.Decode([]byte(caPEM))
	if caBlock == nil {
		return nil, errors.New("failed to decode CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse CA certificate")
	}

	return &pki.ReenrollResponse{
		Certificate:     cert,
		RootCertificate: caCert,
	}, nil
}

// Register is not supported by Vault PKI
func (p *Provider) Register(ctx context.Context, req pki.RegisterRequest) (*pki.RegisterResponse, error) {
	return nil, errors.New("identity registration is not supported by Vault PKI provider")
}

// Revoke revokes a certificate using Vault PKI
func (p *Provider) Revoke(ctx context.Context, req pki.RevokeRequest) error {
	// Vault PKI revocation requires the certificate serial number
	if req.Serial == "" {
		return errors.New("certificate serial number is required for Vault revocation")
	}

	revokeData := map[string]interface{}{
		"serial_number": req.Serial,
	}

	_, err := p.client.Write(
		ctx,
		fmt.Sprintf("%s/revoke", p.config.PKIPath),
		revokeData,
	)
	if err != nil {
		return errors.Wrap(err, "failed to revoke certificate")
	}

	logrus.Infof("Revoked certificate with serial %s", req.Serial)
	return nil
}

// GetCAInfo retrieves information about the Vault PKI CA
func (p *Provider) GetCAInfo(ctx context.Context) (*pki.CAInfo, error) {
	// Read the CA certificate from Vault
	secret, err := p.client.Read(
		ctx,
		fmt.Sprintf("%s/cert/ca", p.config.PKIPath),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read CA certificate from Vault")
	}

	caCert, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, errors.New("failed to get CA certificate from Vault response")
	}

	return &pki.CAInfo{
		Name:    p.config.PKIPath,
		CAChain: []byte(caCert),
	}, nil
}

// createVaultClient creates and configures a Vault client
func createVaultClient(config *pki.VaultConfig, clientSet kubernetes.Interface) (*vault.Client, error) {
	vaultConfig := vault.DefaultConfiguration()
	vaultConfig.Address = config.URL

	var tlsConf vault.TLSConfiguration

	// Configure TLS
	if config.TLS.ClientCert != "" && config.TLS.ClientKeySecretRef != nil {
		// Get the client key from the referenced secret
		secretNamespace := config.TLS.ClientKeySecretRef.Namespace
		if secretNamespace == "" {
			secretNamespace = "default"
		}

		secret, err := clientSet.CoreV1().Secrets(secretNamespace).Get(
			context.Background(),
			config.TLS.ClientKeySecretRef.Name,
			v1.GetOptions{},
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get client key secret")
		}

		clientKey := secret.Data[config.TLS.ClientKeySecretRef.Key]
		if clientKey == nil {
			return nil, fmt.Errorf("key %s not found in the secret", config.TLS.ClientKeySecretRef.Key)
		}

		tlsConf = vault.TLSConfiguration{
			ServerName: config.TLS.ServerName,
			ClientCertificate: vault.ClientCertificateEntry{
				FromBytes: []byte(config.TLS.ClientCert),
			},
			ClientCertificateKey: vault.ClientCertificateKeyEntry{
				FromBytes: clientKey,
			},
			InsecureSkipVerify: config.TLS.SkipVerify,
		}

		if config.TLS.CACert != "" {
			tlsConf.ServerCertificate = vault.ServerCertificateEntry{
				FromBytes: []byte(config.TLS.CACert),
			}
		}
	} else if config.TLS.SkipVerify {
		tlsConf = vault.TLSConfiguration{
			InsecureSkipVerify: true,
		}
	} else if config.TLS.CACert != "" {
		tlsConf = vault.TLSConfiguration{
			ServerCertificate: vault.ServerCertificateEntry{
				FromBytes: []byte(config.TLS.CACert),
			},
			InsecureSkipVerify: config.TLS.SkipVerify,
		}
	}

	// Set timeout
	vaultConfig.RequestTimeout = 30 * time.Second

	vaultClientOpts := []vault.ClientOption{
		vault.WithAddress(vaultConfig.Address),
		vault.WithHTTPClient(vaultConfig.HTTPClient),
		vault.WithRetryConfiguration(vaultConfig.RetryConfiguration),
		vault.WithRequestTimeout(vaultConfig.RequestTimeout),
		vault.WithTLS(tlsConf),
	}

	client, err := vault.New(vaultClientOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create Vault client")
	}

	// Handle authentication
	if config.Auth.TokenSecretRef != nil && config.Auth.TokenSecretRef.Name != "" {
		secretNamespace := config.Auth.TokenSecretRef.Namespace
		if secretNamespace == "" {
			secretNamespace = "default"
		}

		secret, err := clientSet.CoreV1().Secrets(secretNamespace).Get(
			context.Background(),
			config.Auth.TokenSecretRef.Name,
			v1.GetOptions{},
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get token secret")
		}

		tokenBytes := secret.Data[config.Auth.TokenSecretRef.Key]
		if tokenBytes == nil {
			return nil, fmt.Errorf("key %s not found in token secret", config.Auth.TokenSecretRef.Key)
		}

		client.SetToken(string(tokenBytes))
	} else if config.Auth.KubernetesAuth != nil {
		// TODO: Implement Kubernetes auth method
		return nil, errors.New("Kubernetes auth method not yet implemented")
	} else {
		return nil, errors.New("no authentication method provided for Vault")
	}

	return client, nil
}
