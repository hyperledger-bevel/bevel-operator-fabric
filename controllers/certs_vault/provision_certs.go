// Package certs_vault provides PKI operations using HashiCorp Vault.
//
// Deprecated: This package is deprecated and will be removed in a future version.
// Use the github.com/kfsoftware/hlf-operator/pkg/pki package instead.
// The new PKI package provides a unified interface for both Fabric CA and HashiCorp Vault.
//
// Migration guide:
//
//	Old code:
//	  crt, key, rootCrt, err := certs_vault.EnrollUser(clientSet, vaultConf, request, params)
//
//	New code:
//	  import "github.com/kfsoftware/hlf-operator/pkg/pki"
//	  import _ "github.com/kfsoftware/hlf-operator/pkg/pki/vault"
//
//	  provider, _ := pki.NewProvider(&pki.ProviderConfig{
//	      Type:      pki.ProviderTypeVault,
//	      ClientSet: clientSet,
//	      Vault:     &pki.VaultConfig{...},
//	  })
//	  resp, err := provider.Enroll(ctx, pki.EnrollRequest{...})
package certs_vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/kfsoftware/hlf-operator/internal/github.com/hyperledger/fabric-ca/api"
	"github.com/kfsoftware/hlf-operator/internal/github.com/hyperledger/fabric-ca/lib"
	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type FabricPem struct {
	Pem string `yaml:"pem"`
}
type FabricMultiplePem struct {
	Pem []string `yaml:"pem"`
}
type FabricConfigUser struct {
	Key  FabricPem `yaml:"key"`
	Cert FabricPem `yaml:"cert"`
}
type FabricHttpOptions struct {
	Verify bool `yaml:"verify"`
}
type FabricCryptoStore struct {
	Path string `yaml:"path"`
}
type FabricCredentialStore struct {
	Path        string            `yaml:"path"`
	CryptoStore FabricCryptoStore `yaml:"cryptoStore"`
}
type FabricConfigOrg struct {
	Mspid                  string                      `yaml:"mspid"`
	CryptoPath             string                      `yaml:"cryptoPath"`
	Users                  map[string]FabricConfigUser `yaml:"users,omitempty"`
	CredentialStore        FabricCredentialStore       `yaml:"credentialStore,omitempty"`
	CertificateAuthorities []string                    `yaml:"certificateAuthorities"`
}
type FabricRegistrar struct {
	EnrollID     string `yaml:"enrollId"`
	EnrollSecret string `yaml:"enrollSecret"`
}
type FabricConfigCA struct {
	URL         string            `yaml:"url"`
	CaName      string            `yaml:"caName"`
	TLSCACerts  FabricMultiplePem `yaml:"tlsCACerts"`
	Registrar   FabricRegistrar   `yaml:"registrar"`
	HTTPOptions FabricHttpOptions `yaml:"httpOptions"`
}
type FabricConfigTimeoutParams struct {
	Endorser string `yaml:"endorser"`
}
type FabricConfigTimeout struct {
	Peer FabricConfigTimeoutParams `yaml:"peer"`
}
type FabricConfigConnection struct {
	Timeout FabricConfigTimeout `yaml:"timeout"`
}
type FabricConfigClient struct {
	Organization    string                 `yaml:"organization"`
	CredentialStore FabricCredentialStore  `yaml:"credentialStore,omitempty"`
	Connection      FabricConfigConnection `yaml:"connection"`
}
type FabricConfig struct {
	Name                   string                     `yaml:"name"`
	Version                string                     `yaml:"version"`
	Client                 FabricConfigClient         `yaml:"client"`
	Organizations          map[string]FabricConfigOrg `yaml:"organizations"`
	CertificateAuthorities map[string]FabricConfigCA  `yaml:"certificateAuthorities"`
}

type FabricCAParams struct {
	TLSCert      string
	URL          string
	Name         string
	MSPID        string
	EnrollID     string
	EnrollSecret string
}

type EnrollUserRequest struct {
	MSPID      string
	User       string
	Hosts      []string
	CN         string
	Attributes []*api.AttributeRequest
}
type ReenrollUserRequest struct {
	EnrollID   string
	MSPID      string
	Hosts      []string
	CN         string
	Attributes []*api.AttributeRequest
}
type GetCAInfoRequest struct {
	TLSCert string
	URL     string
	Name    string
	MSPID   string
}
type RevokeUserRequest struct {
	TLSCert           string
	URL               string
	Name              string
	MSPID             string
	EnrollID          string
	EnrollSecret      string
	RevocationRequest *api.RevocationRequest
}

func RevokeUser(params RevokeUserRequest) error {
	// Get a Kubernetes clientset
	config, err := rest.InClusterConfig()
	if err != nil {
		return errors.Wrap(err, "failed to get in-cluster config")
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return errors.Wrap(err, "failed to create Kubernetes client")
	}

	// Convert params using the helper function and get the client
	vaultConf := convertToVaultConfig(FabricCAParams{
		TLSCert:      params.TLSCert,
		URL:          params.URL,
		Name:         params.Name,
		MSPID:        params.MSPID,
		EnrollID:     params.EnrollID,
		EnrollSecret: params.EnrollSecret,
	})

	vaultClient, err := GetClient(vaultConf, clientset)
	if err != nil {
		return err
	}
	_ = vaultClient

	// This function expected to use a Fabric CA client, not a Vault client
	// We need to implement the equivalent functionality using Vault
	return fmt.Errorf("RevokeUser functionality not implemented for Vault yet")
}

type RegisterUserRequest struct {
	TLSCert      string
	URL          string
	Name         string
	MSPID        string
	EnrollID     string
	EnrollSecret string
	User         string
	Secret       string
	Type         string
	Attributes   []api.Attribute
}

func RegisterUser(params RegisterUserRequest) (string, error) {
	// Get a Kubernetes clientset
	config, err := rest.InClusterConfig()
	if err != nil {
		return "", errors.Wrap(err, "failed to get in-cluster config")
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return "", errors.Wrap(err, "failed to create Kubernetes client")
	}

	// Convert params using the helper function and get the client
	vaultConf := convertToVaultConfig(FabricCAParams{
		TLSCert:      params.TLSCert,
		URL:          params.URL,
		Name:         params.Name,
		MSPID:        params.MSPID,
		EnrollID:     params.EnrollID,
		EnrollSecret: params.EnrollSecret,
	})

	vaultClient, err := GetClient(vaultConf, clientset)
	if err != nil {
		return "", err
	}
	_ = vaultClient
	// This function expected to use a Fabric CA client, not a Vault client
	// We need to implement the equivalent functionality using Vault
	return "", fmt.Errorf("RegisterUser functionality not implemented for Vault yet")
}

type CreateCARequest struct {
	Name         string
	Subject      hlfv1alpha1.FabricCASubject
	SerialNumber *big.Int
}

// CreateCA creates a CA certificate in Vault's PKI backend
func CreateCA(ctx context.Context, req CreateCARequest, clientset *kubernetes.Clientset, vaultClient *vault.Client) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	logrus.Infof("Creating CA in Vault for %s", req.Name)

	// Check if CA certificate already exists in Vault
	secretPath := fmt.Sprintf("secret/data/hlf-ca/%s", req.Name)
	secret, err := vaultClient.Secrets.KvV2Read(ctx, secretPath)
	if err == nil && secret.Data.Data != nil {
		// CA exists, retrieve it
		logrus.Infof("CA certificate already exists for %s, retrieving it", req.Name)

		certPEM, ok := secret.Data.Data["certificate"].(string)
		if !ok {
			return nil, nil, errors.New("failed to retrieve certificate from Vault")
		}

		keyPEM, ok := secret.Data.Data["private_key"].(string)
		if !ok {
			return nil, nil, errors.New("failed to retrieve private key from Vault")
		}

		// Parse the certificate
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			return nil, nil, errors.New("failed to parse certificate PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to parse certificate")
		}

		// Parse the private key
		block, _ = pem.Decode([]byte(keyPEM))
		if block == nil {
			return nil, nil, errors.New("failed to parse private key PEM")
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to parse private key")
		}

		logrus.Infof("Successfully retrieved existing CA certificate for %s from Vault", req.Name)
		return cert, key, nil
	}

	// Generate a new CA certificate
	logrus.Infof("Generating new root certificate for %s", req.Name)
	serialNumber := req.SerialNumber
	if serialNumber == nil {
		// Generate a random serial number if not provided
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		var genErr error
		serialNumber, genErr = rand.Int(rand.Reader, serialNumberLimit)
		if genErr != nil {
			return nil, nil, errors.Wrap(genErr, "failed to generate serial number")
		}
	}

	// Generate private key
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate private key")
	}

	// Create certificate template
	x509Cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         req.Subject.CN,
			Organization:       []string{req.Subject.O},
			Country:            []string{req.Subject.C},
			Locality:           []string{req.Subject.L},
			OrganizationalUnit: []string{req.Subject.OU},
			StreetAddress:      []string{req.Subject.ST},
		},
		NotBefore:             time.Now().AddDate(0, 0, -1),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, x509Cert, x509Cert, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to create certificate")
	}

	// Convert certificate to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// Convert private key to PEM format
	privKeyBytes, err := x509.MarshalECPrivateKey(caPrivKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to marshal private key")
	}
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	// Store in Vault
	data := map[string]interface{}{
		"certificate": string(certPEM),
		"private_key": string(privKeyPEM),
	}

	// Write to Vault
	_, err = vaultClient.Secrets.KvV2Write(ctx, secretPath, schema.KvV2WriteRequest{
		Data: data,
	})
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to store CA in Vault")
	}

	// Parse the certificate
	crt, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to parse certificate")
	}

	logrus.Infof("Successfully created CA certificate for %s in Vault", req.Name)
	return crt, caPrivKey, nil
}

// CreateDefaultCAWithVault creates a default CA certificate in Vault
func CreateDefaultCAWithVault(ctx context.Context, fabricCA *hlfv1alpha1.FabricCA, conf hlfv1alpha1.FabricCAItemConf, clientset *kubernetes.Clientset, vaultClient *vault.Client, caReq CreateCARequest) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	// Create the CA request
	return CreateCA(ctx, caReq, clientset, vaultClient)
}

func GetCAInfo(params GetCAInfoRequest) (*lib.GetCAInfoResponse, error) {
	// Get a Kubernetes clientset
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get in-cluster config")
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create Kubernetes client")
	}

	// Convert params using the helper function and get the client
	vaultConf := convertToVaultConfig(FabricCAParams{
		TLSCert: params.TLSCert,
		URL:     params.URL,
		Name:    params.Name,
		MSPID:   params.MSPID,
	})

	vaultClient, err := GetClient(vaultConf, clientset)
	if err != nil {
		return nil, err
	}
	_ = vaultClient
	// This function expected to use a Fabric CA client, not a Vault client
	// We need to implement the equivalent functionality using Vault
	return nil, fmt.Errorf("GetCAInfo functionality not implemented for Vault yet")
}

func ReenrollUser(clientSet kubernetes.Interface, spec *hlfv1alpha1.VaultSpecConf, request *hlfv1alpha1.VaultPKICertificateRequest, params ReenrollUserRequest, certPem string, ecdsaKey *ecdsa.PrivateKey) (*x509.Certificate, *x509.Certificate, error) {
	vaultClient, err := GetClient(spec, clientSet)
	if err != nil {
		return nil, nil, err
	}

	commonName := params.EnrollID

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, ecdsaKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to create CSR")
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
	if params.CN != "" {
		csrData["common_name"] = params.CN
	}

	if len(params.Hosts) > 0 {
		csrData["alt_names"] = strings.Join(params.Hosts, ",")
	}

	if request.TTL != "" {
		csrData["ttl"] = request.TTL
	}

	log.Infof("reenrolling certs for %s", commonName)

	secret, err := vaultClient.Write(
		context.Background(),
		fmt.Sprintf("%s/sign/%s", request.PKI, request.Role),
		csrData,
	)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to issue certificate from Vault PKI")
	}

	// Parse the signed certificate
	certPEM := secret.Data["certificate"].(string)
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, nil, errors.New("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to parse certificate")
	}

	// Parse the CA certificate
	caCertPEM := secret.Data["issuing_ca"].(string)
	caBlock, _ := pem.Decode([]byte(caCertPEM))
	if caBlock == nil {
		return nil, nil, errors.New("failed to decode CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to parse CA certificate")
	}

	return cert, caCert, nil
}
func EnrollUser(clientSet kubernetes.Interface, vaultConf *hlfv1alpha1.VaultSpecConf, request *hlfv1alpha1.VaultPKICertificateRequest, params EnrollUserRequest) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, error) {
	// Use the provided VaultSpecConf to get a client
	vaultClient, err := GetClient(vaultConf, clientSet)
	if err != nil {
		return nil, nil, nil, err
	}

	// Generate a new private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to generate private key")
	}

	// Create a CSR template
	commonName := params.User
	if params.CN != "" {
		commonName = params.CN
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
	}

	// Add SANs if hosts are provided
	if len(params.Hosts) > 0 {
		template.DNSNames = params.Hosts
	}

	// Create CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to create CSR")
	}

	// Encode CSR to PEM
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
	if request.TTL != "" {
		csrData["ttl"] = request.TTL
	}

	// Request certificate from Vault PKI using the CSR
	secret, err := vaultClient.Write(
		context.Background(),
		fmt.Sprintf("%s/sign/%s", request.PKI, request.Role),
		csrData,
	)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to sign CSR with Vault PKI")
	}

	// Parse the signed certificate
	certPEM := secret.Data["certificate"].(string)
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, nil, nil, errors.New("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to parse certificate")
	}

	// Parse the CA certificate
	caPEM := secret.Data["issuing_ca"].(string)
	caBlock, _ := pem.Decode([]byte(caPEM))
	if caBlock == nil {
		return nil, nil, nil, errors.New("failed to decode CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to parse CA certificate")
	}

	return cert, privateKey, caCert, nil
}

type GetUserRequest struct {
	TLSCert      string
	URL          string
	Name         string
	MSPID        string
	EnrollID     string
	EnrollSecret string
	User         string
}

// Helper function to convert from the old FabricCAParams to VaultSpecConf
func convertToVaultConfig(params FabricCAParams) *hlfv1alpha1.VaultSpecConf {
	// This is a simplified conversion - you may need to add more fields
	// depending on your specific requirements
	return &hlfv1alpha1.VaultSpecConf{
		URL:           params.URL,
		TLSSkipVerify: true, // You might want to make this configurable
		ServerCert:    params.TLSCert,
		// Additional fields would need to be populated as needed
	}
}

func GetClient(spec *hlfv1alpha1.VaultSpecConf, clientset kubernetes.Interface) (*vault.Client, error) {
	// Configure Vault client
	vaultConfig := vault.DefaultConfiguration()
	vaultConfig.Address = spec.URL
	var tlsConf vault.TLSConfiguration

	// Configure TLS if client certificate is provided
	if spec.ClientCert != "" && spec.ClientKeySecretRef != nil {
		// Get the client key from the referenced secret
		secretNamespace := spec.ClientKeySecretRef.Namespace
		if secretNamespace == "" {
			// Default to the same namespace if not specified
			secretNamespace = "default"
		}

		secret, err := clientset.CoreV1().Secrets(secretNamespace).Get(
			context.Background(),
			spec.ClientKeySecretRef.Name,
			v1.GetOptions{},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to get client key secret: %w", err)
		}

		// Extract client key from the secret
		clientKey := secret.Data[spec.ClientKeySecretRef.Key]
		if clientKey == nil {
			return nil, fmt.Errorf("key %s not found in the secret", spec.ClientKeySecretRef.Key)
		}

		// Configure TLS with the cert and key files
		tlsConf = vault.TLSConfiguration{
			ServerName: spec.ServerName,
			ClientCertificate: vault.ClientCertificateEntry{
				FromBytes: []byte(spec.ClientCert),
			},
			ClientCertificateKey: vault.ClientCertificateKeyEntry{
				FromBytes: clientKey,
			},
			InsecureSkipVerify: spec.TLSSkipVerify,
		}
		if spec.ServerName != "" {
			tlsConf.ServerName = spec.ServerName
		}
		if spec.ServerCert != "" {
			tlsConf.ServerCertificate = vault.ServerCertificateEntry{
				FromBytes: []byte(spec.ServerCert),
			}
		}
	} else if spec.TLSSkipVerify {
		tlsConf = vault.TLSConfiguration{
			InsecureSkipVerify: true,
		}
	} else if spec.CACert != "" {
		tlsConf = vault.TLSConfiguration{
			ServerCertificate: vault.ServerCertificateEntry{
				FromBytes: []byte(spec.CACert),
			},
			InsecureSkipVerify: spec.TLSSkipVerify,
		}
	}

	// Set timeout
	if spec.Timeout != "" {
		timeout, err := time.ParseDuration(spec.Timeout)
		if err != nil {
			return nil, fmt.Errorf("invalid timeout format: %w", err)
		}
		vaultConfig.RequestTimeout = timeout
	}

	// Set max retries
	vaultConfig.RetryConfiguration.RetryMax = spec.MaxRetries
	vaultClientOpts := []vault.ClientOption{
		vault.WithAddress(vaultConfig.Address),
		vault.WithHTTPClient(vaultConfig.HTTPClient),
		vault.WithRetryConfiguration(vaultConfig.RetryConfiguration),
		vault.WithRequestTimeout(vaultConfig.RequestTimeout),
		vault.WithTLS(tlsConf),
	}

	// Create the Vault client
	client, err := vault.New(
		vaultClientOpts...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Handle authentication methods
	if spec.TokenSecretRef != nil && spec.TokenSecretRef.Name != "" {
		// Get token from Kubernetes secret
		secretNamespace := spec.TokenSecretRef.Namespace
		if secretNamespace == "" {
			secretNamespace = "default"
		}

		secret, err := clientset.CoreV1().Secrets(secretNamespace).Get(
			context.Background(),
			spec.TokenSecretRef.Name,
			v1.GetOptions{},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to get token secret: %w", err)
		}

		tokenBytes := secret.Data[spec.TokenSecretRef.Key]
		if tokenBytes == nil {
			return nil, fmt.Errorf("key %s not found in token secret", spec.TokenSecretRef.Key)
		}

		client.SetToken(string(tokenBytes))
	} else if spec.Role != "" && spec.SecretIdSecretRef != nil {
		return nil, fmt.Errorf("role and secretId not implemented yet")
	} else {
		return nil, fmt.Errorf("no authentication method provided for Vault")
	}

	return client, nil
}
