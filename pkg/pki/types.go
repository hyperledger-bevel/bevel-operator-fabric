package pki

import (
	"crypto/ecdsa"
	"crypto/x509"

	"k8s.io/client-go/kubernetes"
)

// EnrollRequest contains the parameters needed for enrolling a new identity
type EnrollRequest struct {
	// User is the enrollment ID
	User string
	// Secret is the enrollment secret (used by Fabric CA, ignored by Vault)
	Secret string
	// CommonName for the certificate
	CN string
	// Hosts are the DNS/IP SANs to include in the certificate
	Hosts []string
	// MSPID is the Membership Service Provider ID
	MSPID string
	// Profile is the enrollment profile (e.g., "tls", "ca")
	Profile string
	// Attributes to include in the certificate
	Attributes []AttributeRequest
}

// ReenrollRequest contains parameters for re-enrolling an existing identity
type ReenrollRequest struct {
	// EnrollID is the identity's enrollment ID
	EnrollID string
	// CommonName for the certificate
	CN string
	// Hosts are the DNS/IP SANs to include in the certificate
	Hosts []string
	// MSPID is the Membership Service Provider ID
	MSPID string
	// Profile is the enrollment profile
	Profile string
	// Attributes to include in the certificate
	Attributes []AttributeRequest
	// ExistingCert is the current certificate PEM
	ExistingCert string
	// ExistingKey is the existing private key to reuse
	ExistingKey *ecdsa.PrivateKey
}

// RegisterRequest contains parameters for registering a new identity
type RegisterRequest struct {
	// EnrollID is the registrar's enrollment ID
	EnrollID string
	// EnrollSecret is the registrar's enrollment secret
	EnrollSecret string
	// User is the new user's enrollment ID
	User string
	// Secret is the new user's enrollment secret
	Secret string
	// Type is the identity type (e.g., "client", "peer", "orderer")
	Type string
	// MSPID is the Membership Service Provider ID
	MSPID string
	// Attributes to assign to the identity
	Attributes []Attribute
	// MaxEnrollments is the maximum number of times the identity can enroll (-1 for unlimited)
	MaxEnrollments int
}

// RevokeRequest contains parameters for revoking a certificate
type RevokeRequest struct {
	// EnrollID is the registrar's enrollment ID
	EnrollID string
	// EnrollSecret is the registrar's enrollment secret
	EnrollSecret string
	// Name is the identity name to revoke
	Name string
	// Serial is the certificate serial number (optional)
	Serial string
	// AKI is the Authority Key Identifier (optional)
	AKI string
	// Reason is the revocation reason
	Reason string
	// GenCRL indicates whether to generate a new CRL
	GenCRL bool
}

// EnrollResponse contains the results of an enrollment operation
type EnrollResponse struct {
	// Certificate is the enrolled certificate
	Certificate *x509.Certificate
	// PrivateKey is the private key for the certificate
	PrivateKey *ecdsa.PrivateKey
	// RootCertificate is the CA's root certificate
	RootCertificate *x509.Certificate
}

// ReenrollResponse contains the results of a re-enrollment operation
type ReenrollResponse struct {
	// Certificate is the renewed certificate
	Certificate *x509.Certificate
	// RootCertificate is the CA's root certificate
	RootCertificate *x509.Certificate
}

// RegisterResponse contains the results of a registration operation
type RegisterResponse struct {
	// Secret is the enrollment secret for the registered identity
	Secret string
}

// CAInfo contains information about a Certificate Authority
type CAInfo struct {
	// Name is the CA name
	Name string
	// CAChain is the certificate chain in PEM format
	CAChain []byte
	// Version is the CA version
	Version string
}

// AttributeRequest specifies an attribute to request during enrollment
type AttributeRequest struct {
	// Name is the attribute name
	Name string
	// Optional indicates if the attribute is optional
	Optional bool
}

// Attribute represents an attribute to assign during registration
type Attribute struct {
	// Name is the attribute name
	Name string
	// Value is the attribute value
	Value string
	// ECert indicates if the attribute should be included in the enrollment certificate
	ECert bool
}

// ProviderConfig holds the configuration needed to create a PKI provider
type ProviderConfig struct {
	// Type specifies the provider type ("fabricca" or "vault")
	Type ProviderType

	// Kubernetes clientset for accessing secrets
	ClientSet kubernetes.Interface

	// FabricCA-specific configuration
	FabricCA *FabricCAConfig

	// Vault-specific configuration
	Vault *VaultConfig
}

// ProviderType represents the type of PKI provider
type ProviderType string

const (
	// ProviderTypeFabricCA indicates a Fabric CA provider
	ProviderTypeFabricCA ProviderType = "fabricca"
	// ProviderTypeVault indicates a HashiCorp Vault provider
	ProviderTypeVault ProviderType = "vault"
)

// FabricCAConfig contains configuration for connecting to a Fabric CA
type FabricCAConfig struct {
	// URL is the CA server URL
	URL string
	// CAName is the name of the CA
	CAName string
	// TLSCert is the TLS certificate for connecting to the CA (PEM format)
	TLSCert string
	// MSPID is the MSP identifier
	MSPID string
}

// VaultConfig contains configuration for connecting to HashiCorp Vault
type VaultConfig struct {
	// URL is the Vault server URL
	URL string
	// PKIPath is the path to the PKI secrets engine
	PKIPath string
	// Role is the PKI role to use for issuing certificates
	Role string
	// TTL is the requested certificate TTL
	TTL string
	// Auth contains authentication configuration
	Auth VaultAuthConfig
	// TLS contains TLS configuration
	TLS VaultTLSConfig
}

// VaultAuthConfig contains Vault authentication configuration
type VaultAuthConfig struct {
	// TokenSecretRef references a Kubernetes secret containing the Vault token
	TokenSecretRef *SecretRef
	// KubernetesAuth contains Kubernetes auth method configuration
	KubernetesAuth *VaultKubernetesAuth
}

// VaultKubernetesAuth contains Vault Kubernetes auth configuration
type VaultKubernetesAuth struct {
	// Role is the Vault role for Kubernetes auth
	Role string
	// MountPath is the auth method mount path
	MountPath string
	// ServiceAccountTokenPath is the path to the service account token
	ServiceAccountTokenPath string
}

// VaultTLSConfig contains Vault TLS configuration
type VaultTLSConfig struct {
	// CACert is the CA certificate for verifying the Vault server
	CACert string
	// ClientCert is the client certificate for mTLS
	ClientCert string
	// ClientKeySecretRef references a Kubernetes secret containing the client key
	ClientKeySecretRef *SecretRef
	// ServerName is the expected server name for TLS verification
	ServerName string
	// SkipVerify disables TLS verification
	SkipVerify bool
}

// SecretRef references a key in a Kubernetes secret
type SecretRef struct {
	// Namespace is the secret namespace
	Namespace string
	// Name is the secret name
	Name string
	// Key is the key within the secret
	Key string
}
