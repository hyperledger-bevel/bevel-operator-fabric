package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"

	"github.com/pkg/errors"
	"k8s.io/client-go/kubernetes"
)

// CryptoMaterial holds the certificate and key material
type CryptoMaterial struct {
	Certificate     *x509.Certificate
	PrivateKey      *ecdsa.PrivateKey
	RootCertificate *x509.Certificate
}

// EnrollmentHelper provides a simplified API for enrollment operations.
// It handles the complexity of choosing the right provider based on configuration.
type EnrollmentHelper struct {
	clientSet kubernetes.Interface
}

// NewEnrollmentHelper creates a new EnrollmentHelper
func NewEnrollmentHelper(clientSet kubernetes.Interface) *EnrollmentHelper {
	return &EnrollmentHelper{
		clientSet: clientSet,
	}
}

// EnrollWithFabricCA enrolls a user using Fabric CA
func (h *EnrollmentHelper) EnrollWithFabricCA(
	ctx context.Context,
	caURL string,
	caName string,
	tlsCert string,
	mspID string,
	user string,
	secret string,
	hosts []string,
	cn string,
	profile string,
) (*CryptoMaterial, error) {
	provider, err := NewProvider(&ProviderConfig{
		Type:      ProviderTypeFabricCA,
		ClientSet: h.clientSet,
		FabricCA: &FabricCAConfig{
			URL:     caURL,
			CAName:  caName,
			TLSCert: tlsCert,
			MSPID:   mspID,
		},
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create FabricCA provider")
	}

	resp, err := provider.Enroll(ctx, EnrollRequest{
		User:    user,
		Secret:  secret,
		Hosts:   hosts,
		CN:      cn,
		MSPID:   mspID,
		Profile: profile,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to enroll user")
	}

	return &CryptoMaterial{
		Certificate:     resp.Certificate,
		PrivateKey:      resp.PrivateKey,
		RootCertificate: resp.RootCertificate,
	}, nil
}

// EnrollWithVault enrolls a user using Vault PKI
func (h *EnrollmentHelper) EnrollWithVault(
	ctx context.Context,
	vaultURL string,
	pkiPath string,
	role string,
	ttl string,
	tokenSecretRef *SecretRef,
	mspID string,
	user string,
	hosts []string,
	cn string,
) (*CryptoMaterial, error) {
	provider, err := NewProvider(&ProviderConfig{
		Type:      ProviderTypeVault,
		ClientSet: h.clientSet,
		Vault: &VaultConfig{
			URL:     vaultURL,
			PKIPath: pkiPath,
			Role:    role,
			TTL:     ttl,
			Auth: VaultAuthConfig{
				TokenSecretRef: tokenSecretRef,
			},
		},
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create Vault provider")
	}

	resp, err := provider.Enroll(ctx, EnrollRequest{
		User:  user,
		Hosts: hosts,
		CN:    cn,
		MSPID: mspID,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to enroll user")
	}

	return &CryptoMaterial{
		Certificate:     resp.Certificate,
		PrivateKey:      resp.PrivateKey,
		RootCertificate: resp.RootCertificate,
	}, nil
}

// Reenroll re-enrolls an existing identity
func (h *EnrollmentHelper) Reenroll(
	ctx context.Context,
	provider Provider,
	enrollID string,
	existingCert string,
	existingKey *ecdsa.PrivateKey,
	hosts []string,
	cn string,
	mspID string,
	profile string,
) (*CryptoMaterial, error) {
	resp, err := provider.Reenroll(ctx, ReenrollRequest{
		EnrollID:     enrollID,
		ExistingCert: existingCert,
		ExistingKey:  existingKey,
		Hosts:        hosts,
		CN:           cn,
		MSPID:        mspID,
		Profile:      profile,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to re-enroll user")
	}

	return &CryptoMaterial{
		Certificate:     resp.Certificate,
		PrivateKey:      existingKey, // Key is reused
		RootCertificate: resp.RootCertificate,
	}, nil
}

// CreateProviderFromConfig is a helper function to create a provider from
// generic configuration parameters. This is useful when you have the
// configuration split across different sources.
func CreateProviderFromConfig(
	credentialStore string,
	clientSet kubernetes.Interface,
	// FabricCA config
	caURL string,
	caName string,
	tlsCert string,
	mspID string,
	// Vault config
	vaultURL string,
	pkiPath string,
	role string,
	ttl string,
	tokenSecretRef *SecretRef,
) (Provider, error) {
	switch credentialStore {
	case "vault":
		return NewProvider(&ProviderConfig{
			Type:      ProviderTypeVault,
			ClientSet: clientSet,
			Vault: &VaultConfig{
				URL:     vaultURL,
				PKIPath: pkiPath,
				Role:    role,
				TTL:     ttl,
				Auth: VaultAuthConfig{
					TokenSecretRef: tokenSecretRef,
				},
			},
		})
	case "kubernetes", "":
		return NewProvider(&ProviderConfig{
			Type:      ProviderTypeFabricCA,
			ClientSet: clientSet,
			FabricCA: &FabricCAConfig{
				URL:     caURL,
				CAName:  caName,
				TLSCert: tlsCert,
				MSPID:   mspID,
			},
		})
	default:
		return nil, errors.Errorf("unsupported credential store: %s", credentialStore)
	}
}
