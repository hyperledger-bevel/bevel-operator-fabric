package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/kfsoftware/hlf-operator/pkg/pki"
	"github.com/pkg/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// pkiHelper provides PKI operations for the identity controller using the unified PKI interface
type pkiHelper struct {
	clientSet kubernetes.Interface
}

// newPKIHelper creates a new PKI helper
func newPKIHelper(clientSet kubernetes.Interface) *pkiHelper {
	return &pkiHelper{clientSet: clientSet}
}

// createProvider creates the appropriate PKI provider based on credential store configuration
func (h *pkiHelper) createProvider(ctx context.Context, conf *hlfv1alpha1.FabricIdentity) (pki.Provider, error) {
	switch conf.Spec.CredentialStore {
	case hlfv1alpha1.CredentialStoreVault:
		return h.createVaultProvider(ctx, conf)
	default:
		return h.createFabricCAProvider(ctx, conf)
	}
}

// createFabricCAProvider creates a FabricCA PKI provider from identity config
func (h *pkiHelper) createFabricCAProvider(ctx context.Context, conf *hlfv1alpha1.FabricIdentity) (pki.Provider, error) {
	cacert, err := h.getCertBytesFromCATLS(conf.Spec.Catls)
	if err != nil {
		return nil, err
	}

	caURL := fmt.Sprintf("https://%s:%d", conf.Spec.Cahost, conf.Spec.Caport)

	return pki.NewProvider(&pki.ProviderConfig{
		Type:      pki.ProviderTypeFabricCA,
		ClientSet: h.clientSet,
		FabricCA: &pki.FabricCAConfig{
			URL:     caURL,
			CAName:  conf.Spec.Caname,
			TLSCert: string(cacert),
			MSPID:   conf.Spec.MSPID,
		},
	})
}

// createVaultProvider creates a Vault PKI provider from identity config
func (h *pkiHelper) createVaultProvider(ctx context.Context, conf *hlfv1alpha1.FabricIdentity) (pki.Provider, error) {
	if conf.Spec.Vault == nil {
		return nil, errors.New("vault configuration is required for vault credential store")
	}

	vaultConf := &conf.Spec.Vault.Vault
	vaultReq := &conf.Spec.Vault.Request

	return pki.NewProvider(&pki.ProviderConfig{
		Type:      pki.ProviderTypeVault,
		ClientSet: h.clientSet,
		Vault: &pki.VaultConfig{
			URL:     vaultConf.URL,
			PKIPath: vaultReq.PKI,
			Role:    vaultReq.Role,
			TTL:     vaultReq.TTL,
			Auth: pki.VaultAuthConfig{
				TokenSecretRef: convertSecretRef(vaultConf.TokenSecretRef),
			},
			TLS: pki.VaultTLSConfig{
				CACert:             vaultConf.CACert,
				ClientCert:         vaultConf.ClientCert,
				ClientKeySecretRef: convertSecretRef(vaultConf.ClientKeySecretRef),
				ServerName:         vaultConf.ServerName,
				SkipVerify:         vaultConf.TLSSkipVerify,
			},
		},
	})
}

// CreateSignCryptoMaterialV2 creates sign crypto material using the PKI interface
func (h *pkiHelper) CreateSignCryptoMaterialV2(
	ctx context.Context,
	conf *hlfv1alpha1.FabricIdentity,
) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, error) {
	provider, err := h.createProvider(ctx, conf)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to create PKI provider")
	}

	resp, err := provider.Enroll(ctx, pki.EnrollRequest{
		User:    conf.Spec.Enrollid,
		Secret:  conf.Spec.Enrollsecret,
		CN:      conf.Name,
		Hosts:   []string{},
		MSPID:   conf.Spec.MSPID,
		Profile: "",
	})
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to enroll identity")
	}

	return resp.Certificate, resp.PrivateKey, resp.RootCertificate, nil
}

// ReenrollSignCryptoMaterialV2 re-enrolls sign crypto material using the PKI interface
func (h *pkiHelper) ReenrollSignCryptoMaterialV2(
	ctx context.Context,
	conf *hlfv1alpha1.FabricIdentity,
	existingCert string,
	existingKey *ecdsa.PrivateKey,
) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, error) {
	provider, err := h.createProvider(ctx, conf)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to create PKI provider")
	}

	resp, err := provider.Reenroll(ctx, pki.ReenrollRequest{
		EnrollID:     conf.Spec.Enrollid,
		CN:           conf.Name,
		Hosts:        []string{},
		MSPID:        conf.Spec.MSPID,
		Profile:      "",
		ExistingCert: existingCert,
		ExistingKey:  existingKey,
	})
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to re-enroll identity")
	}

	return resp.Certificate, existingKey, resp.RootCertificate, nil
}

// RegisterUserV2 registers a user using the PKI interface
func (h *pkiHelper) RegisterUserV2(
	ctx context.Context,
	conf *hlfv1alpha1.FabricIdentity,
	attributes []pki.Attribute,
) (string, error) {
	provider, err := h.createProvider(ctx, conf)
	if err != nil {
		return "", errors.Wrap(err, "failed to create PKI provider")
	}

	// Check if provider supports registration
	if supporter, ok := provider.(pki.RegistrationSupporter); ok {
		if !supporter.SupportsRegistration() {
			return "", errors.Errorf("provider %s does not support identity registration", provider.Type())
		}
	}

	resp, err := provider.Register(ctx, pki.RegisterRequest{
		EnrollID:     conf.Spec.Register.Enrollid,
		EnrollSecret: conf.Spec.Register.Enrollsecret,
		User:         conf.Spec.Enrollid,
		Secret:       conf.Spec.Enrollsecret,
		Type:         conf.Spec.Register.Type,
		MSPID:        conf.Spec.MSPID,
		Attributes:   attributes,
	})
	if err != nil {
		return "", errors.Wrap(err, "failed to register identity")
	}

	return resp.Secret, nil
}

// getCertBytesFromCATLS retrieves the CA TLS certificate bytes
func (h *pkiHelper) getCertBytesFromCATLS(caTls *hlfv1alpha1.Catls) ([]byte, error) {
	var certBytes []byte
	var err error

	if caTls.Cacert != "" {
		certBytes, err = base64.StdEncoding.DecodeString(caTls.Cacert)
		if err != nil {
			return nil, errors.Wrap(err, "failed to decode CA cert from base64")
		}
	} else if caTls.SecretRef != nil {
		secret, err := h.clientSet.CoreV1().Secrets(caTls.SecretRef.Namespace).Get(
			context.Background(),
			caTls.SecretRef.Name,
			v1.GetOptions{},
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get CA cert secret")
		}
		certBytes = secret.Data[caTls.SecretRef.Key]
	} else {
		return nil, errors.New("invalid CA TLS configuration: neither cacert nor secretRef provided")
	}

	return certBytes, nil
}

// convertSecretRef converts from hlfv1alpha1.VaultSecretRef to pki.SecretRef
func convertSecretRef(ref *hlfv1alpha1.VaultSecretRef) *pki.SecretRef {
	if ref == nil {
		return nil
	}
	return &pki.SecretRef{
		Namespace: ref.Namespace,
		Name:      ref.Name,
		Key:       ref.Key,
	}
}
