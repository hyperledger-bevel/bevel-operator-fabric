package ordnode

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

// pkiHelper provides PKI operations for the orderer node controller using the unified PKI interface
type pkiHelper struct {
	clientSet kubernetes.Interface
}

// newPKIHelper creates a new PKI helper
func newPKIHelper(clientSet kubernetes.Interface) *pkiHelper {
	return &pkiHelper{clientSet: clientSet}
}

// createProvider creates the appropriate PKI provider based on credential store configuration
func (h *pkiHelper) createProvider(ctx context.Context, conf *hlfv1alpha1.FabricOrdererNode, enrollment interface{}) (pki.Provider, error) {
	switch conf.Spec.CredentialStore {
	case hlfv1alpha1.CredentialStoreVault:
		return h.createVaultProvider(ctx, enrollment)
	default:
		return h.createFabricCAProvider(ctx, enrollment)
	}
}

// createFabricCAProvider creates a FabricCA PKI provider from enrollment config
func (h *pkiHelper) createFabricCAProvider(ctx context.Context, enrollment interface{}) (pki.Provider, error) {
	var caURL, caName, tlsCert, mspID string

	switch e := enrollment.(type) {
	case *hlfv1alpha1.Component:
		cacert, err := h.getCertBytesFromCATLS(e.Catls)
		if err != nil {
			return nil, err
		}
		caURL = fmt.Sprintf("https://%s:%d", e.Cahost, e.Caport)
		caName = e.Caname
		tlsCert = string(cacert)
	case *hlfv1alpha1.TLSComponent:
		cacert, err := h.getCertBytesFromCATLS(e.Catls)
		if err != nil {
			return nil, err
		}
		caURL = fmt.Sprintf("https://%s:%d", e.Cahost, e.Caport)
		caName = e.Caname
		tlsCert = string(cacert)
	default:
		return nil, errors.New("unsupported enrollment type")
	}

	return pki.NewProvider(&pki.ProviderConfig{
		Type:      pki.ProviderTypeFabricCA,
		ClientSet: h.clientSet,
		FabricCA: &pki.FabricCAConfig{
			URL:     caURL,
			CAName:  caName,
			TLSCert: tlsCert,
			MSPID:   mspID,
		},
	})
}

// createVaultProvider creates a Vault PKI provider from enrollment config
func (h *pkiHelper) createVaultProvider(ctx context.Context, enrollment interface{}) (pki.Provider, error) {
	var vaultConf *hlfv1alpha1.VaultSpecConf
	var vaultReq *hlfv1alpha1.VaultPKICertificateRequest

	switch e := enrollment.(type) {
	case *hlfv1alpha1.Component:
		if e.Vault == nil {
			return nil, errors.New("vault configuration is required for vault credential store")
		}
		vaultConf = &e.Vault.Vault
		vaultReq = &e.Vault.Request
	case *hlfv1alpha1.TLSComponent:
		if e.Vault == nil {
			return nil, errors.New("vault configuration is required for vault credential store")
		}
		vaultConf = &e.Vault.Vault
		vaultReq = &e.Vault.Request
	default:
		return nil, errors.New("unsupported enrollment type")
	}

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

// getTLSHosts returns all TLS hosts for the orderer node
func getTLSHostsForOrderer(conf *hlfv1alpha1.FabricOrdererNode, enrollment *hlfv1alpha1.TLSComponent) []string {
	var hosts []string
	hosts = append(hosts, enrollment.Csr.Hosts...)

	if conf.Spec.Istio != nil {
		hosts = append(hosts, conf.Spec.Istio.Hosts...)
	}
	if conf.Spec.Traefik != nil {
		hosts = append(hosts, conf.Spec.Traefik.Hosts...)
	}
	if conf.Spec.AdminIstio != nil {
		hosts = append(hosts, conf.Spec.AdminIstio.Hosts...)
	}
	if conf.Spec.AdminTraefik != nil {
		hosts = append(hosts, conf.Spec.AdminTraefik.Hosts...)
	}

	return hosts
}

// CreateTLSCryptoMaterialV2 creates TLS crypto material using the PKI interface
func (h *pkiHelper) CreateTLSCryptoMaterialV2(
	ctx context.Context,
	conf *hlfv1alpha1.FabricOrdererNode,
	enrollment *hlfv1alpha1.TLSComponent,
) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, error) {
	provider, err := h.createProvider(ctx, conf, enrollment)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to create PKI provider")
	}

	hosts := getTLSHostsForOrderer(conf, enrollment)

	resp, err := provider.Enroll(ctx, pki.EnrollRequest{
		User:    enrollment.Enrollid,
		Secret:  enrollment.Enrollsecret,
		CN:      enrollment.Enrollid,
		Hosts:   hosts,
		MSPID:   conf.Spec.MspID,
		Profile: "tls",
	})
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to enroll TLS")
	}

	return resp.Certificate, resp.PrivateKey, resp.RootCertificate, nil
}

// CreateTLSAdminCryptoMaterialV2 creates TLS admin crypto material using the PKI interface
func (h *pkiHelper) CreateTLSAdminCryptoMaterialV2(
	ctx context.Context,
	conf *hlfv1alpha1.FabricOrdererNode,
	enrollment *hlfv1alpha1.TLSComponent,
) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, *x509.Certificate, error) {
	provider, err := h.createProvider(ctx, conf, enrollment)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(err, "failed to create PKI provider")
	}

	hosts := getTLSHostsForOrderer(conf, enrollment)

	resp, err := provider.Enroll(ctx, pki.EnrollRequest{
		User:    enrollment.Enrollid,
		Secret:  enrollment.Enrollsecret,
		CN:      enrollment.Enrollid,
		Hosts:   hosts,
		MSPID:   conf.Spec.MspID,
		Profile: "tls",
	})
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(err, "failed to enroll TLS admin")
	}

	// Return root cert twice for admin (client root cert is same as TLS root cert)
	return resp.Certificate, resp.PrivateKey, resp.RootCertificate, resp.RootCertificate, nil
}

// CreateSignCryptoMaterialV2 creates sign crypto material using the PKI interface
func (h *pkiHelper) CreateSignCryptoMaterialV2(
	ctx context.Context,
	conf *hlfv1alpha1.FabricOrdererNode,
	enrollment *hlfv1alpha1.Component,
) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, error) {
	provider, err := h.createProvider(ctx, conf, enrollment)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to create PKI provider")
	}

	resp, err := provider.Enroll(ctx, pki.EnrollRequest{
		User:   enrollment.Enrollid,
		Secret: enrollment.Enrollsecret,
		CN:     conf.Name,
		Hosts:  []string{},
		MSPID:  conf.Spec.MspID,
	})
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to enroll sign")
	}

	return resp.Certificate, resp.PrivateKey, resp.RootCertificate, nil
}

// ReenrollTLSCryptoMaterialV2 re-enrolls TLS crypto material using the PKI interface
func (h *pkiHelper) ReenrollTLSCryptoMaterialV2(
	ctx context.Context,
	conf *hlfv1alpha1.FabricOrdererNode,
	enrollment *hlfv1alpha1.TLSComponent,
	existingCert string,
	existingKey *ecdsa.PrivateKey,
) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, error) {
	provider, err := h.createProvider(ctx, conf, enrollment)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to create PKI provider")
	}

	hosts := getTLSHostsForOrderer(conf, enrollment)

	resp, err := provider.Reenroll(ctx, pki.ReenrollRequest{
		EnrollID:     enrollment.Enrollid,
		CN:           conf.Name,
		Hosts:        hosts,
		MSPID:        conf.Spec.MspID,
		Profile:      "tls",
		ExistingCert: existingCert,
		ExistingKey:  existingKey,
	})
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to re-enroll TLS")
	}

	return resp.Certificate, existingKey, resp.RootCertificate, nil
}

// ReenrollTLSAdminCryptoMaterialV2 re-enrolls TLS admin crypto material using the PKI interface
func (h *pkiHelper) ReenrollTLSAdminCryptoMaterialV2(
	ctx context.Context,
	conf *hlfv1alpha1.FabricOrdererNode,
	enrollment *hlfv1alpha1.TLSComponent,
	existingCert string,
	existingKey *ecdsa.PrivateKey,
) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, *x509.Certificate, error) {
	provider, err := h.createProvider(ctx, conf, enrollment)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(err, "failed to create PKI provider")
	}

	hosts := getTLSHostsForOrderer(conf, enrollment)

	resp, err := provider.Reenroll(ctx, pki.ReenrollRequest{
		EnrollID:     enrollment.Enrollid,
		CN:           conf.Name,
		Hosts:        hosts,
		MSPID:        conf.Spec.MspID,
		Profile:      "tls",
		ExistingCert: existingCert,
		ExistingKey:  existingKey,
	})
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(err, "failed to re-enroll TLS admin")
	}

	// Return root cert twice for admin
	return resp.Certificate, existingKey, resp.RootCertificate, resp.RootCertificate, nil
}

// ReenrollSignCryptoMaterialV2 re-enrolls sign crypto material using the PKI interface
func (h *pkiHelper) ReenrollSignCryptoMaterialV2(
	ctx context.Context,
	conf *hlfv1alpha1.FabricOrdererNode,
	enrollment *hlfv1alpha1.Component,
	existingCert string,
	existingKey *ecdsa.PrivateKey,
) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, error) {
	provider, err := h.createProvider(ctx, conf, enrollment)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to create PKI provider")
	}

	resp, err := provider.Reenroll(ctx, pki.ReenrollRequest{
		EnrollID:     enrollment.Enrollid,
		CN:           "",
		Hosts:        []string{},
		MSPID:        conf.Spec.MspID,
		ExistingCert: existingCert,
		ExistingKey:  existingKey,
	})
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to re-enroll sign")
	}

	return resp.Certificate, existingKey, resp.RootCertificate, nil
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
