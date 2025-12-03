package fabricca

import (
	"context"
	"crypto/ecdsa"
	"io/ioutil"
	"path/filepath"

	"github.com/hyperledger/fabric/bccsp"
	bccsputils "github.com/hyperledger/fabric/bccsp/utils"
	"github.com/kfsoftware/hlf-operator/controllers/utils"
	"github.com/kfsoftware/hlf-operator/internal/github.com/hyperledger/fabric-ca/api"
	"github.com/kfsoftware/hlf-operator/internal/github.com/hyperledger/fabric-ca/lib"
	"github.com/kfsoftware/hlf-operator/internal/github.com/hyperledger/fabric-ca/lib/client/credential"
	fabricx509 "github.com/kfsoftware/hlf-operator/internal/github.com/hyperledger/fabric-ca/lib/client/credential/x509"
	"github.com/kfsoftware/hlf-operator/internal/github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/kfsoftware/hlf-operator/pkg/pki"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func init() {
	// Register the FabricCA provider factory
	pki.RegisterProvider(pki.ProviderTypeFabricCA, func(config *pki.ProviderConfig) (pki.Provider, error) {
		return NewProvider(config.FabricCA)
	})
}

// Provider implements the pki.Provider interface for Fabric CA
type Provider struct {
	config *pki.FabricCAConfig
	client *lib.Client
}

// Ensure Provider implements the pki.Provider interface
var _ pki.Provider = (*Provider)(nil)
var _ pki.RegistrationSupporter = (*Provider)(nil)
var _ pki.RevocationSupporter = (*Provider)(nil)

// NewProvider creates a new Fabric CA PKI provider
func NewProvider(config *pki.FabricCAConfig) (*Provider, error) {
	if config == nil {
		return nil, errors.New("fabric CA config is required")
	}
	if config.URL == "" {
		return nil, errors.New("fabric CA URL is required")
	}

	client, err := createClient(config)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create Fabric CA client")
	}

	return &Provider{
		config: config,
		client: client,
	}, nil
}

// Type returns the provider type
func (p *Provider) Type() pki.ProviderType {
	return pki.ProviderTypeFabricCA
}

// SupportsRegistration returns true as Fabric CA supports identity registration
func (p *Provider) SupportsRegistration() bool {
	return true
}

// SupportsRevocation returns true as Fabric CA supports certificate revocation
func (p *Provider) SupportsRevocation() bool {
	return true
}

// Enroll enrolls a new identity with the Fabric CA
func (p *Provider) Enroll(ctx context.Context, req pki.EnrollRequest) (*pki.EnrollResponse, error) {
	attrReqs := convertAttributeRequests(req.Attributes)

	enrollmentRequest := &api.EnrollmentRequest{
		Name:     req.User,
		Secret:   req.Secret,
		CAName:   p.config.CAName,
		AttrReqs: attrReqs,
		Profile:  req.Profile,
		Label:    "",
		Type:     "x509",
		CSR: &api.CSRInfo{
			Hosts: req.Hosts,
			CN:    req.CN,
		},
	}

	logrus.Infof("Enrolling user %s with Fabric CA", req.User)

	enrollResponse, err := p.client.Enroll(enrollmentRequest)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to enroll user %s", req.User)
	}

	userCrt := enrollResponse.Identity.GetECert().GetX509Cert()

	info, err := p.client.GetCAInfo(&api.GetCAInfoRequest{
		CAName: p.config.CAName,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to get CA info")
	}

	rootCrt, err := utils.ParseX509Certificate(info.CAChain)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse CA chain")
	}

	userKey, err := p.readKey()
	if err != nil {
		return nil, errors.Wrap(err, "failed to read private key")
	}

	return &pki.EnrollResponse{
		Certificate:     userCrt,
		PrivateKey:      userKey,
		RootCertificate: rootCrt,
	}, nil
}

// Reenroll re-enrolls an existing identity
func (p *Provider) Reenroll(ctx context.Context, req pki.ReenrollRequest) (*pki.ReenrollResponse, error) {
	if req.ExistingKey == nil {
		return nil, errors.New("existing private key is required for re-enrollment")
	}
	if req.ExistingCert == "" {
		return nil, errors.New("existing certificate is required for re-enrollment")
	}

	priv, err := bccsputils.PrivateKeyToDER(req.ExistingKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert ECDSA private key")
	}

	bccspKey, err := p.client.GetCSP().KeyImport(priv, &bccsp.ECDSAPrivateKeyImportOpts{Temporary: true})
	if err != nil {
		return nil, errors.Wrap(err, "failed to import private key")
	}

	signer, err := fabricx509.NewSigner(bccspKey, []byte(req.ExistingCert))
	if err != nil {
		return nil, errors.Wrap(err, "failed to create signer")
	}

	cred := fabricx509.NewCredential("", "", p.client)
	if err := cred.SetVal(signer); err != nil {
		return nil, errors.Wrap(err, "failed to set credential value")
	}

	id := lib.NewIdentity(
		p.client,
		req.EnrollID,
		[]credential.Credential{cred},
	)

	attrReqs := convertAttributeRequests(req.Attributes)

	reenrollResponse, err := id.Reenroll(&api.ReenrollmentRequest{
		CAName:   p.config.CAName,
		AttrReqs: attrReqs,
		Profile:  req.Profile,
		Label:    "",
		CSR: &api.CSRInfo{
			Hosts: req.Hosts,
			CN:    req.CN,
			KeyRequest: &api.KeyRequest{
				ReuseKey: true,
			},
		},
	})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to re-enroll user %s", req.EnrollID)
	}

	userCrt := reenrollResponse.Identity.GetECert().GetX509Cert()

	info, err := p.client.GetCAInfo(&api.GetCAInfoRequest{
		CAName: p.config.CAName,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to get CA info")
	}

	rootCrt, err := utils.ParseX509Certificate(info.CAChain)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse CA chain")
	}

	return &pki.ReenrollResponse{
		Certificate:     userCrt,
		RootCertificate: rootCrt,
	}, nil
}

// Register registers a new identity with the Fabric CA
func (p *Provider) Register(ctx context.Context, req pki.RegisterRequest) (*pki.RegisterResponse, error) {
	// First, enroll the registrar
	enrollResponse, err := p.client.Enroll(&api.EnrollmentRequest{
		Name:     req.EnrollID,
		Secret:   req.EnrollSecret,
		CAName:   p.config.CAName,
		AttrReqs: []*api.AttributeRequest{},
		Type:     req.Type,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to enroll registrar")
	}

	attrs := convertAttributes(req.Attributes)
	maxEnrollments := req.MaxEnrollments
	if maxEnrollments == 0 {
		maxEnrollments = -1 // unlimited
	}

	secret, err := enrollResponse.Identity.Register(&api.RegistrationRequest{
		Name:           req.User,
		Type:           req.Type,
		MaxEnrollments: maxEnrollments,
		Affiliation:    "",
		Attributes:     attrs,
		CAName:         p.config.CAName,
		Secret:         req.Secret,
	})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to register user %s", req.User)
	}

	return &pki.RegisterResponse{
		Secret: secret.Secret,
	}, nil
}

// Revoke revokes a certificate
func (p *Provider) Revoke(ctx context.Context, req pki.RevokeRequest) error {
	// First, enroll the registrar
	enrollResponse, err := p.client.Enroll(&api.EnrollmentRequest{
		Name:     req.EnrollID,
		Secret:   req.EnrollSecret,
		CAName:   p.config.CAName,
		AttrReqs: []*api.AttributeRequest{},
	})
	if err != nil {
		return errors.Wrap(err, "failed to enroll registrar for revocation")
	}

	result, err := enrollResponse.Identity.Revoke(&api.RevocationRequest{
		Name:   req.Name,
		Serial: req.Serial,
		AKI:    req.AKI,
		Reason: req.Reason,
		GenCRL: req.GenCRL,
	})
	if err != nil {
		return errors.Wrapf(err, "failed to revoke certificate for %s", req.Name)
	}

	logrus.Infof("Revoked certificates: %v", result.RevokedCerts)
	return nil
}

// GetCAInfo retrieves information about the Certificate Authority
func (p *Provider) GetCAInfo(ctx context.Context) (*pki.CAInfo, error) {
	info, err := p.client.GetCAInfo(&api.GetCAInfoRequest{
		CAName: p.config.CAName,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to get CA info")
	}

	return &pki.CAInfo{
		Name:    p.config.CAName,
		CAChain: info.CAChain,
		Version: info.Version,
	}, nil
}

// createClient creates a Fabric CA client
func createClient(config *pki.FabricCAConfig) (*lib.Client, error) {
	caHomeDir, err := ioutil.TempDir("", "fabric-ca-client")
	if err != nil {
		return nil, errors.Wrap(err, "failed to create temp directory")
	}

	client := &lib.Client{
		HomeDir: caHomeDir,
		Config: &lib.ClientConfig{
			URL: config.URL,
		},
	}

	// Configure TLS if certificate is provided
	if config.TLSCert != "" {
		caCertFile, err := ioutil.TempFile("", "ca-cert")
		if err != nil {
			return nil, errors.Wrap(err, "failed to create temp file for CA cert")
		}

		if _, err = caCertFile.Write([]byte(config.TLSCert)); err != nil {
			return nil, errors.Wrap(err, "failed to write CA cert")
		}

		client.Config.TLS = tls.ClientTLSConfig{
			Enabled:   true,
			CertFiles: []string{caCertFile.Name()},
		}
	} else {
		client.Config.TLS = tls.ClientTLSConfig{
			Enabled: false,
		}
	}

	if err := client.Init(); err != nil {
		return nil, errors.Wrap(err, "failed to initialize Fabric CA client")
	}

	return client, nil
}

// readKey reads the private key from the client's keystore
func (p *Provider) readKey() (*ecdsa.PrivateKey, error) {
	keystoreDir := filepath.Join(p.client.HomeDir, "msp", "keystore")
	files, err := ioutil.ReadDir(keystoreDir)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read keystore directory")
	}

	if len(files) == 0 {
		return nil, errors.New("no key found in keystore")
	}
	if len(files) > 1 {
		return nil, errors.New("multiple keys found in keystore")
	}

	keyPath := filepath.Join(keystoreDir, files[0].Name())
	keyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read key file %s", keyPath)
	}

	ecdsaKey, err := utils.ParseECDSAPrivateKey(keyBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse key file %s", keyPath)
	}

	return ecdsaKey, nil
}

// convertAttributeRequests converts pki.AttributeRequest to api.AttributeRequest
func convertAttributeRequests(attrs []pki.AttributeRequest) []*api.AttributeRequest {
	if len(attrs) == 0 {
		return nil
	}

	result := make([]*api.AttributeRequest, len(attrs))
	for i, attr := range attrs {
		result[i] = &api.AttributeRequest{
			Name:     attr.Name,
			Optional: attr.Optional,
		}
	}
	return result
}

// convertAttributes converts pki.Attribute to api.Attribute
func convertAttributes(attrs []pki.Attribute) []api.Attribute {
	if len(attrs) == 0 {
		return nil
	}

	result := make([]api.Attribute, len(attrs))
	for i, attr := range attrs {
		result[i] = api.Attribute{
			Name:  attr.Name,
			Value: attr.Value,
			ECert: attr.ECert,
		}
	}
	return result
}
