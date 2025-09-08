package certs

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/sirupsen/logrus"

	"github.com/hyperledger/fabric/bccsp"
	bccsputils "github.com/hyperledger/fabric/bccsp/utils"
	"github.com/kfsoftware/hlf-operator/controllers/utils"
	"github.com/kfsoftware/hlf-operator/internal/github.com/hyperledger/fabric-ca/api"
	"github.com/kfsoftware/hlf-operator/internal/github.com/hyperledger/fabric-ca/lib"
	"github.com/kfsoftware/hlf-operator/internal/github.com/hyperledger/fabric-ca/lib/client/credential"
	fabricx509 "github.com/kfsoftware/hlf-operator/internal/github.com/hyperledger/fabric-ca/lib/client/credential/x509"
	"github.com/kfsoftware/hlf-operator/internal/github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/pkg/errors"
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
	TLSCert    string
	URL        string
	Name       string
	MSPID      string
	User       string
	Secret     string
	Hosts      []string
	CN         string
	Profile    string
	Attributes []*api.AttributeRequest
}
type ReenrollUserRequest struct {
	EnrollID   string
	TLSCert    string
	URL        string
	Name       string
	MSPID      string
	Hosts      []string
	CN         string
	Profile    string
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
	caClient, err := GetClient(FabricCAParams{
		TLSCert:      params.TLSCert,
		URL:          params.URL,
		Name:         params.Name,
		MSPID:        params.MSPID,
		EnrollID:     params.EnrollID,
		EnrollSecret: params.EnrollSecret,
	})
	if err != nil {
		return err
	}
	myIdentity, err := caClient.LoadMyIdentity()
	if err != nil {
		return err
	}
	result, err := myIdentity.Revoke(params.RevocationRequest)
	if err != nil {
		return err
	}
	logrus.Infof("Revoked user %v", result.RevokedCerts)
	return nil
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
	caClient, err := GetClient(FabricCAParams{
		TLSCert:      params.TLSCert,
		URL:          params.URL,
		Name:         params.Name,
		MSPID:        params.MSPID,
		EnrollID:     params.EnrollID,
		EnrollSecret: params.EnrollSecret,
	})
	if err != nil {
		return "", err
	}
	enrollResponse, err := caClient.Enroll(&api.EnrollmentRequest{
		Name:     params.EnrollID,
		Secret:   params.EnrollSecret,
		CAName:   params.Name,
		AttrReqs: []*api.AttributeRequest{},
		Type:     params.Type,
	})
	if err != nil {
		return "", err
	}
	secret, err := enrollResponse.Identity.Register(&api.RegistrationRequest{
		Name:           params.User,
		Type:           params.Type,
		MaxEnrollments: -1,
		Affiliation:    "",
		Attributes:     params.Attributes,
		CAName:         params.Name,
		Secret:         params.Secret,
	})
	if err != nil {
		return "", err
	}
	return secret.Secret, nil
}

func GetCAInfo(params GetCAInfoRequest) (*lib.GetCAInfoResponse, error) {
	caClient, err := GetClient(FabricCAParams{
		TLSCert: params.TLSCert,
		URL:     params.URL,
		Name:    params.Name,
		MSPID:   params.MSPID,
	})
	if err != nil {
		return nil, err
	}
	caInfo, err := caClient.GetCAInfo(&api.GetCAInfoRequest{})
	if err != nil {
		return nil, err
	}
	return caInfo, nil
}

func ReenrollUser(params ReenrollUserRequest, certPem string, ecdsaKey *ecdsa.PrivateKey) (*x509.Certificate, *x509.Certificate, error) {
	caClient, err := GetClient(FabricCAParams{
		TLSCert: params.TLSCert,
		URL:     params.URL,
		Name:    params.Name,
		MSPID:   params.MSPID,
	})
	if err != nil {
		return nil, nil, err
	}
	priv, err := bccsputils.PrivateKeyToDER(ecdsaKey)
	if err != nil {
		return nil, nil, errors.WithMessage(err, fmt.Sprintf("Failed to convert ECDSA private key for '%v'", ecdsaKey))
	}
	bccspKey, err := caClient.GetCSP().KeyImport(priv, &bccsp.ECDSAPrivateKeyImportOpts{Temporary: true})
	if err != nil {
		return nil, nil, errors.Wrapf(err, "Error importing private key")
	}
	signer, err := fabricx509.NewSigner(bccspKey, []byte(certPem))
	if err != nil {
		return nil, nil, errors.Wrapf(err, "Error creating signer")
	}
	cred := fabricx509.NewCredential(
		"",
		"",
		caClient,
	)
	err = cred.SetVal(signer)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "Error setting credential value")
	}
	id := lib.NewIdentity(
		caClient,
		params.EnrollID,
		[]credential.Credential{
			cred,
		},
	)
	reuseKey := true
	reenrollResponse, err := id.Reenroll(&api.ReenrollmentRequest{
		CAName:   params.Name,
		AttrReqs: params.Attributes,
		Profile:  params.Profile,
		Label:    "",
		CSR: &api.CSRInfo{
			Hosts: params.Hosts,
			CN:    params.CN,
			KeyRequest: &api.KeyRequest{
				ReuseKey: reuseKey,
			},
		},
	})
	if err != nil {
		return nil, nil, errors.Wrapf(err, "Error reenrolling user '%s'", params.EnrollID)
	}
	userCrt := reenrollResponse.Identity.GetECert().GetX509Cert()
	if err != nil {
		return nil, nil, err
	}
	info, err := caClient.GetCAInfo(&api.GetCAInfoRequest{
		CAName: params.Name,
	})
	if err != nil {
		return nil, nil, err
	}
	rootCrt, err := utils.ParseX509Certificate(info.CAChain)
	if err != nil {
		return nil, nil, err
	}
	return userCrt, rootCrt, nil
}
func readKey(client *lib.Client) (*ecdsa.PrivateKey, error) {
	keystoreDir := filepath.Join(client.HomeDir, "msp", "keystore")
	files, err := ioutil.ReadDir(keystoreDir)
	if err != nil {
		return nil, err
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
func EnrollUser(params EnrollUserRequest) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, error) {

	caClient, err := GetClient(FabricCAParams{
		TLSCert: params.TLSCert,
		URL:     params.URL,
		Name:    params.Name,
		MSPID:   params.MSPID,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	enrollmentRequest := &api.EnrollmentRequest{
		Name:     params.User,
		Secret:   params.Secret,
		CAName:   params.Name,
		AttrReqs: params.Attributes,
		Profile:  params.Profile,
		Label:    "",
		Type:     "x509",
		CSR: &api.CSRInfo{
			Hosts: params.Hosts,
			CN:    params.CN,
		},
	}
	logrus.Infof("Enrollment request: %+v", enrollmentRequest)
	enrollResponse, err := caClient.Enroll(enrollmentRequest)
	if err != nil {
		return nil, nil, nil, err
	}
	userCrt := enrollResponse.Identity.GetECert().GetX509Cert()

	info, err := caClient.GetCAInfo(&api.GetCAInfoRequest{
		CAName: params.Name,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	rootCrt, err := utils.ParseX509Certificate(info.CAChain)
	if err != nil {
		return nil, nil, nil, err
	}
	userKey, err := readKey(caClient)
	if err != nil {
		return nil, nil, nil, err
	}
	return userCrt, userKey, rootCrt, nil
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

func GetClient(ca FabricCAParams) (*lib.Client, error) {
	// create temporary directory
	caHomeDir, err := ioutil.TempDir("", "fabric-ca-client")
	if err != nil {
		return nil, nil
	}
	
	client := &lib.Client{
		HomeDir: caHomeDir,
		Config: &lib.ClientConfig{
			URL: ca.URL,
		},
	}
	
	// Only configure TLS if TLS certificate is provided
	if ca.TLSCert != "" {
		// create temporary file
		caCertFile, err := ioutil.TempFile("", "ca-cert")
		if err != nil {
			return nil, nil
		}
		// write ca cert to file
		_, err = caCertFile.Write([]byte(ca.TLSCert))
		if err != nil {
			return nil, nil
		}
		client.Config.TLS = tls.ClientTLSConfig{
			Enabled:   true,
			CertFiles: []string{caCertFile.Name()},
		}
	} else {
		// Disable TLS for HTTP connections
		client.Config.TLS = tls.ClientTLSConfig{
			Enabled: false,
		}
	}
	
	err = client.Init()
	if err != nil {
		return nil, err
	}
	return client, err
}
