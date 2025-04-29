package identity

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/kfsoftware/hlf-operator/kubectl-hlf/cmd/helpers"
	"github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/spf13/cobra"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type createIdentityCmd struct {
	name            string
	namespace       string
	caName          string
	caNamespace     string
	ca              string
	mspID           string
	enrollId        string
	enrollSecret    string
	caEnrollId      string
	caEnrollSecret  string
	caType          string
	credentialStore string

	// Add Vault parameters for enrollment
	vaultAddress              string
	vaultTokenSecretName      string
	vaultTokenSecretNamespace string
	vaultTokenSecretKey       string
	vaultPKIPath              string
	vaultRole                 string
	vaultTTL                  string
}

func (c *createIdentityCmd) validate() error {
	if c.name == "" {
		return fmt.Errorf("--name is required")
	}
	if c.namespace == "" {
		return fmt.Errorf("--namespace is required")
	}
	if c.mspID == "" {
		return fmt.Errorf("--mspid is required")
	}
	if c.credentialStore == hlfv1alpha1.CredentialStoreKubernetes {
		if c.ca == "" {
			return fmt.Errorf("--ca is required for Kubernetes credential store")
		}
		if c.caName == "" {
			return fmt.Errorf("--ca-name is required for Kubernetes credential store")
		}
		if c.caNamespace == "" {
			return fmt.Errorf("--ca-namespace is required for Kubernetes credential store")
		}
		if c.enrollId == "" {
			return fmt.Errorf("--enroll-id is required for Kubernetes credential store")
		}
		if c.enrollSecret == "" {
			return fmt.Errorf("--enroll-secret is required for Kubernetes credential store")
		}
	}
	return nil
}
func (c *createIdentityCmd) run() error {
	oclient, err := helpers.GetKubeOperatorClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	clientSet, err := helpers.GetKubeClient()
	if err != nil {
		return err
	}
	fabricIdentitySpec := v1alpha1.FabricIdentitySpec{
		MSPID: c.mspID,
	}

	if c.credentialStore == hlfv1alpha1.CredentialStoreVault {
		// Configure Vault component if Vault is selected as credential store
		vaultComponent := &v1alpha1.VaultComponent{
			Request: v1alpha1.VaultPKICertificateRequest{
				PKI:  c.vaultPKIPath,
				Role: c.vaultRole,
				TTL:  c.vaultTTL,
			},
			Vault: v1alpha1.VaultSpecConf{
				URL: c.vaultAddress,
				TokenSecretRef: &v1alpha1.VaultSecretRef{
					Name:      c.vaultTokenSecretName,
					Namespace: c.vaultTokenSecretNamespace,
					Key:       c.vaultTokenSecretKey,
				},
			},
		}
		fabricIdentitySpec.Vault = vaultComponent
		fabricIdentitySpec.CredentialStore = v1alpha1.CredentialStore(c.credentialStore)
	} else if c.credentialStore == hlfv1alpha1.CredentialStoreKubernetes {

		fabricCA, err := helpers.GetCertAuthByName(
			clientSet,
			oclient,
			c.caName,
			c.caNamespace,
		)
		if err != nil {
			return err
		}
		// Configure Kubernetes component if Kubernetes is selected as credential store
		fabricIdentitySpec.Cahost = fabricCA.Name
		fabricIdentitySpec.Caport = 7054
		fabricIdentitySpec.Caname = c.ca
		fabricIdentitySpec.Catls = &v1alpha1.Catls{
			Cacert: base64.StdEncoding.EncodeToString([]byte(fabricCA.Status.TlsCert)),
		}
		fabricIdentitySpec.Enrollid = c.enrollId
		fabricIdentitySpec.Enrollsecret = c.enrollSecret
		fabricIdentitySpec.CredentialStore = v1alpha1.CredentialStore(c.credentialStore)
	}

	if c.caEnrollId != "" && c.caEnrollSecret != "" {
		fabricIdentitySpec.Register = &v1alpha1.FabricIdentityRegister{
			Enrollid:       c.caEnrollId,
			Enrollsecret:   c.caEnrollSecret,
			Type:           c.caType,
			Affiliation:    "",
			MaxEnrollments: -1,
			Attrs:          []string{},
		}
	}
	fabricIdentity := &v1alpha1.FabricIdentity{
		ObjectMeta: v1.ObjectMeta{
			Name:      c.name,
			Namespace: c.namespace,
		},
		Spec: fabricIdentitySpec,
	}
	fabricIdentity, err = oclient.HlfV1alpha1().FabricIdentities(c.namespace).Create(
		ctx,
		fabricIdentity,
		v1.CreateOptions{},
	)
	if err != nil {
		return err
	}
	fmt.Printf("Created hlf identity %s/%s\n", fabricIdentity.Name, fabricIdentity.Namespace)
	return nil
}
func newIdentityCreateCMD() *cobra.Command {
	c := &createIdentityCmd{}
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create HLF identity",
		Long:  `Create HLF identity`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			if err := c.run(); err != nil {
				return err
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&c.name, "name", "", "Name of the external chaincode")
	f.StringVar(&c.namespace, "namespace", "", "Namespace of the external chaincode")
	f.StringVar(&c.caName, "ca-name", "", "Name of the CA")
	f.StringVar(&c.caNamespace, "ca-namespace", "", "Namespace of the CA")
	f.StringVar(&c.ca, "ca", "", "CA name")
	f.StringVar(&c.mspID, "mspid", "", "MSP ID")
	f.StringVar(&c.enrollId, "enroll-id", "", "Enroll ID")
	f.StringVar(&c.enrollSecret, "enroll-secret", "", "Enroll Secret")
	f.StringVar(&c.caEnrollId, "ca-enroll-id", "", "CA Enroll ID to register the user")
	f.StringVar(&c.caEnrollSecret, "ca-enroll-secret", "", "CA Enroll Secret to register the user")
	f.StringVar(&c.caType, "ca-type", "", "Type of the user to be registered in the CA")

	// Add credential store flag
	f.StringVar(&c.credentialStore, "credential-store", "kubernetes", "Credential store to use for the identity")

	// Add Vault flags for enrollment
	f.StringVar(&c.vaultAddress, "vault-address", "", "Vault server address")
	f.StringVar(&c.vaultTokenSecretName, "vault-token-secret", "", "Secret name containing Vault token")
	f.StringVar(&c.vaultTokenSecretNamespace, "vault-token-secret-namespace", "default", "Namespace of the Vault token secret")
	f.StringVar(&c.vaultTokenSecretKey, "vault-token-secret-key", "", "Key in the secret containing Vault token")
	f.StringVar(&c.vaultPKIPath, "vault-pki-path", "", "Path to the PKI secrets engine in Vault")
	f.StringVar(&c.vaultRole, "vault-role", "", "Vault role to use for certificate generation")
	f.StringVar(&c.vaultTTL, "vault-ttl", "8760h", "Requested certificate TTL")

	return cmd
}
