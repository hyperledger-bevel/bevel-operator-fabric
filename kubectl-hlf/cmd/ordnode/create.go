package ordnode

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"github.com/kfsoftware/hlf-operator/controllers/utils"
	"github.com/kfsoftware/hlf-operator/kubectl-hlf/cmd/helpers"
	"github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type OrdererOptions struct {
	Name                 string
	StorageClass         string
	Capacity             string
	NS                   string
	Image                string
	Version              string
	MspID                string
	EnrollID             string
	EnrollPW             string
	CAName               string
	Hosts                []string
	HostAliases          []string
	Output               bool
	IngressGateway       string
	IngressPort          int
	AdminHosts           []string
	CAHost               string
	CAPort               int
	ImagePullSecrets     []string
	GatewayApiName       string
	GatewayApiNamespace  string
	GatewayApiPort       int
	GatewayApiHosts      []string
	AdminGatewayApiHosts []string

	CredentialStore              string
	VaultAddress                 string
	VaultTokenSecretName         string
	VaultTokenSecretNamespace    string
	VaultTokenSecretKey          string
	VaultPKIPath                 string
	VaultRole                    string
	VaultTTL                     string
	TLSVaultAddress              string
	TLSVaultTokenSecretName      string
	TLSVaultTokenSecretNamespace string
	TLSVaultTokenSecretKey       string
	TLSVaultPKIPath              string
	TLSVaultRole                 string
	TLSVaultTTL                  string
}

func (o OrdererOptions) Validate() error {
	return nil
}

type createCmd struct {
	out         io.Writer
	errOut      io.Writer
	ordererOpts OrdererOptions
}

func (c *createCmd) validate() error {
	return c.ordererOpts.Validate()
}
func (c *createCmd) run(args []string) error {
	oclient, err := helpers.GetKubeOperatorClient()
	if err != nil {
		return err
	}
	clientSet, err := helpers.GetKubeClient()
	if err != nil {
		return err
	}
	k8sIP, err := utils.GetPublicIPKubernetes(clientSet)
	if err != nil {
		return err
	}

	csrHosts := []string{
		"127.0.0.1",
		"localhost",
	}
	csrHosts = append(csrHosts, k8sIP)
	csrHosts = append(csrHosts, c.ordererOpts.Name)
	csrHosts = append(csrHosts, fmt.Sprintf("%s.%s", c.ordererOpts.Name, c.ordererOpts.NS))
	ingressGateway := c.ordererOpts.IngressGateway
	ingressPort := c.ordererOpts.IngressPort
	istio := &v1alpha1.FabricIstio{
		Port:           ingressPort,
		Hosts:          []string{},
		IngressGateway: ingressGateway,
	}
	gatewayApiName := c.ordererOpts.GatewayApiName
	gatewayApiNamespace := c.ordererOpts.GatewayApiNamespace
	gatewayApiPort := c.ordererOpts.GatewayApiPort
	var gatewayApi *v1alpha1.FabricGatewayApi
	if c.ordererOpts.GatewayApiName != "" {
		gatewayApi = &v1alpha1.FabricGatewayApi{
			Port:             gatewayApiPort,
			Hosts:            []string{},
			GatewayName:      gatewayApiName,
			GatewayNamespace: gatewayApiNamespace,
		}
	}
	if len(c.ordererOpts.Hosts) > 0 {
		istio = &v1alpha1.FabricIstio{
			Port:           ingressPort,
			Hosts:          c.ordererOpts.Hosts,
			IngressGateway: ingressGateway,
		}
		csrHosts = append(csrHosts, c.ordererOpts.Hosts...)
	} else if len(c.ordererOpts.GatewayApiHosts) > 0 {
		gatewayApi = &v1alpha1.FabricGatewayApi{
			Port:             gatewayApiPort,
			Hosts:            c.ordererOpts.GatewayApiHosts,
			GatewayName:      gatewayApiName,
			GatewayNamespace: gatewayApiNamespace,
		}
		csrHosts = append(csrHosts, c.ordererOpts.GatewayApiHosts...)
	}
	adminIstio := &v1alpha1.FabricIstio{
		Port:           ingressPort,
		Hosts:          []string{},
		IngressGateway: ingressGateway,
	}
	var adminGatewayApi *v1alpha1.FabricGatewayApi
	if len(c.ordererOpts.AdminHosts) > 0 {
		adminIstio = &v1alpha1.FabricIstio{
			Port:           ingressPort,
			Hosts:          c.ordererOpts.AdminHosts,
			IngressGateway: ingressGateway,
		}
		csrHosts = append(csrHosts, c.ordererOpts.AdminHosts...)
	} else if len(c.ordererOpts.AdminGatewayApiHosts) > 0 {
		adminGatewayApi = &v1alpha1.FabricGatewayApi{
			Port:             gatewayApiPort,
			Hosts:            c.ordererOpts.AdminGatewayApiHosts,
			GatewayName:      gatewayApiName,
			GatewayNamespace: gatewayApiNamespace,
		}
		csrHosts = append(csrHosts, c.ordererOpts.AdminGatewayApiHosts...)
	}

	caHost := k8sIP
	serviceType := corev1.ServiceTypeClusterIP
	var hostAliases []corev1.HostAlias
	for _, hostAlias := range c.ordererOpts.HostAliases {
		ipAndNames := strings.Split(hostAlias, ":")
		if len(ipAndNames) == 2 {
			aliases := strings.Split(ipAndNames[1], ",")
			if len(aliases) > 0 {
				hostAliases = append(hostAliases, corev1.HostAlias{IP: ipAndNames[0], Hostnames: aliases})
			} else {
				log.Warningf("ingnoring host-alias [%s]: must be in format <ip>:<alias1>,<alias2>...", hostAlias)
			}
		} else {
			log.Warningf("ingnoring host-alias [%s]: must be in format <ip>:<alias1>,<alias2>...", hostAlias)
		}
	}
	var imagePullSecrets []corev1.LocalObjectReference
	if len(c.ordererOpts.ImagePullSecrets) > 0 {
		for _, v := range c.ordererOpts.ImagePullSecrets {
			imagePullSecrets = append(imagePullSecrets, corev1.LocalObjectReference{
				Name: v,
			})
		}
	}
	var signComponent v1alpha1.Component
	var tlsComponent v1alpha1.TLSComponent

	if c.ordererOpts.CredentialStore == "vault" {
		// Configure credentials based on the selected credential store

		vaultComponent := &v1alpha1.VaultComponent{
			Request: v1alpha1.VaultPKICertificateRequest{
				PKI:  c.ordererOpts.VaultPKIPath,
				Role: c.ordererOpts.VaultRole,
				TTL:  c.ordererOpts.VaultTTL,
			},
			Vault: v1alpha1.VaultSpecConf{
				URL: c.ordererOpts.VaultAddress,
				TokenSecretRef: &v1alpha1.VaultSecretRef{
					Name:      c.ordererOpts.VaultTokenSecretName,
					Namespace: c.ordererOpts.VaultTokenSecretNamespace,
					Key:       c.ordererOpts.VaultTokenSecretKey,
				},
			},
		}

		// Configure Vault for TLS component if specified
		tlsVaultComponent := &v1alpha1.VaultComponent{
			Request: v1alpha1.VaultPKICertificateRequest{
				PKI:  c.ordererOpts.TLSVaultPKIPath,
				Role: c.ordererOpts.TLSVaultRole,
				TTL:  c.ordererOpts.TLSVaultTTL,
			},
			Vault: v1alpha1.VaultSpecConf{
				URL: c.ordererOpts.TLSVaultAddress,
				TokenSecretRef: &v1alpha1.VaultSecretRef{
					Name:      c.ordererOpts.TLSVaultTokenSecretName,
					Namespace: c.ordererOpts.TLSVaultTokenSecretNamespace,
					Key:       c.ordererOpts.TLSVaultTokenSecretKey,
				},
			},
		}

		signComponent = v1alpha1.Component{
			Vault: vaultComponent,
		}
		tlsComponent = v1alpha1.TLSComponent{
			Vault: tlsVaultComponent,
		}
	} else if c.ordererOpts.CredentialStore == "kubernetes" {

		certAuth, err := helpers.GetCertAuthByFullName(clientSet, oclient, c.ordererOpts.CAName)
		if err != nil {
			return err
		}
		caPort := certAuth.Status.NodePort
		if len(certAuth.Spec.Istio.Hosts) > 0 {
			caHost = certAuth.Spec.Istio.Hosts[0]
			caPort = certAuth.Spec.Istio.Port
		} else if len(certAuth.Spec.GatewayApi.Hosts) > 0 {
			caHost = certAuth.Spec.GatewayApi.Hosts[0]
			caPort = certAuth.Spec.GatewayApi.Port
		}
		if c.ordererOpts.CAHost != "" {
			caHost = c.ordererOpts.CAHost
		}
		if c.ordererOpts.CAPort != 0 {
			caPort = c.ordererOpts.CAPort
		}
		// Configure credentials based on the selected credential store
		var vaultComponent *v1alpha1.VaultComponent
		var tlsVaultComponent *v1alpha1.VaultComponent

		// Configure Vault for enrollment component if specified
		if c.ordererOpts.CredentialStore == "vault" && c.ordererOpts.VaultAddress != "" {
			vaultComponent = &v1alpha1.VaultComponent{
				Request: v1alpha1.VaultPKICertificateRequest{
					PKI:  c.ordererOpts.VaultPKIPath,
					Role: c.ordererOpts.VaultRole,
					TTL:  c.ordererOpts.VaultTTL,
				},
				Vault: v1alpha1.VaultSpecConf{
					URL: c.ordererOpts.VaultAddress,
					TokenSecretRef: &v1alpha1.VaultSecretRef{
						Name:      c.ordererOpts.VaultTokenSecretName,
						Namespace: c.ordererOpts.VaultTokenSecretNamespace,
						Key:       c.ordererOpts.VaultTokenSecretKey,
					},
				},
			}
		}

		// Configure Vault for TLS component if specified
		if c.ordererOpts.CredentialStore == "vault" && c.ordererOpts.TLSVaultAddress != "" {
			tlsVaultComponent = &v1alpha1.VaultComponent{
				Request: v1alpha1.VaultPKICertificateRequest{
					PKI:  c.ordererOpts.TLSVaultPKIPath,
					Role: c.ordererOpts.TLSVaultRole,
					TTL:  c.ordererOpts.TLSVaultTTL,
				},
				Vault: v1alpha1.VaultSpecConf{
					URL: c.ordererOpts.TLSVaultAddress,
					TokenSecretRef: &v1alpha1.VaultSecretRef{
						Name:      c.ordererOpts.TLSVaultTokenSecretName,
						Namespace: c.ordererOpts.TLSVaultTokenSecretNamespace,
						Key:       c.ordererOpts.TLSVaultTokenSecretKey,
					},
				},
			}
		}

		signComponent = v1alpha1.Component{
			Cahost: caHost,
			Caport: caPort,
			Caname: certAuth.Spec.CA.Name,
			Catls: &v1alpha1.Catls{
				Cacert: base64.StdEncoding.EncodeToString([]byte(certAuth.Status.TlsCert)),
			},
			Enrollid:     c.ordererOpts.EnrollID,
			Enrollsecret: c.ordererOpts.EnrollPW,
			Vault:        vaultComponent,
		}
		tlsComponent = v1alpha1.TLSComponent{
			Cahost: caHost,
			Caport: caPort,
			Caname: certAuth.Spec.TLSCA.Name,
			Catls: &v1alpha1.Catls{
				Cacert: base64.StdEncoding.EncodeToString([]byte(certAuth.Status.TlsCert)),
			},
			Csr: v1alpha1.Csr{
				Hosts: csrHosts,
				CN:    "",
			},
			Enrollid:     c.ordererOpts.EnrollID,
			Enrollsecret: c.ordererOpts.EnrollPW,
			Vault:        tlsVaultComponent,
		}
	} else {
		return errors.Errorf("invalid credential store: %s", c.ordererOpts.CredentialStore)
	}

	fabricOrderer := &v1alpha1.FabricOrdererNode{
		TypeMeta: v1.TypeMeta{
			Kind:       "FabricOrdererNode",
			APIVersion: v1alpha1.GroupVersion.String(),
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      c.ordererOpts.Name,
			Namespace: c.ordererOpts.NS,
		},
		Spec: v1alpha1.FabricOrdererNodeSpec{
			CredentialStore:             v1alpha1.CredentialStore(c.ordererOpts.CredentialStore),
			ServiceMonitor:              nil,
			HostAliases:                 hostAliases,
			Resources:                   corev1.ResourceRequirements{},
			Replicas:                    1,
			Image:                       c.ordererOpts.Image,
			ImagePullSecrets:            imagePullSecrets,
			Tag:                         c.ordererOpts.Version,
			PullPolicy:                  corev1.PullIfNotPresent,
			MspID:                       c.ordererOpts.MspID,
			Genesis:                     "",
			BootstrapMethod:             v1alpha1.BootstrapMethodNone,
			ChannelParticipationEnabled: true,
			Storage: v1alpha1.Storage{
				Size:         c.ordererOpts.Capacity,
				StorageClass: c.ordererOpts.StorageClass,
				AccessMode:   "ReadWriteOnce",
			},
			Service: v1alpha1.OrdererNodeService{
				Type: serviceType,
			},
			Secret: &v1alpha1.Secret{
				Enrollment: v1alpha1.Enrollment{
					Component: signComponent,
					TLS:       tlsComponent,
				},
			},
			Istio:           istio,
			AdminIstio:      adminIstio,
			GatewayApi:      gatewayApi,
			AdminGatewayApi: adminGatewayApi,
		},
	}
	if c.ordererOpts.Output {
		ot, err := helpers.MarshallWithoutStatus(&fabricOrderer)
		if err != nil {
			return err
		}
		fmt.Println(string(ot))
	} else {
		ctx := context.Background()
		ordService, err := oclient.HlfV1alpha1().FabricOrdererNodes(c.ordererOpts.NS).Create(
			ctx,
			fabricOrderer,
			v1.CreateOptions{},
		)
		if err != nil {
			return err
		}
		log.Infof("Ordering service %s created on namespace %s", ordService.Name, ordService.Namespace)
	}
	return nil
}
func newCreateOrdererNodeCmd(out io.Writer, errOut io.Writer) *cobra.Command {
	c := createCmd{out: out, errOut: errOut}
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a Fabric Ordering Service Node(OSN)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			return c.run(args)
		},
	}
	f := cmd.Flags()
	f.StringVar(&c.ordererOpts.Name, "name", "", "Name of the Fabric Orderer to create")
	f.StringVar(&c.ordererOpts.CAName, "ca-name", "", "CA name to enroll the orderer identity")
	f.StringVar(&c.ordererOpts.CAHost, "ca-host", "", "CA host to enroll the orderer identity")
	f.IntVar(&c.ordererOpts.CAPort, "ca-port", 0, "CA host to enroll the orderer identity")
	f.StringVar(&c.ordererOpts.EnrollID, "enroll-id", "", "Enroll ID of the CA")
	f.StringVar(&c.ordererOpts.EnrollPW, "enroll-pw", "", "Enroll secret of the CA")
	f.StringVar(&c.ordererOpts.Capacity, "capacity", "5Gi", "Total raw capacity of Fabric Orderer in this zone, e.g. 16Ti")
	f.StringVarP(&c.ordererOpts.NS, "namespace", "n", helpers.DefaultNamespace, "Namespace scope for this request")
	f.StringVarP(&c.ordererOpts.StorageClass, "storage-class", "s", helpers.DefaultStorageclass, "Storage class for this Fabric Orderer")
	f.StringVarP(&c.ordererOpts.Image, "image", "", helpers.DefaultOrdererImage, "Version of the Fabric Orderer")
	f.StringVarP(&c.ordererOpts.Version, "version", "", helpers.DefaultOrdererVersion, "Version of the Fabric Orderer")
	f.StringVarP(&c.ordererOpts.IngressGateway, "istio-ingressgateway", "", "ingressgateway", "Istio ingress gateway name")
	f.IntVarP(&c.ordererOpts.IngressPort, "istio-port", "", 443, "Istio ingress port")
	f.StringVarP(&c.ordererOpts.MspID, "mspid", "", "", "MSP ID of the organization")
	f.StringArrayVarP(&c.ordererOpts.Hosts, "hosts", "", []string{}, "Hosts")
	f.StringArrayVarP(&c.ordererOpts.GatewayApiHosts, "gateway-api-hosts", "", []string{}, "Hosts for GatewayApi")
	f.StringArrayVarP(&c.ordererOpts.AdminGatewayApiHosts, "admin-gateway-api-hosts", "", []string{}, "GatewayAPI Hosts for the admin API")
	f.StringVarP(&c.ordererOpts.GatewayApiName, "gateway-api-name", "", "", "Gateway-api name")
	f.StringVarP(&c.ordererOpts.GatewayApiNamespace, "gateway-api-namespace", "", "", "Namespace of GatewayApi")
	f.IntVarP(&c.ordererOpts.GatewayApiPort, "gateway-api-port", "", 0, "Gateway API port")
	f.StringArrayVarP(&c.ordererOpts.AdminHosts, "admin-hosts", "", []string{}, "Hosts for the admin API(introduced in v2.3)")
	f.BoolVarP(&c.ordererOpts.Output, "output", "o", false, "Output in yaml")
	f.StringArrayVarP(&c.ordererOpts.HostAliases, "host-aliases", "", []string{}, "Host aliases (e.g.: \"1.2.3.4:osn2.example.com,peer1.example.com\")")
	f.StringArrayVarP(&c.ordererOpts.ImagePullSecrets, "image-pull-secrets", "", []string{}, "Image Pull Secrets for the Peer Image")
	f.StringVar(&c.ordererOpts.CredentialStore, "credential-store", "kubernetes", "Credential store to use for the Orderer Node")
	f.StringVar(&c.ordererOpts.VaultAddress, "vault-address", "", "Vault server address")
	f.StringVar(&c.ordererOpts.VaultTokenSecretName, "vault-token-secret", "", "Secret name containing Vault token")
	f.StringVar(&c.ordererOpts.VaultTokenSecretNamespace, "vault-token-secret-namespace", "default", "Namespace of the Vault token secret")
	f.StringVar(&c.ordererOpts.VaultTokenSecretKey, "vault-token-secret-key", "", "Key in the secret containing Vault token")
	f.StringVar(&c.ordererOpts.VaultPKIPath, "vault-pki-path", "", "Path to the PKI secrets engine in Vault")
	f.StringVar(&c.ordererOpts.VaultRole, "vault-role", "", "Vault role to use for certificate generation")
	f.StringVar(&c.ordererOpts.VaultTTL, "vault-ttl", "8760h", "Requested certificate TTL")
	f.StringVar(&c.ordererOpts.TLSVaultAddress, "tls-vault-address", "", "Vault server address for TLS")
	f.StringVar(&c.ordererOpts.TLSVaultTokenSecretName, "tls-vault-token-secret", "", "Secret name containing Vault token for TLS")
	f.StringVar(&c.ordererOpts.TLSVaultTokenSecretNamespace, "tls-vault-token-secret-namespace", "default", "Namespace of the Vault token secret for TLS")
	f.StringVar(&c.ordererOpts.TLSVaultTokenSecretKey, "tls-vault-token-secret-key", "", "Key in the secret containing Vault token for TLS")
	f.StringVar(&c.ordererOpts.TLSVaultPKIPath, "tls-vault-pki-path", "", "Path to the PKI secrets engine in Vault for TLS")
	f.StringVar(&c.ordererOpts.TLSVaultRole, "tls-vault-role", "", "Vault role to use for TLS certificate generation")
	f.StringVar(&c.ordererOpts.TLSVaultTTL, "tls-vault-ttl", "8760h", "Requested TLS certificate TTL")
	return cmd
}
