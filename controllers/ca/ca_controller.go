package ca

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"

	"github.com/go-logr/logr"
	"github.com/kfsoftware/hlf-operator/controllers/hlfmetrics"
	"github.com/kfsoftware/hlf-operator/pkg/status"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/release"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	"math/big"
	"net"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/kfsoftware/hlf-operator/controllers/utils"
	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/storage/driver"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// FabricCAReconciler reconciles a FabricCA object
type FabricCAReconciler struct {
	client.Client
	ChartPath  string
	Log        logr.Logger
	Scheme     *runtime.Scheme
	Config     *rest.Config
	ClientSet  *kubernetes.Clientset
	Wait       bool
	Timeout    time.Duration
	MaxHistory int
}

func parseECDSAPrivateKey(contents []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(contents)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not of ECDSA type")
	}
	return ecdsaKey, nil
}
func parseX509Certificate(contents []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(contents)
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return crt, nil
}

func getExistingTLSCrypto(client *kubernetes.Clientset, chartName string, namespace string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	secretName := fmt.Sprintf("%s--tls-cryptomaterial", chartName)
	secret, err := client.CoreV1().Secrets(namespace).Get(context.Background(), secretName, v1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}
	tlsKeyData := secret.Data["tls.key"]
	tlsCrtData := secret.Data["tls.crt"]
	key, err := parseECDSAPrivateKey(tlsKeyData)
	if err != nil {
		return nil, nil, err
	}
	crt, err := parseX509Certificate(tlsCrtData)
	if err != nil {
		return nil, nil, err
	}
	return crt, key, nil
}

func getExistingSignCrypto(client *kubernetes.Clientset, chartName string, namespace string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	secretName := fmt.Sprintf("%s--msp-cryptomaterial", chartName)

	secret, err := client.CoreV1().Secrets(namespace).Get(context.Background(), secretName, v1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}
	tlsKeyData := secret.Data["keyfile"]
	tlsCrtData := secret.Data["certfile"]
	key, err := parseECDSAPrivateKey(tlsKeyData)
	if err != nil {
		return nil, nil, err
	}
	crt, err := parseX509Certificate(tlsCrtData)
	if err != nil {
		return nil, nil, err
	}
	return crt, key, nil
}

func getAlreadyExistingCrypto(client *kubernetes.Clientset, secretName string, namespace string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	secret, err := client.CoreV1().Secrets(namespace).Get(context.Background(), secretName, v1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}
	tlsKeyData := secret.Data["keyfile"]
	tlsCrtData := secret.Data["certfile"]
	key, err := parseECDSAPrivateKey(tlsKeyData)
	if err != nil {
		return nil, nil, err
	}
	crt, err := parseX509Certificate(tlsCrtData)
	if err != nil {
		return nil, nil, err
	}
	return crt, key, nil
}

func getExistingSignTLSCrypto(client *kubernetes.Clientset, chartName string, namespace string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	secretName := fmt.Sprintf("%s--msp-tls-cryptomaterial", chartName)

	secret, err := client.CoreV1().Secrets(namespace).Get(context.Background(), secretName, v1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}
	tlsKeyData := secret.Data["keyfile"]
	tlsCrtData := secret.Data["certfile"]
	key, err := parseECDSAPrivateKey(tlsKeyData)
	if err != nil {
		return nil, nil, err
	}
	crt, err := parseX509Certificate(tlsCrtData)
	if err != nil {
		return nil, nil, err
	}
	return crt, key, nil
}

// compute Subject Key Identifier
func computeSKI(privKey *ecdsa.PrivateKey) []byte {
	// Marshall the public key
	raw := elliptic.Marshal(privKey.Curve, privKey.PublicKey.X, privKey.PublicKey.Y)

	// Hash it
	hash := sha256.Sum256(raw)
	return hash[:]
}
func getDNSNames(spect hlfv1alpha1.FabricCASpec) []string {
	var dnsNames []string
	for _, host := range spect.Hosts {
		addr := net.ParseIP(host)
		if addr == nil {
			dnsNames = append(dnsNames, host)
		}
	}
	return dnsNames
}
func getIPAddresses(spect hlfv1alpha1.FabricCASpec) []net.IP {
	ipAddresses := []net.IP{net.ParseIP("127.0.0.1")}
	for _, host := range spect.Hosts {
		addr := net.ParseIP(host)
		if addr != nil {
			ipAddresses = append(ipAddresses, addr)
		}
	}
	return ipAddresses
}
func CreateDefaultTLSCA(spec hlfv1alpha1.FabricCASpec) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
		return nil, nil, err
	}
	ips := getIPAddresses(spec)
	dnsNames := getDNSNames(spec)
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	x509Cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{spec.TLS.Subject.O},
			Country:            []string{spec.TLS.Subject.C},
			Locality:           []string{spec.TLS.Subject.L},
			OrganizationalUnit: []string{spec.TLS.Subject.OU},
			StreetAddress:      []string{spec.TLS.Subject.ST},
		},
		NotBefore:             time.Now().AddDate(0, 0, -1),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		SubjectKeyId:          computeSKI(caPrivKey),
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, x509Cert, x509Cert, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}
	crt, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, nil, err
	}
	return crt, caPrivKey, nil
}

func CreateDefaultCA(conf hlfv1alpha1.FabricCAItemConf) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
		return nil, nil, err
	}
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	signCA := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{conf.Subject.O},
			Country:            []string{conf.Subject.C},
			Locality:           []string{conf.Subject.L},
			OrganizationalUnit: []string{conf.Subject.OU},
			StreetAddress:      []string{conf.Subject.ST},
			CommonName:         conf.Subject.CN,
		},
		NotBefore:             time.Now().AddDate(0, 0, -1),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		SubjectKeyId:          computeSKI(caPrivKey),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, signCA, signCA, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}
	crt, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, nil, err
	}
	return crt, caPrivKey, nil
}

func newActionCfg(log logr.Logger, clusterCfg *rest.Config, namespace string) (*action.Configuration, error) {
	err := os.Setenv("HELM_NAMESPACE", namespace)
	if err != nil {
		return nil, err
	}
	cfg := new(action.Configuration)
	ns := namespace
	err = cfg.Init(&genericclioptions.ConfigFlags{
		Namespace:   &ns,
		APIServer:   &clusterCfg.Host,
		CAFile:      &clusterCfg.CAFile,
		BearerToken: &clusterCfg.BearerToken,
	}, ns, "secret", actionLogger(log))
	return cfg, err
}

func actionLogger(logger logr.Logger) func(format string, v ...interface{}) {
	return func(format string, v ...interface{}) {
		logger.Info(fmt.Sprintf(format, v...))
	}
}
func mapCRDItemConfToChart(conf hlfv1alpha1.FabricCAItemConf) FabricCAChartItemConf {
	names := []FabricCAChartNames{}
	for _, name := range conf.CSR.Names {
		names = append(names, FabricCAChartNames{
			C:  name.C,
			ST: name.ST,
			O:  name.O,
			L:  name.L,
			OU: name.OU,
		})
	}
	identities := []FabricCAChartIdentity{}
	for _, identity := range conf.Registry.Identities {
		identities = append(identities, FabricCAChartIdentity{
			Name:        identity.Name,
			Pass:        identity.Pass,
			Type:        identity.Type,
			Affiliation: identity.Affiliation,
			Attrs: FabricCAChartIdentityAttrs{
				RegistrarRoles: identity.Attrs.RegistrarRoles,
				DelegateRoles:  identity.Attrs.DelegateRoles,
				Attributes:     identity.Attrs.Attributes,
				Revoker:        identity.Attrs.Revoker,
				IntermediateCA: identity.Attrs.IntermediateCA,
				GenCRL:         identity.Attrs.GenCRL,
				AffiliationMgr: identity.Attrs.AffiliationMgr,
			},
		})
	}
	affiliations := []Affiliation{}
	for _, affiliation := range conf.Affiliations {
		affiliations = append(affiliations, Affiliation{
			Name:        affiliation.Name,
			Departments: affiliation.Departments,
		})
	}
	var signing FabricCASigning
	if conf.Signing != nil {
		signing = FabricCASigning{
			Default: FabricCASigningDefault{
				Expiry: conf.Signing.Default.Expiry,
				Usage:  conf.Signing.Default.Usage,
			},
			Profiles: FabricCASigningProfiles{
				CA: FabricCASigningSignProfile{
					Usage:  conf.Signing.Profiles.CA.Usage,
					Expiry: conf.Signing.Profiles.CA.Expiry,
					CAConstraint: FabricCASigningSignProfileConstraint{
						IsCA:       conf.Signing.Profiles.CA.CAConstraint.IsCA,
						MaxPathLen: conf.Signing.Profiles.CA.CAConstraint.MaxPathLen,
					},
				},
				TLS: FabricCASigningTLSProfile{
					Usage:  conf.Signing.Profiles.TLS.Usage,
					Expiry: conf.Signing.Profiles.TLS.Expiry,
				},
			},
		}
	} else {
		signing = FabricCASigning{
			Default: FabricCASigningDefault{
				Expiry: "8760h",
				Usage:  []string{"digital signature"},
			},
			Profiles: FabricCASigningProfiles{
				CA: FabricCASigningSignProfile{
					Usage: []string{
						"cert sign",
						"crl sign",
					},
					Expiry: "43800h",
					CAConstraint: FabricCASigningSignProfileConstraint{
						IsCA:       true,
						MaxPathLen: 0,
					},
				},
				TLS: FabricCASigningTLSProfile{
					Usage: []string{
						"signing",
						"key encipherment",
						"server auth",
						"client auth",
						"key agreement",
					},
					Expiry: "8760h",
				},
			},
		}
	}
	item := FabricCAChartItemConf{
		Name:    conf.Name,
		Signing: signing,
		CFG: FabricCAChartCFG{
			Identities:   FabricCAChartCFGIdentities{AllowRemove: conf.CFG.Identities.AllowRemove},
			Affiliations: FabricCAChartCFGAffilitions{AllowRemove: conf.CFG.Affiliations.AllowRemove},
		},
		CSR: FabricCAChartCSR{
			CN:    conf.CSR.CN,
			Hosts: conf.CSR.Hosts,
			Names: names,
			CA: FabricCAChartCSRCA{
				Expiry:     conf.CSR.CA.Expiry,
				PathLength: conf.CSR.CA.PathLength,
			},
		},
		CRL: FabricCAChartCRL{Expiry: conf.CRL.Expiry},
		Registry: FabricCAChartRegistry{
			MaxEnrollments: conf.Registry.MaxEnrollments,
			Identities:     identities,
		},
		Intermediate: FabricCAChartIntermediate{
			ParentServer: FabricCAChartIntermediateParentServer{
				URL:    conf.Intermediate.ParentServer.URL,
				CAName: conf.Intermediate.ParentServer.CAName,
			},
		},
		Affiliations: affiliations,
		BCCSP: FabricCAChartBCCSP{
			Default: conf.BCCSP.Default,
			SW: FabricCAChartBCCSPSW{
				Hash:     conf.BCCSP.SW.Hash,
				Security: conf.BCCSP.SW.Security,
			},
		},
	}
	return item
}
func parseCrypto(key string, cert string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, nil, err
	}
	pk, err := utils.ParseECDSAPrivateKey(keyBytes)
	if err != nil {
		return nil, nil, err
	}
	certBytes, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		return nil, nil, err
	}
	x509Cert, err := utils.ParseX509Certificate(certBytes)
	if err != nil {
		return nil, nil, err
	}
	return x509Cert, pk, nil
}
func doesCertNeedsToBeRenewed(tlsCert *x509.Certificate, conf *hlfv1alpha1.FabricCA) bool {
	tlsCertDNSNames := tlsCert.DNSNames
	tlsCertIPAddresses := tlsCert.IPAddresses
	expectedDNSNames := getDNSNames(conf.Spec)
	expectedIPAddresses := getIPAddresses(conf.Spec)
	sort.Strings(tlsCertDNSNames)
	sort.Strings(expectedDNSNames)
	sort.Slice(tlsCertIPAddresses, func(i, j int) bool {
		return bytes.Compare(tlsCertIPAddresses[i], tlsCertIPAddresses[j]) < 0
	})
	sort.Slice(expectedIPAddresses, func(i, j int) bool {
		return bytes.Compare(expectedIPAddresses[i], expectedIPAddresses[j]) < 0
	})
	log.Infof(
		"FabricCA, name=%s namespace=%s DNS=%v Expected DNS=%v IPs=%v Expected IPS=%v TLS certs needs to be renewed: %v",
		conf.Name,
		conf.Namespace,
		tlsCertDNSNames,
		expectedDNSNames,
		tlsCertIPAddresses,
		expectedIPAddresses,
		!reflect.DeepEqual(tlsCertDNSNames, expectedDNSNames),
	)
	if !reflect.DeepEqual(tlsCertDNSNames, expectedDNSNames) {
		return true
	}

	return false
}
func GetConfig(conf *hlfv1alpha1.FabricCA, client *kubernetes.Clientset, chartName string, namespace string) (*FabricCAChart, error) {
	spec := conf.Spec
	tlsCert, tlsKey, err := getExistingTLSCrypto(client, chartName, namespace)
	if err != nil {
		tlsCert, tlsKey, err = CreateDefaultTLSCA(spec)
		if err != nil {
			return nil, err
		}
	} else {
		certNeedsToBeRenewed := doesCertNeedsToBeRenewed(tlsCert, conf)
		log.Infof("FabricCA, name=%s namespace=%s TLS certs needs to be renewed: %v", conf.Name, conf.Namespace, certNeedsToBeRenewed)
		if certNeedsToBeRenewed {
			tlsCert, tlsKey, err = CreateDefaultTLSCA(spec)
			if err != nil {
				return nil, err
			}
		}
	}
	var caRef *SecretRef
	signCert, signKey, err := getExistingSignCrypto(client, chartName, namespace)
	if err != nil {
		if conf.Spec.CA.CA != nil && conf.Spec.CA.CA.SecretRef != nil && conf.Spec.CA.CA.SecretRef.Name != "" {
			caRef = &SecretRef{
				SecretName: conf.Spec.CA.CA.SecretRef.Name,
			}
			err = nil
		} else if conf.Spec.CA.CA != nil && conf.Spec.CA.CA.Key != "" && conf.Spec.CA.CA.Cert != "" {
			signCert, signKey, err = parseCrypto(conf.Spec.CA.CA.Key, conf.Spec.CA.CA.Cert)
		} else {
			signCert, signKey, err = CreateDefaultCA(spec.CA)
		}
		if err != nil {
			return nil, err
		}
	}
	var caTLSSignRef *SecretRef
	caTLSSignCert, caTLSSignKey, err := getExistingSignTLSCrypto(client, chartName, namespace)
	if err != nil {
		if conf.Spec.TLSCA.CA != nil && conf.Spec.TLSCA.CA.SecretRef != nil && conf.Spec.TLSCA.CA.SecretRef.Name != "" {
			caTLSSignRef = &SecretRef{
				SecretName: conf.Spec.TLSCA.CA.SecretRef.Name,
			}
			err = nil
		} else if conf.Spec.TLSCA.CA != nil && conf.Spec.TLSCA.CA.Key != "" && conf.Spec.TLSCA.CA.Cert != "" {
			caTLSSignCert, caTLSSignKey, err = parseCrypto(conf.Spec.TLSCA.CA.Key, conf.Spec.TLSCA.CA.Cert)
		} else {
			caTLSSignCert, caTLSSignKey, err = CreateDefaultCA(spec.TLSCA)
		}
		if err != nil {
			return nil, err
		}
	}
	tlsCRTEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: tlsCert.Raw,
	})
	tlsEncodedPK, err := x509.MarshalPKCS8PrivateKey(tlsKey)
	if err != nil {
		return nil, err
	}
	tlsPEMEncodedPK := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: tlsEncodedPK,
	})
	var signCRTEncoded []byte
	if signCert != nil {
		signCRTEncoded = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: signCert.Raw,
		})
	}
	var signPEMEncodedPK []byte
	if signKey != nil {
		signEncodedPK, err := x509.MarshalPKCS8PrivateKey(signKey)
		if err != nil {
			return nil, err
		}
		signPEMEncodedPK = pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: signEncodedPK,
		})
	}
	var caTLSSignCRTEncoded []byte
	if caTLSSignCert != nil {
		caTLSSignCRTEncoded = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caTLSSignCert.Raw,
		})
	}
	var caTLSSignPEMEncodedPK []byte
	if caTLSSignKey != nil {
		caTLSSignEncodedPK, err := x509.MarshalPKCS8PrivateKey(caTLSSignKey)
		if err != nil {
			return nil, err
		}
		caTLSSignPEMEncodedPK = pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: caTLSSignEncodedPK,
		})
	}
	istioPort := 443
	if spec.Istio != nil && spec.Istio.Port != 0 {
		istioPort = spec.Istio.Port
	}
	istioHosts := []string{}
	if spec.Istio != nil && len(spec.Istio.Hosts) > 0 {
		istioHosts = spec.Istio.Hosts
	}
	gatewayApiHosts := []string{}
	gatewayApiName := ""
	gatewayApiNamespace := ""
	gatewayApiPort := 443
	if spec.GatewayApi != nil {
		gatewayApiPort = spec.GatewayApi.Port
		gatewayApiHosts = spec.GatewayApi.Hosts
		gatewayApiName = spec.GatewayApi.GatewayName
		gatewayApiNamespace = spec.GatewayApi.GatewayNamespace
	}
	msp := Msp{
		CARef:          caRef,
		TLSCARef:       caTLSSignRef,
		Keyfile:        string(signPEMEncodedPK),
		Certfile:       string(signCRTEncoded),
		Chainfile:      "",
		TLSCAKeyfile:   string(caTLSSignPEMEncodedPK),
		TLSCACertfile:  string(caTLSSignCRTEncoded),
		TLSCAChainfile: "",
		TlsKeyFile:     string(tlsPEMEncodedPK),
		TlsCertFile:    string(tlsCRTEncoded),
	}
	if conf.Spec.CA.CA != nil {
		msp.Chainfile = conf.Spec.CA.CA.Chain
	}
	if conf.Spec.TLSCA.CA != nil {
		msp.TLSCAChainfile = conf.Spec.TLSCA.CA.Chain
	}
	var serviceMonitor ServiceMonitor
	if spec.ServiceMonitor != nil && spec.ServiceMonitor.Enabled {
		serviceMonitor = ServiceMonitor{
			Enabled:           spec.ServiceMonitor.Enabled,
			Labels:            spec.ServiceMonitor.Labels,
			Interval:          spec.ServiceMonitor.Interval,
			ScrapeTimeout:     spec.ServiceMonitor.ScrapeTimeout,
			Scheme:            "http",
			Relabelings:       []interface{}{},
			TargetLabels:      []interface{}{},
			MetricRelabelings: []interface{}{},
			SampleLimit:       spec.ServiceMonitor.SampleLimit,
		}
	} else {
		serviceMonitor = ServiceMonitor{
			Enabled: false,
		}
	}

	traefik := Traefik{}
	if spec.Traefik != nil {
		var middlewares []TraefikMiddleware
		if spec.Traefik.Middlewares != nil {
			for _, middleware := range spec.Traefik.Middlewares {
				middlewares = append(middlewares, TraefikMiddleware{
					Name:      middleware.Name,
					Namespace: middleware.Namespace,
				})
			}
		}
		traefik = Traefik{
			Entrypoints: spec.Traefik.Entrypoints,
			Middlewares: middlewares,
			Hosts:       spec.Traefik.Hosts,
		}
	}
	replicas := 1
	if spec.Replicas != nil {
		replicas = *spec.Replicas
	}
	var c = FabricCAChart{
		Replicas:         replicas,
		PodLabels:        spec.PodLabels,
		PodAnnotations:   spec.PodAnnotations,
		ImagePullSecrets: spec.ImagePullSecrets,
		EnvVars:          spec.Env,
		FullNameOverride: conf.Name,
		Istio: Istio{
			Port:  istioPort,
			Hosts: istioHosts,
		},
		GatewayApi: GatewayApi{
			Port:             gatewayApiPort,
			Hosts:            gatewayApiHosts,
			GatewayName:      gatewayApiName,
			GatewayNamespace: gatewayApiNamespace,
		},
		ServiceMonitor: serviceMonitor,
		Image: Image{
			Repository: spec.Image,
			Tag:        spec.Version,
			PullPolicy: "IfNotPresent",
		},
		Service: Service{
			Type: string(spec.Service.ServiceType),
			Port: 7054,
		},
		Traefik: traefik,
		Persistence: Persistence{
			Enabled:      true,
			Annotations:  map[string]string{},
			StorageClass: spec.Storage.StorageClass,
			AccessMode:   string(spec.Storage.AccessMode),
			Size:         spec.Storage.Size,
		},
		Msp: msp,
		Database: Database{
			Type:       spec.Database.Type,
			Datasource: spec.Database.Datasource,
		},
		Resources:    spec.Resources,
		NodeSelector: spec.NodeSelector,
		Tolerations:  spec.Tolerations,
		Affinity:     spec.Affinity,
		Debug:        spec.Debug,
		CLRSizeLimit: spec.CLRSizeLimit,
		Metrics: FabricCAChartMetrics{
			Provider: spec.Metrics.Provider,
			Statsd: FabricCAChartMetricsStatsd{
				Network:       spec.Metrics.Statsd.Network,
				Address:       spec.Metrics.Statsd.Address,
				WriteInterval: spec.Metrics.Statsd.WriteInterval,
				Prefix:        spec.Metrics.Statsd.Prefix,
			},
		},

		Ca:    mapCRDItemConfToChart(spec.CA),
		TLSCA: mapCRDItemConfToChart(spec.TLSCA),
		Cors: Cors{
			Enabled: spec.Cors.Enabled,
			Origins: spec.Cors.Origins,
		},
	}
	return &c, nil
}

type Status struct {
	Status    hlfv1alpha1.DeploymentStatus
	TlsCert   string
	CACert    string
	TLSCACert string
	NodeURL   string
	NodePort  int
	NodeHost  string
}

func GetServiceName(releaseName string) string {
	return releaseName
}
func GetDeploymentName(releaseName string) string {
	return releaseName
}
func GetCAState(clientSet *kubernetes.Clientset, ca *hlfv1alpha1.FabricCA, releaseName string, ns string) (*Status, error) {
	ctx := context.Background()
	k8sIP, err := utils.GetPublicIPKubernetes(clientSet)
	if err != nil {
		return nil, err
	}
	r := &Status{
		Status: hlfv1alpha1.PendingStatus,
	}
	depName := GetDeploymentName(releaseName)
	dep, err := clientSet.AppsV1().Deployments(ns).Get(ctx, depName, v1.GetOptions{})
	if err != nil {
		return nil, err
	}
	pods, err := clientSet.CoreV1().Pods(ns).List(ctx, v1.ListOptions{
		LabelSelector: fmt.Sprintf("release=%s", releaseName),
	})
	if err != nil {
		return nil, err
	}
	if len(pods.Items) > 0 {
		for _, item := range pods.Items {
			if utils.IsPodReadyConditionTrue(item.Status) {
				r.Status = hlfv1alpha1.RunningStatus
			} else {
				switch item.Status.Phase {
				case corev1.PodPending:
					r.Status = hlfv1alpha1.PendingStatus
				case corev1.PodFailed:
					r.Status = hlfv1alpha1.FailedStatus
				case corev1.PodSucceeded:
				case corev1.PodRunning:
				case corev1.PodUnknown:
					r.Status = hlfv1alpha1.UnknownStatus
				}
			}
		}
	} else {
		replicas := 1
		if ca.Spec.Replicas != nil {
			replicas = *ca.Spec.Replicas
		}
		if dep.Status.ReadyReplicas == int32(replicas) {
			r.Status = hlfv1alpha1.RunningStatus
		} else {
			r.Status = hlfv1alpha1.PendingStatus
		}
	}
	svcName := GetServiceName(releaseName)
	svc, err := clientSet.CoreV1().Services(ns).Get(ctx, svcName, v1.GetOptions{})
	if err != nil {
		return nil, err
	}
	nodePort := svc.Spec.Ports[0].NodePort
	r.NodeURL = fmt.Sprintf("https://%s:%d", k8sIP, nodePort)
	r.NodePort = int(nodePort)
	r.NodeHost = k8sIP
	tlsCrt, _, err := getExistingTLSCrypto(clientSet, releaseName, ns)
	if err != nil {
		return nil, err
	}
	r.TlsCert = string(utils.EncodeX509Certificate(tlsCrt))
	hlfmetrics.UpdateCertificateExpiry(
		"ca",
		"tls",
		tlsCrt,
		releaseName,
		ns,
	)
	var signCrt *x509.Certificate
	if ca.Spec.CA.CA != nil && ca.Spec.CA.CA.SecretRef != nil && ca.Spec.CA.CA.SecretRef.Name != "" {
		signCrt, _, err = getAlreadyExistingCrypto(clientSet, ca.Spec.CA.CA.SecretRef.Name, ns)
		if err != nil {
			return nil, err
		}
	} else {
		signCrt, _, err = getExistingSignCrypto(clientSet, releaseName, ns)
		if err != nil {
			return nil, err
		}
	}
	r.CACert = string(utils.EncodeX509Certificate(signCrt))
	hlfmetrics.UpdateCertificateExpiry(
		"ca",
		"signca",
		signCrt,
		releaseName,
		ns,
	)
	var tlsCACrt *x509.Certificate
	if ca.Spec.TLSCA.CA != nil && ca.Spec.TLSCA.CA.SecretRef != nil && ca.Spec.TLSCA.CA.SecretRef.Name != "" {
		tlsCACrt, _, err = getAlreadyExistingCrypto(clientSet, ca.Spec.TLSCA.CA.SecretRef.Name, ns)
		if err != nil {
			return nil, err
		}
	} else {
		tlsCACrt, _, err = getExistingSignTLSCrypto(clientSet, releaseName, ns)
		if err != nil {
			return nil, err
		}
	}
	r.TLSCACert = string(utils.EncodeX509Certificate(tlsCACrt))
	hlfmetrics.UpdateCertificateExpiry(
		"ca",
		"tlsca",
		tlsCACrt,
		releaseName,
		ns,
	)
	return r, nil
}

const caFinalizer = "finalizer.ca.hlf.kungfusoftware.es"

func (r *FabricCAReconciler) finalizeCA(reqLogger logr.Logger, m *hlfv1alpha1.FabricCA) error {
	ns := m.Namespace
	if ns == "" {
		ns = "default"
	}
	cfg, err := newActionCfg(r.Log, r.Config, ns)
	if err != nil {
		return err
	}
	releaseName := m.Name
	reqLogger.Info("Successfully finalized ca")
	cmd := action.NewUninstall(cfg)
	cmd.Wait = r.Wait
	cmd.Timeout = r.Timeout
	resp, err := cmd.Run(releaseName)
	if err != nil {
		if strings.Compare("Release not loaded", err.Error()) != 0 {
			return nil
		}
		log.Debugf("Failed to uninstall release %s %v", releaseName, err)
		return err
	}
	log.Debugf("Release %s deleted=%s", releaseName, resp.Info)
	return nil
}

func (r *FabricCAReconciler) addFinalizer(reqLogger logr.Logger, m *hlfv1alpha1.FabricCA) error {
	reqLogger.Info("Adding Finalizer for the CA")
	controllerutil.AddFinalizer(m, caFinalizer)

	// Update CR
	err := r.Update(context.TODO(), m)
	if err != nil {
		reqLogger.Error(err, "Failed to update CA with finalizer")
		return err
	}
	return nil
}

func Reconcile(
	req ctrl.Request,
	r *FabricCAReconciler,
	cfg *action.Configuration,
) (ctrl.Result, error) {
	ctx := context.Background()
	reqLogger := r.Log.WithValues("hlf", req.NamespacedName)
	ns := req.Namespace
	hlf := &hlfv1alpha1.FabricCA{}
	releaseName := req.Name
	err := r.Get(ctx, req.NamespacedName, hlf)
	if err != nil {
		log.Debugf("Error getting the object %s error=%v", req.NamespacedName, err)
		if apierrors.IsNotFound(err) {
			reqLogger.Info("CA resource not found. Ignoring since object must be deleted.")
			return ctrl.Result{}, nil
		}
		reqLogger.Error(err, "Failed to get CA.")
		return ctrl.Result{}, err
	}
	isMemcachedMarkedToBeDeleted := hlf.GetDeletionTimestamp() != nil
	if isMemcachedMarkedToBeDeleted {
		if utils.Contains(hlf.GetFinalizers(), caFinalizer) {
			if err := r.finalizeCA(reqLogger, hlf); err != nil {
				return ctrl.Result{}, err
			}
			controllerutil.RemoveFinalizer(hlf, caFinalizer)
			err := r.Update(ctx, hlf)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}
	if !utils.Contains(hlf.GetFinalizers(), caFinalizer) {
		if err := r.addFinalizer(reqLogger, hlf); err != nil {
			return ctrl.Result{}, err
		}
	}

	cmdStatus := action.NewStatus(cfg)
	exists := true
	helmStatus, err := cmdStatus.Run(releaseName)
	if err != nil {
		if errors.Is(err, driver.ErrReleaseNotFound) {
			// it doesn't exists
			exists = false
		} else {
			// it doesn't exist
			return ctrl.Result{}, err
		}
	}
	if exists && helmStatus.Info.Status == release.StatusPendingUpgrade {
		rollbackStatus := action.NewRollback(cfg)
		rollbackStatus.Version = helmStatus.Version - 1
		err = rollbackStatus.Run(releaseName)
		if err != nil {
			// it doesn't exist
			return ctrl.Result{}, err
		}
	} else if exists && helmStatus.Info.Status == release.StatusPendingRollback {
		historyAction := action.NewHistory(cfg)
		history, err := historyAction.Run(releaseName)
		if err != nil {
			return ctrl.Result{}, err
		}
		if len(history) > 0 {
			// find the last deployed revision
			// and rollback to it
			// sort history by revision number descending using raw go
			sort.Slice(history, func(i, j int) bool {
				return history[i].Version > history[j].Version
			})
			for _, historyItem := range history {
				if historyItem.Info.Status == release.StatusDeployed {
					rollbackStatus := action.NewRollback(cfg)
					rollbackStatus.Version = historyItem.Version
					err = rollbackStatus.Run(releaseName)
					if err != nil {
						// it doesn't exist
						return ctrl.Result{}, err
					}
					break
				}
			}
		}
	}
	log.Debugf("Release %s exists=%v", releaseName, exists)
	clientSet, err := utils.GetClientKubeWithConf(r.Config)
	if err != nil {
		return ctrl.Result{}, err
	}

	if exists {
		// update
		log.Debugf("Release %s exists, updating", releaseName)
		s, err := GetCAState(r.ClientSet, hlf, releaseName, ns)
		if err != nil {
			return ctrl.Result{}, err
		}
		err = r.Get(ctx, req.NamespacedName, hlf)
		if err != nil {
			log.Debugf("Error getting the object %s error=%v", req.NamespacedName, err)
			if apierrors.IsNotFound(err) {
				reqLogger.Info("CA resource not found. Ignoring since object must be deleted.")
				return ctrl.Result{}, nil
			}
			reqLogger.Error(err, "Failed to get CA.")
			return ctrl.Result{}, err
		}
		fca := hlf.DeepCopy()
		fca.Status.Status = s.Status
		fca.Status.Message = ""
		fca.Status.TlsCert = s.TlsCert
		fca.Status.TLSCACert = s.TLSCACert
		fca.Status.CACert = s.CACert
		fca.Status.NodePort = s.NodePort
		fca.Status.Conditions.SetCondition(status.Condition{
			Type:               status.ConditionType(s.Status),
			Status:             "True",
			LastTransitionTime: v1.Time{},
		})
		if helmStatus.Info.Status != release.StatusPendingUpgrade {
			c, err := GetConfig(hlf, clientSet, releaseName, req.Namespace)
			if err != nil {
				return ctrl.Result{}, err
			}
			inrec, err := json.Marshal(c)
			if err != nil {
				return ctrl.Result{}, err
			}
			var inInterface map[string]interface{}
			err = json.Unmarshal(inrec, &inInterface)
			if err != nil {
				return ctrl.Result{}, err
			}
			cmd := action.NewUpgrade(cfg)
			cmd.Timeout = r.Timeout
			cmd.Wait = r.Wait
			cmd.MaxHistory = r.MaxHistory

			settings := cli.New()
			chartPath, err := cmd.LocateChart(r.ChartPath, settings)
			ch, err := loader.Load(chartPath)
			if err != nil {
				return ctrl.Result{}, err
			}
			release, err := cmd.Run(releaseName, ch, inInterface)
			if err != nil {
				setConditionStatus(hlf, hlfv1alpha1.FailedStatus, false, err, false)
				return r.updateCRStatusOrFailReconcile(ctx, r.Log, hlf)
			}
			log.Debugf("Chart upgraded %s", release.Name)
		}
		if !reflect.DeepEqual(fca.Status, hlf.Status) {
			if err := r.Status().Update(ctx, fca); err != nil {
				log.Debugf("Error updating the status: %v", err)
				return ctrl.Result{}, err
			}
		}
		reqLogger.Info(fmt.Sprintf("CA Status %s", s.Status))
		switch s.Status {
		case hlfv1alpha1.PendingStatus:
			log.Infof("CA %s in pending status, refreshing state in 10 seconds", fca.Name)
			return ctrl.Result{
				RequeueAfter: 10 * time.Second,
			}, nil
		case hlfv1alpha1.RunningStatus:
			return ctrl.Result{
				RequeueAfter: 60 * time.Minute,
			}, nil
		case hlfv1alpha1.FailedStatus:
			log.Infof("CA %s in failed status, refreshing state in 10 seconds", fca.Name)
			return ctrl.Result{
				RequeueAfter: 10 * time.Second,
			}, nil
		default:
			return ctrl.Result{}, nil
		}
	} else {
		cmd := action.NewInstall(cfg)
		name, chart, err := cmd.NameAndChart([]string{releaseName, r.ChartPath})
		if err != nil {
			return ctrl.Result{}, err
		}
		cmd.ReleaseName = name
		cmd.Wait = r.Wait
		cmd.Timeout = r.Timeout
		ch, err := loader.Load(chart)
		if err != nil {
			return ctrl.Result{}, err
		}
		c, err := GetConfig(hlf, clientSet, name, req.Namespace)
		if err != nil {
			reqLogger.Error(err, "Failed to get config")
			return ctrl.Result{}, err
		}
		var inInterface map[string]interface{}
		inrec, err := json.Marshal(c)
		if err != nil {
			reqLogger.Error(err, "Failed to marshall helm values")
			return ctrl.Result{}, err
		}
		err = json.Unmarshal(inrec, &inInterface)
		if err != nil {
			return ctrl.Result{}, err
		}
		release, err := cmd.Run(ch, inInterface)
		if err != nil {
			setConditionStatus(hlf, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, hlf)
		}
		log.Debugf("Chart installed %s", release.Name)
		hlf.Status.Status = hlfv1alpha1.PendingStatus
		hlf.Status.Conditions.SetCondition(status.Condition{
			Type:               "DEPLOYED",
			Status:             "True",
			LastTransitionTime: v1.Time{},
		})
		if err := r.Status().Update(ctx, hlf); err != nil {
			return ctrl.Result{}, err
		}
		log.Info("CA is installed and must run successfully")
		return ctrl.Result{
			Requeue:      false,
			RequeueAfter: 10 * time.Second,
		}, nil
	}
}

var (
	ErrClientK8s = errors.New("k8sAPIClientError")
)

func (r *FabricCAReconciler) updateCRStatusOrFailReconcile(ctx context.Context, log logr.Logger, p *hlfv1alpha1.FabricCA) (
	ctrl.Result, error) {
	if err := r.Status().Update(ctx, p); err != nil {
		log.Error(err, fmt.Sprintf("%v failed to update the application status", ErrClientK8s))
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func setConditionStatus(p *hlfv1alpha1.FabricCA, conditionType hlfv1alpha1.DeploymentStatus, statusFlag bool, err error, statusUnknown bool) (update bool) {
	statusStr := func() corev1.ConditionStatus {
		if statusUnknown {
			return corev1.ConditionUnknown
		}
		if statusFlag {
			return corev1.ConditionTrue
		} else {
			return corev1.ConditionFalse
		}
	}
	p.Status.Status = conditionType
	if err != nil {
		p.Status.Message = err.Error()
	}
	condition := func() status.Condition {
		if err != nil {
			return status.Condition{
				Type:    status.ConditionType(conditionType),
				Status:  statusStr(),
				Reason:  status.ConditionReason(err.Error()),
				Message: err.Error(),
			}
		}
		return status.Condition{
			Type:   status.ConditionType(conditionType),
			Status: statusStr(),
		}
	}
	return p.Status.Conditions.SetCondition(condition())
}

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabriccas,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabriccas/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabriccas/finalizers,verbs=update
func (r *FabricCAReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	ns := req.Namespace
	cfg, err := newActionCfg(r.Log, r.Config, ns)
	if err != nil {
		return ctrl.Result{}, err
	}
	return Reconcile(
		req,
		r,
		cfg,
	)

}

func (r *FabricCAReconciler) SetupWithManager(mgr ctrl.Manager, maxConcurrentReconciles int) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&hlfv1alpha1.FabricCA{}).
		Owns(&appsv1.Deployment{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: maxConcurrentReconciles,
		}).
		Complete(r)
}
