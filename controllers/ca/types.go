package ca

import corev1 "k8s.io/api/core/v1"

type FabricCAChart struct {
	PodLabels        map[string]string             `json:"podLabels"`
	PodAnnotations   map[string]string             `json:"podAnnotations"`
	Istio            Istio                         `json:"istio"`
	Traefik          Traefik                       `json:"traefik"`
	GatewayApi       GatewayApi                    `json:"gatewayApi"`
	FullNameOverride string                        `json:"fullnameOverride"`
	Image            Image                         `json:"image"`
	Service          Service                       `json:"service"`
	Persistence      Persistence                   `json:"persistence"`
	Msp              Msp                           `json:"msp"`
	Database         Database                      `json:"db"`
	Resources        corev1.ResourceRequirements   `json:"resources"`
	NodeSelector     *corev1.NodeSelector          `json:"nodeSelector,omitempty"`
	Tolerations      []corev1.Toleration           `json:"tolerations"`
	Affinity         *corev1.Affinity              `json:"affinity,omitempty"`
	Metrics          FabricCAChartMetrics          `json:"metrics"`
	Debug            bool                          `json:"debug"`
	CLRSizeLimit     int                           `json:"clrsizelimit"`
	Ca               FabricCAChartItemConf         `json:"ca"`
	TLSCA            FabricCAChartItemConf         `json:"tlsCA"`
	Cors             Cors                          `json:"cors"`
	ServiceMonitor   ServiceMonitor                `json:"serviceMonitor"`
	EnvVars          []corev1.EnvVar               `json:"envVars"`
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets"`
	// +kubebuilder:default:=1
	Replicas int `json:"replicas"`
}
type ServiceMonitor struct {
	Enabled           bool              `json:"enabled"`
	Labels            map[string]string `json:"labels"`
	Interval          string            `json:"interval"`
	ScrapeTimeout     string            `json:"scrapeTimeout"`
	Scheme            string            `json:"scheme"`
	Relabelings       []interface{}     `json:"relabelings"`
	TargetLabels      []interface{}     `json:"targetLabels"`
	MetricRelabelings []interface{}     `json:"metricRelabelings"`
	SampleLimit       int               `json:"sampleLimit"`
}
type TraefikMiddleware struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}
type Traefik struct {
	Entrypoints []string            `json:"entryPoints"`
	Middlewares []TraefikMiddleware `json:"middlewares"`
	Hosts       []string            `json:"hosts"`
}
type Istio struct {
	Port  int      `json:"port"`
	Hosts []string `json:"hosts"`
}
type GatewayApi struct {
	Port             int      `json:"port"`
	Hosts            []string `json:"hosts"`
	GatewayName      string   `json:"gatewayName"`
	GatewayNamespace string   `json:"gatewayNamespace"`
}
type Cors struct {
	Enabled bool     `json:"enabled"`
	Origins []string `json:"origins"`
}

type FabricCAChartItemConf struct {
	Name         string                    `json:"name"`
	CFG          FabricCAChartCFG          `json:"cfg"`
	CSR          FabricCAChartCSR          `json:"csr"`
	CRL          FabricCAChartCRL          `json:"crl"`
	Registry     FabricCAChartRegistry     `json:"registry"`
	Signing      FabricCASigning           `json:"signing"`
	Intermediate FabricCAChartIntermediate `json:"intermediate"`
	BCCSP        FabricCAChartBCCSP        `json:"bccsp"`
	Affiliations []Affiliation             `json:"affiliations"`
}
type FabricCAChartBCCSP struct {
	Default string               `json:"default"`
	SW      FabricCAChartBCCSPSW `json:"sw"`
}
type FabricCAChartBCCSPSW struct {
	Hash     string `json:"hash"`
	Security string `json:"security"`
}

type FabricCAChartIntermediate struct {
	ParentServer FabricCAChartIntermediateParentServer `json:"parentServer"`
}
type FabricCAChartIntermediateParentServer struct {
	URL    string `json:"url"`
	CAName string `json:"caName"`
}
type FabricCAChartIntermediateEnrollment struct {
	Hosts   string `json:"hosts"`
	Profile string `json:"profile"`
	Label   string `json:"label"`
}
type FabricCAChartIntermediateTLS struct {
	CertFiles []string                           `json:"certFiles"`
	Client    FabricCAChartIntermediateTLSClient `json:"client"`
}
type FabricCAChartIntermediateTLSClient struct {
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}
type FabricCAChartRegistry struct {
	MaxEnrollments int                     `json:"maxenrollments"`
	Identities     []FabricCAChartIdentity `json:"identities"`
}
type FabricCAChartIdentity struct {
	Name        string                     `json:"name"`
	Pass        string                     `json:"pass"`
	Type        string                     `json:"type"`
	Affiliation string                     `json:"affiliation"`
	Attrs       FabricCAChartIdentityAttrs `json:"attrs"`
}
type FabricCAChartIdentityAttrs struct {
	RegistrarRoles string `json:"hf.Registrar.Roles"`
	DelegateRoles  string `json:"hf.Registrar.DelegateRoles"`
	Attributes     string `json:"hf.Registrar.Attributes"`
	Revoker        bool   `json:"hf.Revoker"`
	IntermediateCA bool   `json:"hf.IntermediateCA"`
	GenCRL         bool   `json:"hf.GenCRL"`
	AffiliationMgr bool   `json:"hf.AffiliationMgr"`
}
type FabricCAChartCRL struct {
	Expiry string `json:"expiry"`
}
type FabricCAChartCSR struct {
	CN    string               `json:"cn"`
	Hosts []string             `json:"hosts"`
	Names []FabricCAChartNames `json:"names"`
	CA    FabricCAChartCSRCA   `json:"ca"`
}
type FabricCAChartCSRCA struct {
	Expiry     string `json:"expiry"`
	PathLength int    `json:"pathlength"`
}
type FabricCAChartNames struct {
	C  string `json:"C"`
	ST string `json:"ST"`
	O  string `json:"O"`
	L  string `json:"L"`
	OU string `json:"OU"`
}
type FabricCAChartSpecService struct {
	ServiceType string `json:"type"`
}

type FabricCAChartCFG struct {
	Identities   FabricCAChartCFGIdentities  `json:"identities"`
	Affiliations FabricCAChartCFGAffilitions `json:"affiliations"`
}
type FabricCAChartCFGIdentities struct {
	AllowRemove bool `json:"allowRemove"`
}
type FabricCAChartCFGAffilitions struct {
	AllowRemove bool `json:"allowRemove"`
}
type FabricCAChartMetrics struct {
	Provider string                     `json:"provider"`
	Statsd   FabricCAChartMetricsStatsd `json:"statsd"`
}
type FabricCAChartMetricsStatsd struct {
	Network       string `json:"network"`
	Address       string `json:"address"`
	WriteInterval string `json:"writeInterval"`
	Prefix        string `json:"prefix"`
}
type Image struct {
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	PullPolicy string `json:"pullPolicy"`
}
type Service struct {
	Type string `json:"type"`
	Port int    `json:"port"`
}

type Ingress struct {
	Enabled     bool              `json:"enabled"`
	Annotations map[string]string `json:"annotations"`
	Path        string            `json:"path"`
	Hosts       []string          `json:"hosts"`
	TLS         []interface{}     `json:"tls"`
}
type Persistence struct {
	Enabled      bool              `json:"enabled"`
	Annotations  map[string]string `json:"annotations"`
	StorageClass string            `json:"storageClass"`
	AccessMode   string            `json:"accessMode"`
	Size         string            `json:"size"`
}
type SecretRef struct {
	SecretName string `json:"secretName"`
}
type Msp struct {
	CARef    *SecretRef `json:"caRef"`
	TLSCARef *SecretRef `json:"tlsCARef"`

	Keyfile        string `json:"keyfile"`
	Certfile       string `json:"certfile"`
	Chainfile      string `json:"chainfile"`
	TLSCAKeyfile   string `json:"tlsCAKeyFile"`
	TLSCACertfile  string `json:"tlsCACertFile"`
	TLSCAChainfile string `json:"tlsCAChainfile"`
	TlsKeyFile     string `json:"tlsKeyFile"`
	TlsCertFile    string `json:"tlsCertFile"`
}

type ConfigurationFiles struct {
	MysqlCnf string `json:"mysql.cnf"`
}
type Mysql struct {
	Enabled            bool               `json:"enabled"`
	Image              string             `json:"image"`
	ImageTag           string             `json:"imageTag"`
	MysqlDatabase      string             `json:"mysqlDatabase"`
	MysqlUser          string             `json:"mysqlUser"`
	ConfigurationFiles ConfigurationFiles `json:"configurationFiles"`
}
type Database struct {
	Type       string `json:"type"`
	Datasource string `json:"datasource"`
}

type Names struct {
	C  string      `json:"c"`
	St string      `json:"st"`
	L  interface{} `json:"l"`
	O  string      `json:"o"`
	Ou string      `json:"ou"`
}
type Affiliation struct {
	Name        string   `json:"name"`
	Departments []string `json:"departments"`
}

type FabricCASigning struct {
	Default  FabricCASigningDefault  `json:"default"`
	Profiles FabricCASigningProfiles `json:"profiles"`
}
type FabricCASigningProfiles struct {
	CA  FabricCASigningSignProfile `json:"ca"`
	TLS FabricCASigningTLSProfile  `json:"tls"`
}
type FabricCASigningSignProfile struct {
	// +kubebuilder:default:={"cert sign","crl sign"}
	Usage []string `json:"usage"`
	// +kubebuilder:default:="43800h"
	Expiry       string                               `json:"expiry"`
	CAConstraint FabricCASigningSignProfileConstraint `json:"caconstraint"`
}
type FabricCASigningSignProfileConstraint struct {
	// +kubebuilder:default:=true
	IsCA bool `json:"isCA"`
	// +kubebuilder:default:=0
	MaxPathLen int `json:"maxPathLen"`
}
type FabricCASigningTLSProfile struct {
	// +kubebuilder:default:={"signing","key encipherment", "server auth", "client auth", "key agreement"}
	Usage []string `json:"usage"`
	// +kubebuilder:default:="8760h"
	Expiry string `json:"expiry"`
}
type FabricCASigningDefault struct {
	// +kubebuilder:default:="8760h"
	Expiry string `json:"expiry"`
	// +kubebuilder:default:={"digital signature"}
	Usage []string `json:"usage"`
}
