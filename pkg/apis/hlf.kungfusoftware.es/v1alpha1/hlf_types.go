/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"fmt"
	"strings"

	sb "github.com/hyperledger/fabric-protos-go/orderer/smartbft"
	"github.com/kfsoftware/hlf-operator/pkg/status"
	"k8s.io/api/networking/v1beta1"
	kubeclock "k8s.io/utils/clock"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// clock is used to set status condition timestamps.
// This variable makes it easier to test conditions.
var clock kubeclock.Clock = &kubeclock.RealClock{}

// ConditionType is the type of the condition and is typically a CamelCased
// word or short phrase.
//
// Condition types should indicate state in the "abnormal-true" polarity. For
// example, if the condition indicates when a policy is invalid, the "is valid"
// case is probably the norm, so the condition should be called "Invalid".
type ConditionType string

// ConditionReason is intended to be a one-word, CamelCase representation of
// the category of cause of the current status. It is intended to be used in
// concise output, such as one-line kubectl get output, and in summarizing
// occurrences of causes.
type ConditionReason string

type Condition struct {
	Type               ConditionType          `json:"type"`
	Status             corev1.ConditionStatus `json:"status"`
	Reason             ConditionReason        `json:"reason,omitempty"`
	Message            string                 `json:"message,omitempty"`
	LastTransitionTime metav1.Time            `json:"lastTransitionTime,omitempty"`
}

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

type CA struct {
	// +kubebuilder:validation:MinLength=1
	Host string `json:"host"`
	// +kubebuilder:validation:MinLength=1
	Cert string `json:"cert"`
	// +kubebuilder:validation:MinLength=1
	User string `json:"user"`
	// +kubebuilder:validation:MinLength=1
	Password string `json:"password"`
}

// +kubebuilder:validation:Enum=couchdb;leveldb;pg
type StateDB string

// Use LevelDB database
const StateDBLevelDB StateDB = "leveldb"

// Use CouchDB database
const StateDBCouchDB StateDB = "couchdb"

// Use Postgres database
const StateDBPostgres StateDB = "pg"

type ExternalBuilder struct {
	Name string `json:"name"`
	Path string `json:"path"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	PropagateEnvironment []string `json:"propagateEnvironment"`
}

const DefaultImagePullPolicy = corev1.PullIfNotPresent

type ServiceMonitor struct {
	// +kubebuilder:default:=false
	Enabled bool `json:"enabled"`
	// +optional
	Labels map[string]string `json:"labels"`
	// +kubebuilder:default:=0
	SampleLimit int `json:"sampleLimit"`
	// +kubebuilder:default:="10s"
	Interval string `json:"interval"`
	// +kubebuilder:default:="10s"
	ScrapeTimeout string `json:"scrapeTimeout"`
}

type FabricPeerCouchdbExporter struct {
	// +kubebuilder:default:=false
	Enabled bool `json:"enabled"`
	// +kubebuilder:default:="gesellix/couchdb-prometheus-exporter"
	Image string `json:"image"`
	// +kubebuilder:default:="v30.0.0"
	Tag string `json:"tag"`
	// +kubebuilder:default:="IfNotPresent"
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy"`
}

type GRPCProxy struct {
	// +kubebuilder:default:=false
	Enabled bool `json:"enabled"`
	// +kubebuilder:default:="ghcr.io/hyperledger-labs/grpc-web"
	Image string `json:"image"`
	// +kubebuilder:default:="latest"
	Tag string `json:"tag"`

	Istio FabricIstio `json:"istio"`
	// +kubebuilder:default:="IfNotPresent"
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy"`

	// +nullable
	Resources *corev1.ResourceRequirements `json:"resources"`
	// +kubebuilder:validation:Default={}
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets"`
}
type AddressOverride struct {
	From        string `json:"from"`
	To          string `json:"to"`
	CACertsFile string `json:"caCertsFile"`
}

// FabricPeerSpec defines the desired state of FabricPeer
type FabricPeerSpec struct {
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:={}
	PodAnnotations map[string]string `json:"podAnnotations"`
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:={}
	PodLabels map[string]string `json:"podLabels"`

	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:={}
	DeliveryClientaddressOverrides []AddressOverride `json:"deliveryClientaddressOverrides"`
	// +optional
	// +nullable
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:={}
	Volumes []corev1.Volume `json:"volumes"`

	// +optional
	// +nullable
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:={}
	PeerVolumeMounts []corev1.VolumeMount `json:"peerVolumeMounts"`

	// +optional
	// +nullable
	UpdateCertificateTime *metav1.Time `json:"updateCertificateTime"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Affinity *corev1.Affinity `json:"affinity"`
	// +optional
	// +nullable
	ServiceMonitor *ServiceMonitor `json:"serviceMonitor"`
	// +optional
	// +nullable
	HostAliases []corev1.HostAlias `json:"hostAliases"`

	// +kubebuilder:validation:Default={}
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	NodeSelector *corev1.NodeSelector `json:"nodeSelector,omitempty"`

	// +optional
	// +nullable
	CouchDBExporter *FabricPeerCouchdbExporter `json:"couchDBexporter"`

	// +optional
	// +nullable
	GRPCProxy *GRPCProxy `json:"grpcProxy"`

	// +kubebuilder:default:=1
	Replicas int `json:"replicas"`
	// +kubebuilder:default:=""
	DockerSocketPath string `json:"dockerSocketPath"`
	// +kubebuilder:validation:MinLength=1
	Image string `json:"image"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	ExternalBuilders []ExternalBuilder `json:"externalBuilders"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	GatewayApi *FabricGatewayApi `json:"gatewayApi"`

	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	Traefik *FabricTraefik `json:"traefik"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	Istio            *FabricIstio         `json:"istio"`
	Gossip           FabricPeerSpecGossip `json:"gossip"`
	ExternalEndpoint string               `json:"externalEndpoint"`
	// +kubebuilder:validation:MinLength=1
	Tag string `json:"tag"`
	// +kubebuilder:default:="IfNotPresent"
	ImagePullPolicy          corev1.PullPolicy `json:"imagePullPolicy,omitempty"`
	ExternalChaincodeBuilder bool              `json:"external_chaincode_builder"`
	CouchDB                  FabricPeerCouchDB `json:"couchdb"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	FSServer *FabricFSServer `json:"fsServer"`

	// +kubebuilder:validation:Default={}
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets"`

	// +kubebuilder:validation:MinLength=3
	MspID     string              `json:"mspID"`
	Secret    Secret              `json:"secret"`
	Service   PeerService         `json:"service"`
	StateDb   StateDB             `json:"stateDb"`
	Storage   FabricPeerStorage   `json:"storage"`
	Discovery FabricPeerDiscovery `json:"discovery"`
	Logging   FabricPeerLogging   `json:"logging"`
	Resources FabricPeerResources `json:"resources"`
	Hosts     []string            `json:"hosts"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	// +kubebuilder:validation:Default={}
	Tolerations []corev1.Toleration `json:"tolerations"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Env []corev1.EnvVar `json:"env"`

	// +kubebuilder:default:="kubernetes"
	// +kubebuilder:validation:Enum=kubernetes;vault
	CredentialStore CredentialStore `json:"credentialStore"`
}

type VaultComponent struct {
	Request VaultPKICertificateRequest `json:"request"`
	Vault   VaultSpecConf              `json:"vault"`
}

type FabricPeerResources struct {
	Peer      *corev1.ResourceRequirements `json:"peer"`
	CouchDB   *corev1.ResourceRequirements `json:"couchdb"`
	Chaincode *corev1.ResourceRequirements `json:"chaincode"`
	// +optional
	// +nullable
	CouchDBExporter *corev1.ResourceRequirements `json:"couchdbExporter"`
	// +optional
	// +nullable
	Proxy *corev1.ResourceRequirements `json:"proxy"`
}
type FabricPeerDiscovery struct {
	Period      string `json:"period"`
	TouchPeriod string `json:"touchPeriod"`
}
type FabricPeerLogging struct {
	Level    string `json:"level"`
	Peer     string `json:"peer"`
	Cauthdsl string `json:"cauthdsl"`
	Gossip   string `json:"gossip"`
	Grpc     string `json:"grpc"`
	Ledger   string `json:"ledger"`
	Msp      string `json:"msp"`
	Policies string `json:"policies"`
}
type FabricPeerStorage struct {
	CouchDB   Storage `json:"couchdb"`
	Peer      Storage `json:"peer"`
	Chaincode Storage `json:"chaincode"`
}
type FabricFSServer struct {
	// +kubebuilder:default:="quay.io/kfsoftware/fs-peer"
	Image string `json:"image"`
	// +kubebuilder:default:="amd64-2.2.0"
	Tag string `json:"tag"`
	// +kubebuilder:default:="IfNotPresent"
	PullPolicy corev1.PullPolicy `json:"pullPolicy"`
}
type FabricPeerCouchDB struct {
	User     string `json:"user"`
	Password string `json:"password"`

	// +kubebuilder:default:="couchdb"
	Image string `json:"image"`
	// +kubebuilder:default:="3.1.1"
	Tag string `json:"tag"`
	// +kubebuilder:default:="IfNotPresent"
	PullPolicy corev1.PullPolicy `json:"pullPolicy"`

	// +optional
	// +nullable
	ExternalCouchDB *FabricPeerExternalCouchDB `json:"externalCouchDB"`
}

type FabricPeerExternalCouchDB struct {
	Enabled bool   `json:"enabled"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
}
type FabricIstio struct {
	// +optional
	// +nullable
	Port int `json:"port"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Hosts []string `json:"hosts,omitempty"`
	// +kubebuilder:validation:Default=ingressgateway
	IngressGateway string `json:"ingressGateway"`
}
type FabricTraefikMiddleware struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`
}
type FabricTraefik struct {
	Entrypoints []string `json:"entryPoints"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Middlewares []FabricTraefikMiddleware `json:"middlewares,omitempty"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Hosts []string `json:"hosts,omitempty"`
}

type FabricGatewayApi struct {
	// +optional
	// +nullable
	Port int `json:"port"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Hosts []string `json:"hosts,omitempty"`
	// +kubebuilder:validation:Default=hlf-gateway
	GatewayName string `json:"gatewayName"`
	// +kubebuilder:validation:Default=default
	GatewayNamespace string `json:"gatewayNamespace"`
}

type FabricPeerSpecGossip struct {
	ExternalEndpoint  string `json:"externalEndpoint"`
	Bootstrap         string `json:"bootstrap"`
	Endpoint          string `json:"endpoint"`
	UseLeaderElection bool   `json:"useLeaderElection"`
	OrgLeader         bool   `json:"orgLeader"`
	// +kubebuilder:validation:Default=25s
	// +optional
	ReconnectInterval string `json:"reconnectInterval"`
	// +kubebuilder:validation:Default=25s
	// +optional
	AliveExpirationTimeout string `json:"aliveExpirationTimeout"`
	// +kubebuilder:validation:Default=5s
	// +optional
	AliveTimeInterval string `json:"aliveTimeInterval"`
	// +kubebuilder:validation:Default=2s
	// +optional
	ResponseWaitTime string `json:"responseWaitTime"`
}
type Catls struct {
	Cacert string `json:"cacert"`
	// +optional
	// +nullable
	// +kubebuilder:validation:Optional
	SecretRef *SecretRefNSKey `json:"secretRef"`
}
type Component struct {
	// +optional
	// +nullable
	Cahost string `json:"cahost"`
	// +optional
	// +nullable
	Caname string `json:"caname"`
	// +optional
	// +nullable
	Caport int `json:"caport"`
	// +optional
	// +nullable
	Catls *Catls `json:"catls"`
	// +optional
	// +nullable
	Enrollid string `json:"enrollid"`
	// +optional
	// +nullable
	Enrollsecret string `json:"enrollsecret"`

	// +optional
	// +nullable
	External *ExternalCertificate `json:"external"`

	// +optional
	// +nullable
	Vault *VaultComponent `json:"vault"`
}
type ExternalCertificate struct {
	SecretName         string `json:"secretName"`
	SecretNamespace    string `json:"secretNamespace"`
	RootCertificateKey string `json:"rootCertificateKey"`
	CertificateKey     string `json:"certificateKey"`
	PrivateKeyKey      string `json:"privateKeyKey"`
}

func (c *Component) CAUrl() string {
	return fmt.Sprintf("https://%s:%d", c.Cahost, c.Caport)
}

type Csr struct {
	// +optional
	Hosts []string `json:"hosts"`
	// +optional
	CN string `json:"cn"`
}
type TLSComponent struct {
	// +optional
	// +nullable
	Cahost string `json:"cahost"`
	// +optional
	// +nullable
	Caname string `json:"caname"`
	// +optional
	// +nullable
	Caport int `json:"caport"`
	// +optional
	// +nullable
	Catls *Catls `json:"catls"`
	// +optional
	// +nullable
	Csr Csr `json:"csr"`
	// +optional
	// +nullable
	Enrollid string `json:"enrollid"`
	// +optional
	// +nullable
	Enrollsecret string `json:"enrollsecret"`

	// +optional
	// +nullable
	Vault *VaultComponent `json:"vault"`

	// +optional
	// +nullable
	External *ExternalCertificate `json:"external"`
}

type Enrollment struct {
	Component Component    `json:"component"`
	TLS       TLSComponent `json:"tls"`
}

type OrdererEnrollment struct {
	// +optional
	// +nullable
	Component *Component `json:"component"`

	TLS TLSComponent `json:"tls"`
}
type Secret struct {
	Enrollment Enrollment `json:"enrollment"`
}
type OrdererNode struct {
	// +kubebuilder:validation:MinLength=1
	ID string `json:"id"`
	// +optional
	Host string `json:"host"`
	// +optional
	Port       int                   `json:"port"`
	Enrollment OrdererNodeEnrollment `json:"enrollment"`
}
type OrdererNodeEnrollment struct {
	TLS OrdererNodeEnrollmentTLS `json:"tls"`
}
type OrdererNodeEnrollmentTLS struct {
	// +optional
	Csr Csr `json:"csr"`
}

// +kubebuilder:validation:Enum=NodePort;ClusterIP;LoadBalancer
// +kubebuilder:default:NodePort
type ServiceType string

const ServiceTypeNodePort = "NodePort"
const ServiceTypeClusterIP = "ClusterIP"
const ServiceTypeLoadBalancer = "LoadBalancer"

type Service struct {
	Type ServiceType `json:"type"`
}

type PeerService struct {
	// +kubebuilder:validation:Enum=NodePort;ClusterIP;LoadBalancer
	// +kubebuilder:default:NodePort
	Type corev1.ServiceType `json:"type"`
}

// FabricPeerStatus defines the observed state of FabricPeer
type FabricPeerStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Message    string            `json:"message"`
	Status     DeploymentStatus  `json:"status"`

	// +optional
	// +nullable
	LastCertificateUpdate *metav1.Time `json:"lastCertificateUpdate"`

	// +optional
	SignCert string `json:"signCert"`
	// +optional
	TlsCert string `json:"tlsCert"`
	// +optional
	TlsCACert string `json:"tlsCaCert"`
	// +optional
	SignCACert string `json:"signCaCert"`
	// +optional
	NodePort int `json:"port"`
}
type OrdererService struct {
	// +kubebuilder:validation:Enum=NodePort;ClusterIP;LoadBalancer
	// +kubebuilder:default:NodePort
	Type ServiceType `json:"type"`
}

type OrdererNodeService struct {
	Type               corev1.ServiceType `json:"type"`
	NodePortOperations int                `json:"nodePortOperations,omitempty"`
	NodePortRequest    int                `json:"nodePortRequest,omitempty"`
}

// FabricOrderingServiceSpec defines the desired state of FabricOrderingService
type FabricOrderingServiceSpec struct {
	// +kubebuilder:validation:MinLength=1
	Image string `json:"image"`
	// +kubebuilder:validation:MinLength=1
	Tag string `json:"tag"`
	// +kubebuilder:validation:MinLength=3
	MspID         string               `json:"mspID"`
	Enrollment    OrdererEnrollment    `json:"enrollment"`
	Nodes         []OrdererNode        `json:"nodes"`
	Service       OrdererService       `json:"service"`
	Storage       Storage              `json:"storage"`
	SystemChannel OrdererSystemChannel `json:"systemChannel"`
}
type BootstrapMethod string

const (
	BootstrapMethodNone = "none"
	BootstrapMethodFile = "file"
)

// FabricOrdererNodeSpec defines the desired state of FabricOrdererNode
type FabricOrdererNodeSpec struct {
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:={}
	PodAnnotations map[string]string `json:"podAnnotations"`
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:={}
	PodLabels map[string]string `json:"podLabels"`

	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	// +kubebuilder:validation:Default={}
	Tolerations []corev1.Toleration `json:"tolerations"`
	// +optional
	// +nullable
	GRPCProxy *GRPCProxy `json:"grpcProxy"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Affinity *corev1.Affinity `json:"affinity"`
	// +optional
	// +nullable
	UpdateCertificateTime *metav1.Time `json:"updateCertificateTime"`
	// +optional
	// +nullable
	ServiceMonitor *ServiceMonitor `json:"serviceMonitor"`
	// +optional
	// +nullable
	HostAliases []corev1.HostAlias `json:"hostAliases"`

	// +kubebuilder:validation:Default={}
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	NodeSelector *corev1.NodeSelector `json:"nodeSelector,omitempty"`

	Resources corev1.ResourceRequirements `json:"resources"`

	// +kubebuilder:default:=1
	Replicas int `json:"replicas"`
	// +kubebuilder:validation:MinLength=1
	Image string `json:"image"`
	// +kubebuilder:validation:MinLength=1
	Tag string `json:"tag"`

	// +kubebuilder:default:="IfNotPresent"
	PullPolicy corev1.PullPolicy `json:"pullPolicy,omitempty"`

	// +kubebuilder:validation:MinLength=3
	MspID string `json:"mspID"`
	// +kubebuilder:validation:Default={}
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets"`

	Genesis                     string             `json:"genesis"`
	BootstrapMethod             BootstrapMethod    `json:"bootstrapMethod"`
	ChannelParticipationEnabled bool               `json:"channelParticipationEnabled"`
	Storage                     Storage            `json:"storage"`
	Service                     OrdererNodeService `json:"service"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	Secret *Secret `json:"secret"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	GatewayApi *FabricGatewayApi `json:"gatewayApi"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	Istio *FabricIstio `json:"istio"`

	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	Traefik *FabricTraefik `json:"traefik"`

	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	AdminGatewayApi *FabricGatewayApi `json:"adminGatewayApi"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	AdminIstio *FabricIstio `json:"adminIstio"`

	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	AdminTraefik *FabricTraefik `json:"adminTraefik"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Env []corev1.EnvVar `json:"env"`

	// +kubebuilder:default:="kubernetes"
	// +kubebuilder:validation:Enum=kubernetes;vault
	CredentialStore CredentialStore `json:"credentialStore"`
}

type FabricOrdererVaultSpec struct {
	Request VaultPKICertificateRequest `json:"request"`
	Vault   VaultSpecConf              `json:"vault"`
}

type OrdererSystemChannel struct {
	// +kubebuilder:validation:MinLength=3
	Name   string        `json:"name"`
	Config ChannelConfig `json:"config"`
}
type OrdererCapabilities struct {
	V2_0 bool `json:"V2_0"`
}
type ApplicationCapabilities struct {
	V2_0 bool `json:"V2_0"`
}
type ChannelCapabilities struct {
	V2_0 bool `json:"V2_0"`
}
type ChannelConfig struct {
	BatchTimeout            string                  `json:"batchTimeout"`
	MaxMessageCount         int                     `json:"maxMessageCount"`
	AbsoluteMaxBytes        int                     `json:"absoluteMaxBytes"`
	PreferredMaxBytes       int                     `json:"preferredMaxBytes"`
	OrdererCapabilities     OrdererCapabilities     `json:"ordererCapabilities"`
	ApplicationCapabilities ApplicationCapabilities `json:"applicationCapabilities"`
	ChannelCapabilities     ChannelCapabilities     `json:"channelCapabilities"`
	SnapshotIntervalSize    int                     `json:"snapshotIntervalSize"`
	TickInterval            string                  `json:"tickInterval"`
	ElectionTick            int                     `json:"electionTick"`
	HeartbeatTick           int                     `json:"heartbeatTick"`
	MaxInflightBlocks       int                     `json:"maxInflightBlocks"`
}

// FabricOrderingServiceStatus defines the observed state of FabricOrderingService
type FabricOrderingServiceStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Status     DeploymentStatus  `json:"status"`
}

// FabricOrdererNodeStatus defines the observed state of FabricOrdererNode
type FabricOrdererNodeStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Status     DeploymentStatus  `json:"status"`

	// +optional
	// +nullable
	LastCertificateUpdate *metav1.Time `json:"lastCertificateUpdate"`

	// +optional
	SignCert string `json:"signCert"`
	// +optional
	TlsCert string `json:"tlsCert"`
	// +optional
	SignCACert string `json:"signCaCert"`
	// +optional
	TlsCACert string `json:"tlsCaCert"`
	// +optional
	TlsAdminCert string `json:"tlsAdminCert"`
	// +optional
	OperationsPort int `json:"operationsPort"`
	// +optional
	AdminPort int `json:"adminPort"`
	// +optional
	NodePort int `json:"port"`
	// +optional
	Message string `json:"message"`
}

type Cors struct {
	// +kubebuilder:default:=false
	Enabled bool     `json:"enabled"`
	Origins []string `json:"origins"`
}
type FabricCADatabase struct {
	Type       string `json:"type"`
	Datasource string `json:"datasource"`
}

type CredentialStore string

const (
	CredentialStoreKubernetes = "kubernetes"
	CredentialStoreVault      = "vault"
)

// FabricCASpec defines the desired state of FabricCA
type FabricCASpec struct {
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:={}
	PodAnnotations map[string]string `json:"podAnnotations"`
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:={}
	PodLabels map[string]string `json:"podLabels"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Affinity *corev1.Affinity `json:"affinity"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	// +kubebuilder:validation:Default={}
	Tolerations []corev1.Toleration `json:"tolerations"`
	// +kubebuilder:validation:Default={}
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets"`

	// +kubebuilder:validation:Default={}
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	NodeSelector *corev1.NodeSelector `json:"nodeSelector,omitempty"`

	// +optional
	// +nullable
	ServiceMonitor *ServiceMonitor `json:"serviceMonitor"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	GatewayApi *FabricGatewayApi `json:"gatewayApi"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	Istio *FabricIstio `json:"istio"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	Traefik  *FabricTraefik   `json:"traefik"`
	Database FabricCADatabase `json:"db"`
	// +kubebuilder:validation:MinItems=1
	// Hosts for the Fabric CA
	Hosts   []string            `json:"hosts"`
	Service FabricCASpecService `json:"service"`
	// +kubebuilder:validation:MinLength=1
	Image string `json:"image"`
	// +kubebuilder:validation:MinLength=1
	Version string `json:"version"`
	// +kubebuilder:default:=false
	Debug bool `json:"debug"`
	// +kubebuilder:default:=512000
	CLRSizeLimit int              `json:"clrSizeLimit"`
	TLS          FabricCATLSConf  `json:"rootCA"`
	CA           FabricCAItemConf `json:"ca"`
	TLSCA        FabricCAItemConf `json:"tlsCA"`
	Cors         Cors             `json:"cors"`

	Resources corev1.ResourceRequirements `json:"resources"`
	Storage   Storage                     `json:"storage"`
	Metrics   FabricCAMetrics             `json:"metrics"`

	// +kubebuilder:default:="kubernetes"
	// +kubebuilder:validation:Enum=kubernetes;vault
	CredentialStore CredentialStore `json:"credentialStore"`

	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	Vault *FabricCAVaultSpec `json:"vault"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Env []corev1.EnvVar `json:"env"`
}

type FabricCAVaultSpec struct {
	Request VaultPKICertificateRequest `json:"request"`
	Vault   VaultSpecConf              `json:"vault"`
}

type VaultBackend string

const (
	VaultBackendKV  VaultBackend = "kv"
	VaultBackendPKI VaultBackend = "pki"
)

// VaultPKICertificateRequest defines the configuration for requesting certificates from Vault's PKI backend
type VaultPKICertificateRequest struct {

	// PKI is the PKI backend to use for certificate generation
	// +kubebuilder:validation:Required
	PKI string `json:"pki"`

	// Role is the PKI role to use for certificate generation
	// +kubebuilder:validation:Required
	Role string `json:"role"`

	// TTL is the requested time-to-live of the certificate
	// +optional
	// +kubebuilder:default:="8760h"
	TTL string `json:"ttl,omitempty"`

	// UserIDs are optional user identifiers that can be included in the certificate
	// +optional
	// +nullable
	// +kubebuilder:default:={}
	UserIDs []string `json:"userIDs,omitempty"`
}

type VaultSpecConf struct {
	// URL of the Vault server
	URL string `json:"url"`
	// Token for direct authentication to Vault
	// +optional
	// +nullable
	TokenSecretRef *VaultSecretRef `json:"tokenSecretRef,omitempty"`
	// Role for Kubernetes auth method
	// +optional
	// +nullable
	Role string `json:"role"`

	// Path in Vault where secrets are stored
	// +optional
	// +nullable
	Path string `json:"path,omitempty"`

	// Backend type in Vault (e.g., "kv", "pki")
	// +kubebuilder:default:="kv"
	// +optional
	Backend VaultBackend `json:"backend,omitempty"`

	// Version of KV backend (1 or 2)
	// +kubebuilder:default:=2
	// +optional
	KVVersion int `json:"kvVersion,omitempty"`

	// Path to the secret in Vault
	// +optional
	// +nullable
	SecretIdSecretRef *VaultSecretRef `json:"secretIdSecretRef,omitempty"`
	// Kubernetes service account token path for auth
	// +optional
	// +nullable
	ServiceAccountTokenPath string `json:"serviceAccountTokenPath"`
	// Kubernetes auth mount path
	// +kubebuilder:default:="kubernetes"
	// +optional
	// +nullable
	AuthPath string `json:"authPath"`
	// Server Certificate for TLS authentication
	// +optional
	// +nullable
	ServerCert string `json:"serverCert"`
	// Server Name for TLS authentication
	// +optional
	ServerName string `json:"serverName"`

	// Client certificate for TLS authentication
	// +optional
	ClientCert string `json:"clientCert"`
	// Client key for TLS authentication
	// +optional
	ClientKeySecretRef *VaultSecretRef `json:"clientKey"`
	// CA certificate for TLS verification
	// +optional
	CACert string `json:"caCert"`
	// Skip TLS verification
	// +kubebuilder:default:=false
	TLSSkipVerify bool `json:"tlsSkipVerify"`
	// Timeout for Vault operations
	// +kubebuilder:default:="30s"
	Timeout string `json:"timeout"`
	// Maximum number of retries for Vault operations
	// +kubebuilder:default:=2
	MaxRetries int `json:"maxRetries"`
}

type FabricCATLSConf struct {
	Subject FabricCASubject `json:"subject"`
}
type FabricCACFG struct {
	Identities   FabricCACFGIdentities  `json:"identities"`
	Affiliations FabricCACFGAffilitions `json:"affiliations"`
}
type FabricCACFGIdentities struct {
	// +kubebuilder:default:=true
	AllowRemove bool `json:"allowRemove"`
}
type FabricCACFGAffilitions struct {
	// +kubebuilder:default:=true
	AllowRemove bool `json:"allowRemove"`
}
type FabricCAMetrics struct {
	// +kubebuilder:default:="disabled"
	Provider string `json:"provider"`
	// +optional
	Statsd *FabricCAMetricsStatsd `json:"statsd"`
}
type FabricCAMetricsStatsd struct {
	// +kubebuilder:validation:Enum=udp;tcp
	// +kubebuilder:default:="udp"
	Network string `json:"network"`
	// +optional
	Address string `json:"address"`
	// +optional
	// +kubebuilder:default:="10s"
	WriteInterval string `json:"writeInterval"`
	// +optional
	// +kubebuilder:default:=""
	Prefix string `json:"prefix"`
}

// +kubebuilder:validation:Enum=statsd;prometheus;disabled
type MetricsProvider string

type Storage struct {
	// +kubebuilder:default:="5Gi"
	Size string `json:"size"`
	// +kubebuilder:default:=""
	// +optional
	StorageClass string `json:"storageClass"`
	// +kubebuilder:default:="ReadWriteOnce"
	AccessMode corev1.PersistentVolumeAccessMode `json:"accessMode"`
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

type FabricCAAffiliation struct {
	Name        string   `json:"name"`
	Departments []string `json:"departments"`
}

type FabricCAItemConf struct {
	Name    string          `json:"name"`
	CFG     FabricCACFG     `json:"cfg"`
	Subject FabricCASubject `json:"subject"`
	CSR     FabricCACSR     `json:"csr"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	Signing      *FabricCASigning     `json:"signing"`
	CRL          FabricCACRL          `json:"crl"`
	Registry     FabricCARegistry     `json:"registry"`
	Intermediate FabricCAIntermediate `json:"intermediate"`
	BCCSP        FabricCABCCSP        `json:"bccsp"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Affiliations []FabricCAAffiliation `json:"affiliations"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	CA *FabricCACrypto `json:"ca"`
}
type FabricTLSCACrypto struct {
	Key        string             `json:"key"`
	Cert       string             `json:"cert"`
	ClientAuth FabricCAClientAuth `json:"clientAuth"`
}
type FabricCAClientAuth struct {
	// NoClientCert, RequestClientCert, RequireAnyClientCert, VerifyClientCertIfGiven and RequireAndVerifyClientCert.
	Type     string   `json:"type"`
	CertFile []string `json:"cert_file"`
}
type SecretRef struct {
	// +optional
	// +nullable
	// +kubebuilder:validation:Optional
	Name string `json:"name"`
}

type VaultSecretRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Key       string `json:"key"`
}
type SecretRefNSKey struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Key       string `json:"key"`
}
type FabricCACrypto struct {
	Key string `json:"key"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	SecretRef *SecretRef `json:"secret"`
	Cert      string     `json:"cert"`
	Chain     string     `json:"chain"`
}
type FabricCASubject struct {
	// +kubebuilder:default:="ca"
	CN string `json:"cn"`
	// +kubebuilder:default:="US"
	C string `json:"C"`
	// +kubebuilder:default:="North Carolina"
	ST string `json:"ST"`
	// +kubebuilder:default:="Hyperledger"
	O string `json:"O"`
	// +kubebuilder:default:="Raleigh"
	L string `json:"L"`
	// +kubebuilder:default:="Fabric"
	OU string `json:"OU"`
}
type FabricCABCCSP struct {
	// +kubebuilder:default:="SW"
	Default string          `json:"default"`
	SW      FabricCABCCSPSW `json:"sw"`
}
type FabricCABCCSPSW struct {
	// +kubebuilder:default:="SHA2"
	Hash string `json:"hash"`
	// +kubebuilder:default:="256"
	Security string `json:"security"`
}

type FabricCAIntermediate struct {
	ParentServer FabricCAIntermediateParentServer `json:"parentServer"`
}
type FabricCAIntermediateParentServer struct {
	URL string `json:"url"`
	// FabricCA Name of the organization
	CAName string `json:"caName"`
}
type FabricCAIntermediateEnrollment struct {
	Hosts   string `json:"hosts"`
	Profile string `json:"profile"`
	Label   string `json:"label"`
}
type FabricCAIntermediateTLS struct {
	CertFiles []string                      `json:"certFiles"`
	Client    FabricCAIntermediateTLSClient `json:"client"`
}
type FabricCAIntermediateTLSClient struct {
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}
type FabricCARegistry struct {
	MaxEnrollments int                `json:"max_enrollments"`
	Identities     []FabricCAIdentity `json:"identities"`
}
type FabricCAIdentity struct {
	Name string `json:"name"`
	Pass string `json:"pass"`
	Type string `json:"type"`
	// +kubebuilder:default:=""
	Affiliation string                `json:"affiliation"`
	Attrs       FabricCAIdentityAttrs `json:"attrs"`
}
type FabricCAIdentityAttrs struct {
	// +kubebuilder:default:="*"
	RegistrarRoles string `json:"hf.Registrar.Roles"`
	// +kubebuilder:default:="*"
	DelegateRoles string `json:"hf.Registrar.DelegateRoles"`
	// +kubebuilder:default:="*"
	Attributes string `json:"hf.Registrar.Attributes"`
	// +kubebuilder:default:=true
	Revoker bool `json:"hf.Revoker"`
	// +kubebuilder:default:=true
	IntermediateCA bool `json:"hf.IntermediateCA"`
	// +kubebuilder:default:=true
	GenCRL bool `json:"hf.GenCRL"`
	// +kubebuilder:default:=true
	AffiliationMgr bool `json:"hf.AffiliationMgr"`
}
type FabricCACRL struct {
	// +kubebuilder:default:="24h"
	Expiry string `json:"expiry"`
}
type FabricCACSR struct {
	// +kubebuilder:default:="ca"
	CN string `json:"cn"`
	// +kubebuilder:default:={"localhost"}
	Hosts []string        `json:"hosts"`
	Names []FabricCANames `json:"names"`
	CA    FabricCACSRCA   `json:"ca"`
}
type FabricCACSRCA struct {
	// +kubebuilder:default:="131400h"
	Expiry string `json:"expiry"`
	// +kubebuilder:default:=0
	PathLength int `json:"pathLength"`
}
type FabricCANames struct {
	// +kubebuilder:default:="US"
	C string `json:"C"`
	// +kubebuilder:default:="North Carolina"
	ST string `json:"ST"`
	// +kubebuilder:default:="Hyperledger"
	O string `json:"O"`
	// +kubebuilder:default:="Raleigh"
	L string `json:"L"`
	// +kubebuilder:default:="Fabric"
	OU string `json:"OU"`
}
type FabricCASpecService struct {
	ServiceType corev1.ServiceType `json:"type"`
}
type DeploymentStatus string

const (
	PendingStatus        DeploymentStatus = "PENDING"
	FailedStatus         DeploymentStatus = "FAILED"
	RunningStatus        DeploymentStatus = "RUNNING"
	UnknownStatus        DeploymentStatus = "UNKNOWN"
	UpdatingVersion      DeploymentStatus = "UPDATING_VERSION"
	UpdatingCertificates DeploymentStatus = "UPDATING_CERTIFICATES"
)

// FabricCAStatus defines the observed state of FabricCA
type FabricCAStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Message    string            `json:"message"`
	// Status of the FabricCA
	Status DeploymentStatus `json:"status"`

	// +optional
	NodePort int `json:"nodePort"`
	// TLS Certificate to connect to the FabricCA
	TlsCert string `json:"tls_cert"`
	// Root certificate for Sign certificates generated by FabricCA
	CACert string `json:"ca_cert"`
	// Root certificate for TLS certificates generated by FabricCA
	TLSCACert string `json:"tlsca_cert"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=peer,singular=peer
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// FabricPeer is the Schema for the hlfs API
type FabricPeer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FabricPeerSpec   `json:"spec,omitempty"`
	Status FabricPeerStatus `json:"status,omitempty"`
}

func (in *FabricPeer) FullName() string {
	return fmt.Sprintf("%s.%s", in.Name, in.Namespace)
}

// +kubebuilder:object:root=true

// FabricPeerList contains a list of FabricPeer
type FabricPeerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricPeer `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=orderingservice,singular=orderingservice
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// FabricOrderingService is the Schema for the hlfs API
type FabricOrderingService struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FabricOrderingServiceSpec   `json:"spec,omitempty"`
	Status FabricOrderingServiceStatus `json:"status,omitempty"`
}

func (s *FabricOrderingService) FullName() string {
	return fmt.Sprintf("%s.%s", s.Name, s.Namespace)
}

// +kubebuilder:object:root=true

// FabricOrderingServiceList contains a list of FabricOrderingService
type FabricOrderingServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricOrderingService `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=orderernode,singular=orderernode
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// FabricOrdererNode is the Schema for the hlfs API
type FabricOrdererNode struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FabricOrdererNodeSpec   `json:"spec,omitempty"`
	Status FabricOrdererNodeStatus `json:"status,omitempty"`
}

func (n *FabricOrdererNode) FullName() string {
	return fmt.Sprintf("%s.%s", n.Name, n.Namespace)
}

// +kubebuilder:object:root=true

// FabricOrdererNodeList contains a list of FabricOrdererNode
type FabricOrdererNodeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricOrdererNode `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=ca,singular=ca
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +k8s:openapi-gen=true

// FabricCA is the Schema for the hlfs API
type FabricCA struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              FabricCASpec   `json:"spec,omitempty"`
	Status            FabricCAStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FabricCAList contains a list of FabricCA
type FabricCAList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricCA `json:"items"`
}

// FabricExplorerSpec defines the desired state of FabricExplorer
type FabricExplorerSpec struct {
	Resources corev1.ResourceRequirements `json:"resources"`
}

// FabricExplorerStatus defines the observed state of FabricExplorer
type FabricExplorerStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Message    string            `json:"message"`
	// Status of the FabricCA
	Status DeploymentStatus `json:"status"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=explorer,singular=explorer
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +k8s:openapi-gen=true

// FabricExplorer is the Schema for the hlfs API
type FabricExplorer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              FabricExplorerSpec   `json:"spec,omitempty"`
	Status            FabricExplorerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FabricExplorerList contains a list of FabricExplorer
type FabricExplorerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricExplorer `json:"items"`
}

// FabricOperationsConsoleSpec defines the desired state of FabricOperationsConsole
type FabricOperationsConsoleCouchDB struct {
	// +kubebuilder:default:="couchdb"
	Image string `json:"image"`
	// +kubebuilder:default:="3.1.1"
	Tag string `json:"tag"`

	Username string  `json:"username"`
	Password string  `json:"password"`
	Storage  Storage `json:"storage"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources"`

	// +kubebuilder:validation:Default={}
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Affinity *corev1.Affinity `json:"affinity"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Tolerations []corev1.Toleration `json:"tolerations"`
	// +kubebuilder:default:="IfNotPresent"
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy"`
}
type FabricOperationsConsoleAuth struct {
	// +kubebuilder:default:="couchdb"
	Scheme   string `json:"scheme"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// FabricOperationsConsoleSpec defines the desired state of FabricOperationsConsole
type FabricOperationsConsoleSpec struct {
	Auth FabricOperationsConsoleAuth `json:"auth"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Resources corev1.ResourceRequirements `json:"resources"`
	// +kubebuilder:default:="ghcr.io/hyperledger-labs/fabric-console"
	Image string `json:"image"`
	// +kubebuilder:default:="latest"
	Tag string `json:"tag"`

	// +kubebuilder:default:="IfNotPresent"
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Tolerations []corev1.Toleration `json:"tolerations"`

	// +kubebuilder:validation:Default=1
	Replicas int `json:"replicas"`

	CouchDB FabricOperationsConsoleCouchDB `json:"couchDB"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Env []corev1.EnvVar `json:"env"`

	// +kubebuilder:validation:Default={}
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Affinity *corev1.Affinity `json:"affinity"`

	// +kubebuilder:default:=3000
	Port int `json:"port"`

	// +optional
	// +nullable
	Config string `json:"config"`

	Ingress Ingress `json:"ingress"`
	HostURL string  `json:"hostUrl"`
}

type Ingress struct {
	// +kubebuilder:default:=true
	Enabled bool `json:"enabled"`

	ClassName string `json:"className"`
	// +kubebuilder:default:={}
	Annotations map[string]string    `json:"annotations"`
	TLS         []v1beta1.IngressTLS `json:"tls"`
	Hosts       []IngressHost        `json:"hosts"`
}

type IngressHost struct {
	Host  string        `json:"host"`
	Paths []IngressPath `json:"paths"`
}
type IngressPath struct {
	// +kubebuilder:default:="/"
	Path string `json:"path"`
	// +kubebuilder:default:="Prefix"
	PathType string `json:"pathType"`
}

// FabricOperationsConsoleStatus defines the observed state of FabricOperationsConsole
type FabricOperationsConsoleStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Message    string            `json:"message"`
	// Status of the FabricCA
	Status DeploymentStatus `json:"status"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=fabricoperationsconsoles,singular=fabricoperationsconsoles
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +k8s:openapi-gen=true

// FabricOperationsConsole is the Schema for the hlfs API
type FabricOperationsConsole struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              FabricOperationsConsoleSpec   `json:"spec,omitempty"`
	Status            FabricOperationsConsoleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FabricOperationsConsoleList contains a list of FabricOperationsConsole
type FabricOperationsConsoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricOperationsConsole `json:"items"`
}

// FabricOperatorUIStatus defines the observed state of FabricOperatorUI
type FabricOperatorUIStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Message    string            `json:"message"`
	// Status of the FabricCA
	Status DeploymentStatus `json:"status"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=fabricoperatorui,singular=fabricoperatorui
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +k8s:openapi-gen=true

// FabricOperatorUI is the Schema for the hlfs API
type FabricOperatorUI struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              FabricOperatorUISpec   `json:"spec,omitempty"`
	Status            FabricOperatorUIStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FabricOperatorUIList contains a list of FabricOperatorUI
type FabricOperatorUIList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricOperatorUI `json:"items"`
}
type FabricOperatorUIAuth struct {
	OIDCAuthority string `json:"oidcAuthority"`
	OIDCClientId  string `json:"oidcClientId"`
	OIDCScope     string `json:"oidcScope"`
}

// FabricOperatorUISpec defines the desired state of FabricOperatorUI
type FabricOperatorUISpec struct {
	Image string `json:"image"`
	Tag   string `json:"tag"`
	// +kubebuilder:default:="IfNotPresent"
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy"`

	// +kubebuilder:default:=""
	LogoURL string `json:"logoUrl"`

	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	// +kubebuilder:validation:Default={}
	Auth *FabricOperatorUIAuth `json:"auth"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	// +kubebuilder:validation:Default={}
	Tolerations []corev1.Toleration `json:"tolerations"`
	// +kubebuilder:validation:Default=1
	Replicas int     `json:"replicas"`
	Ingress  Ingress `json:"ingress"`

	APIURL string `json:"apiUrl"`
	// +kubebuilder:validation:Default={}
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Env []corev1.EnvVar `json:"env"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Affinity *corev1.Affinity `json:"affinity"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources"`
}

// FabricOperatorAPIStatus defines the observed state of FabricOperatorAPI
type FabricOperatorAPIStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Message    string            `json:"message"`
	// Status of the FabricCA
	Status DeploymentStatus `json:"status"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=fabricoperatorapi,singular=fabricoperatorapi
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +k8s:openapi-gen=true

// FabricOperatorAPI is the Schema for the hlfs API
type FabricOperatorAPI struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              FabricOperatorAPISpec   `json:"spec,omitempty"`
	Status            FabricOperatorAPIStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FabricOperatorAPIList contains a list of FabricOperatorAPI
type FabricOperatorAPIList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricOperatorAPI `json:"items"`
}
type FabricOperatorAPIHLFConfig struct {
	MSPID         string                         `json:"mspID"`
	User          string                         `json:"user"`
	NetworkConfig FabricOperatorAPINetworkConfig `json:"networkConfig"`
}
type FabricOperatorAPINetworkConfig struct {
	SecretName string `json:"secretName"`
	Key        string `json:"key"`
}
type FabricOperatorAPIAuth struct {
	OIDCJWKS   string `json:"oidcJWKS"`
	OIDCIssuer string `json:"oidcIssuer"`

	// +kubebuilder:default:=""
	OIDCAuthority string `json:"oidcAuthority"`
	// +kubebuilder:default:=""
	OIDCClientId string `json:"oidcClientId"`
	// +kubebuilder:default:=""
	OIDCScope string `json:"oidcScope"`
}

// FabricOperatorAPISpec defines the desired state of FabricOperatorAPI
type FabricOperatorAPISpec struct {
	Image string `json:"image"`
	Tag   string `json:"tag"`
	// +kubebuilder:default:="IfNotPresent"
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy"`
	Istio           FabricIstio       `json:"istio"`
	Ingress         Ingress           `json:"ingress"`
	// +kubebuilder:validation:Default=1
	Replicas int `json:"replicas"`

	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Default={}
	PodLabels map[string]string `json:"podLabels"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	// +kubebuilder:validation:Default={}
	Auth *FabricOperatorAPIAuth `json:"auth"`

	// +kubebuilder:default:=""
	LogoURL string `json:"logoUrl"`

	HLFConfig FabricOperatorAPIHLFConfig `json:"hlfConfig"`

	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	// +kubebuilder:validation:Default={}
	Tolerations []corev1.Toleration `json:"tolerations"`

	// +kubebuilder:validation:Default={}
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Env []corev1.EnvVar `json:"env"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Affinity *corev1.Affinity `json:"affinity"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources"`
}

type FabricNetworkConfigOrgPeer struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}
type FabricNetworkConfigOrganization struct {
	Peers []FabricNetworkConfigOrgPeer `json:"peers"`
}

type FabricNetworkConfigCA struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// FabricNetworkConfigSpec defines the desired state of FabricNetworkConfig
type FabricNetworkConfigSpec struct {
	Organization string `json:"organization"`

	Internal bool `json:"internal"`

	Organizations []string `json:"organizations"`
	// +kubebuilder:validation:Default={}
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	OrganizationConfig map[string]FabricNetworkConfigOrganization `json:"organizationConfig"`
	Namespaces         []string                                   `json:"namespaces"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	CertificateAuthorities []FabricNetworkConfigCA `json:"certificateAuthorities"`

	Channels []string `json:"channels"`
	// HLF Identities to be included in the network config
	Identities []FabricNetworkConfigIdentity `json:"identities"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	ExternalOrderers []FabricNetworkConfigExternalOrderer `json:"externalOrderers"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	ExternalPeers []FabricNetworkConfigExternalPeer `json:"externalPeers"`

	SecretName string `json:"secretName"`
}
type FabricNetworkConfigExternalPeer struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	TLSCACert string `json:"tlsCACert"`
	MSPID     string `json:"mspID"`
}
type FabricNetworkConfigExternalOrderer struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	TLSCACert string `json:"tlsCACert"`
	MSPID     string `json:"mspID"`
}
type FabricNetworkConfigIdentity struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// FabricNetworkConfigStatus defines the observed state of FabricNetworkConfig
type FabricNetworkConfigStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Message    string            `json:"message"`
	// Status of the FabricNetworkConfig
	Status DeploymentStatus `json:"status"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=networkconfig,singular=networkconfig
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +k8s:openapi-gen=true

// FabricNetworkConfig is the Schema for the hlfs API
type FabricNetworkConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              FabricNetworkConfigSpec   `json:"spec,omitempty"`
	Status            FabricNetworkConfigStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FabricNetworkConfigList contains a list of FabricNetworkConfig
type FabricNetworkConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricNetworkConfig `json:"items"`
}

type FabricChaincodeTemplateRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// FabricChaincodeSpec defines the desired state of FabricChaincode
type FabricChaincodeSpec struct {
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	Template *FabricChaincodeTemplateRef `json:"template"`

	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:={}
	Annotations map[string]string `json:"annotations"`
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:={}
	Labels map[string]string `json:"labels"`

	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:={}
	PodAnnotations map[string]string `json:"podAnnotations"`

	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:={}
	PodLabels map[string]string `json:"podLabels"`

	Image string `json:"image"`
	// +kubebuilder:default:="IfNotPresent"
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy"`
	// +kubebuilder:validation:MinLength=1
	PackageID string `json:"packageId"`
	// +kubebuilder:validation:Default={}
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets"`

	// Entrypoint array. Not executed within a shell.
	// The container image's ENTRYPOINT is used if this is not provided.
	// +optional
	Command []string `json:"command,omitempty" protobuf:"bytes,3,rep,name=command"`

	// Arguments to the entrypoint.
	// The container image's CMD is used if this is not provided.
	// +optional
	Args []string `json:"args,omitempty" protobuf:"bytes,4,rep,name=args"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Affinity *corev1.Affinity `json:"affinity"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Tolerations []corev1.Toleration `json:"tolerations"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	PodSecurityContext *corev1.PodSecurityContext `json:"podSecurityContext"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	SecurityContext *corev1.SecurityContext `json:"securityContext"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default=""
	ServiceAccountName string `json:"serviceAccountName"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default=false
	EnableServiceLinks bool `json:"enableServiceLinks"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	NodeSelector map[string]string `json:"nodeSelector"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Credentials *TLSComponent `json:"credentials"`

	// +kubebuilder:validation:Default=1
	Replicas int `json:"replicas"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Env []corev1.EnvVar `json:"env"`

	// +kubebuilder:default=7052
	ChaincodeServerPort int `json:"chaincodeServerPort"`

	// +optional
	// +kubebuilder:validation:Optional
	MspID string `json:"mspID"`
}

func (in *FabricChaincodeSpec) ApplyDefaultValuesFromTemplate(template *FabricChaincodeTemplate) {
	if in.ImagePullPolicy == "" {
		in.ImagePullPolicy = template.Spec.ImagePullPolicy
	}
	if in.ImagePullSecrets == nil || len(in.ImagePullSecrets) == 0 {
		in.ImagePullSecrets = template.Spec.ImagePullSecrets
	}
	if in.Command == nil || len(in.Command) == 0 {
		in.Command = template.Spec.Command
	}
	if in.Args == nil || len(in.Args) == 0 {
		in.Args = template.Spec.Args
	}
	if in.Affinity == nil {
		in.Affinity = template.Spec.Affinity
	}
	if in.Tolerations == nil || len(in.Tolerations) == 0 {
		in.Tolerations = template.Spec.Tolerations
	}
	if in.Resources == nil {
		in.Resources = template.Spec.Resources
	}
	if in.Replicas == 0 {
		in.Replicas = template.Spec.Replicas
	}
	if in.Env == nil || len(in.Env) == 0 {
		in.Env = template.Spec.Env
	} else {
		for _, env := range template.Spec.Env {
			found := false
			for _, e := range in.Env {
				if e.Name == env.Name {
					found = true
					break
				}
			}
			if !found {
				in.Env = append(in.Env, env)
			}

		}
	}
	if in.ChaincodeServerPort == 0 {
		in.ChaincodeServerPort = template.Spec.ChaincodeServerPort
	}
	if in.MspID == "" {
		in.MspID = template.Spec.MspID
	}
}

// FabricChaincodeStatus defines the observed state of FabricChaincode
type FabricChaincodeStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Message    string            `json:"message"`
	// Status of the FabricChaincode
	Status DeploymentStatus `json:"status"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=fabricchaincode,singular=fabricchaincode
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +k8s:openapi-gen=true

// FabricChaincode is the Schema for the hlfs API
type FabricChaincode struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              FabricChaincodeSpec   `json:"spec,omitempty"`
	Status            FabricChaincodeStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FabricChaincodeList contains a list of FabricChaincode
type FabricChaincodeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricChaincode `json:"items"`
}

// FabricChaincodeInstallSpec defines the desired state of FabricChaincodeInstall
type FabricChaincodeInstallSpec struct {
	Peers            []FabricPeerInternalRef `json:"peers"`
	ExternalPeers    []FabricPeerExternalRef `json:"externalPeers"`
	MSPID            string                  `json:"mspID"`
	HLFIdentity      HLFIdentity             `json:"hlfIdentity"`
	ChaincodePackage ChaincodePackage        `json:"chaincodePackage"`
}

type ChaincodePackageTLS struct {
	// +kubebuilder:validation:Default=false
	Required bool `json:"required"`
}

type ChaincodePackage struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Type    string `json:"type"`

	// +optional
	// +nullable
	// +kubebuilder:validation:Default=10s
	DialTimeout string `json:"dialTimeout"`
	// +optional
	// +nullable
	TLS *ChaincodePackageTLS `json:"tls"`
}

type FabricPeerInternalRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}
type FabricPeerExternalRef struct {
	URL       string `json:"url"`
	TLSCACert string `json:"tlsCACert"`
}

// FabricChaincodeInstallStatus defines the observed state of FabricChaincodeInstall
type FabricChaincodeInstallStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Message    string            `json:"message"`
	// +optional
	// +nullable
	PackageID string `json:"packageID"`
	// +optional
	// +nullable
	FailedPeers []FailedPeer `json:"failedPeers"`
	// +optional
	// +nullable
	InstalledPeers []InstalledPeer `json:"installedPeers"`
	// Status of the FabricChaincodeInstall
	Status DeploymentStatus `json:"status"`
}
type FailedPeer struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}
type InstalledPeer struct {
	Name string `json:"name"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=fabricchaincodeinstall,singular=fabricchaincodeinstall
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +k8s:openapi-gen=true

// FabricChaincodeInstall is the Schema for the hlfs API
type FabricChaincodeInstall struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              FabricChaincodeInstallSpec   `json:"spec,omitempty"`
	Status            FabricChaincodeInstallStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FabricChaincodeInstallList contains a list of FabricChaincodeInstall
type FabricChaincodeInstallList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricChaincodeInstall `json:"items"`
}

// FabricChaincodeApproveSpec defines the desired state of FabricChaincodeApprove
type FabricChaincodeApproveSpec struct {
	// ChaincodeName is the name of the chaincode
	ChaincodeName string `json:"chaincodeName"`

	// ChannelName is the name of the channel
	ChannelName string `json:"channelName"`

	// +kubebuilder:validation:Default=false
	// +optional
	// +nullable
	InitRequired bool `json:"initRequired"`

	// MSPID is the MSP ID of the organization approving the chaincode
	MSPID string `json:"mspID"`

	// PackageID is the ID of the chaincode package
	PackageID string `json:"packageId"`

	// Version is the version of the chaincode
	Version string `json:"version"`

	// Sequence is the sequence number of the chaincode definition
	Sequence int64 `json:"sequence"`

	// EndorsementPolicy specifies the endorsement policy
	EndorsementPolicy string `json:"endorsementPolicy"`

	// PrivateDataCollections is a list of private data collection configurations
	// +optional
	PrivateDataCollections []PrivateDataCollection `json:"pdc,omitempty"`

	// HLFIdentity specifies the identity to use for the operation
	HLFIdentity HLFIdentity `json:"hlfIdentity"`

	// Peers is a list of peers to approve the chaincode
	Peers         []FabricPeerInternalRef `json:"peers"`
	ExternalPeers []FabricPeerExternalRef `json:"externalPeers"`

	// Orderers is a list of orderers to use for the transaction
	Orderers         []FabricOrdererInternalRef `json:"orderers"`
	ExternalOrderers []FabricOrdererExternalRef `json:"externalOrderers"`
}

type FabricOrdererInternalRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type FabricOrdererExternalRef struct {
	URL       string `json:"url"`
	TLSCACert string `json:"tlsCACert"`
}

type PrivateDataCollectionEndorsementPolicy struct {
	// +optional
	// +nullable
	ChannelConfigPolicy string `json:"channelConfigPolicy,omitempty"`
	SignaturePolicy     string `json:"signaturePolicy,omitempty"`
}

type PrivateDataCollection struct {
	// Define the structure for private data collections here
	// This is a placeholder and should be expanded based on your specific requirements
	Name   string `json:"name"`
	Policy string `json:"policy"`
	// +optional
	// +nullable
	// add default
	// +kubebuilder:validation:Default=1
	RequiredPeerCount *int32 `json:"requiredPeerCount"`
	// +kubebuilder:validation:Default=1
	MaxPeerCount *int32 `json:"maxPeerCount"`
	// +nullable
	// +optional
	BlockToLive       uint64                                  `json:"blockToLive"`
	MemberOnlyRead    bool                                    `json:"memberOnlyRead"`
	MemberOnlyWrite   bool                                    `json:"memberOnlyWrite"`
	EndorsementPolicy *PrivateDataCollectionEndorsementPolicy `json:"endorsementPolicy,omitempty"`
}

type PeerReference struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type OrdererReference struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// FabricChaincodeApproveStatus defines the observed state of FabricChaincodeApprove
type FabricChaincodeApproveStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Message    string            `json:"message"`
	// Status of the FabricChaincodeApprove
	Status DeploymentStatus `json:"status"`

	// +optional
	// +nullable
	TransactionID string `json:"transactionID"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=fabricchaincodeapprove,singular=fabricchaincodeapprove
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +k8s:openapi-gen=true

// FabricChaincodeApprove is the Schema for the hlfs API
type FabricChaincodeApprove struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              FabricChaincodeApproveSpec   `json:"spec,omitempty"`
	Status            FabricChaincodeApproveStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FabricChaincodeApproveList contains a list of FabricChaincodeApprove
type FabricChaincodeApproveList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricChaincodeApprove `json:"items"`
}

// FabricChaincodeCommitSpec defines the desired state of FabricChaincodeCommit
type FabricChaincodeCommitSpec struct {
	// ChaincodeName is the name of the chaincode
	ChaincodeName string `json:"chaincodeName"`
	// Channel is the name of the channel
	ChannelName string `json:"channelName"`
	// Version is the version of the chaincode to approve
	Version string `json:"version"`
	// Sequence is the sequence number of the chaincode definition
	Sequence int64 `json:"sequence"`
	// EndorsementPolicy is the endorsement policy of the chaincode
	// +optional
	EndorsementPolicy string `json:"endorsementPolicy,omitempty"`
	// CollectionConfig is the private data collection configuration of the chaincode
	// +optional
	PrivateDataCollections []PrivateDataCollection `json:"pdc,omitempty"`
	// InitRequired is a flag to indicate if the chaincode requires initialization
	// +optional
	InitRequired bool `json:"initRequired,omitempty"`
	// HLFIdentity is the identity to use for the approve transaction
	HLFIdentity HLFIdentity `json:"hlfIdentity"`
	// MSPID is the MSP ID of the organization approving the chaincode
	MSPID string `json:"mspID"`
	// Peers is the list of peers to approve the chaincode
	Peers []FabricPeerInternalRef `json:"peers"`
	// ExternalPeers is the list of external peers to approve the chaincode
	// +optional
	ExternalPeers []FabricPeerExternalRef `json:"externalPeers,omitempty"`
	// Orderers is the list of orderers to use for the approve transaction
	Orderers []FabricOrdererInternalRef `json:"orderers"`
	// ExternalOrderers is the list of external orderers to use for the approve transaction
	// +optional
	ExternalOrderers []FabricOrdererExternalRef `json:"externalOrderers,omitempty"`
}

// FabricChaincodeCommitStatus defines the observed state of FabricChaincodeCommit
type FabricChaincodeCommitStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Message    string            `json:"message"`
	// Status of the FabricChaincodeCommit
	Status DeploymentStatus `json:"status"`
	// +optional
	// +nullable
	TransactionID string `json:"transactionID"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=fabricchaincodecommit,singular=fabricchaincodecommit
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +k8s:openapi-gen=true

// FabricChaincodeCommit is the Schema for the hlfs API
type FabricChaincodeCommit struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              FabricChaincodeCommitSpec   `json:"spec,omitempty"`
	Status            FabricChaincodeCommitStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FabricChaincodeCommitList contains a list of FabricChaincodeCommit
type FabricChaincodeCommitList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricChaincodeCommit `json:"items"`
}

// FabricMainChannelStatus defines the observed state of FabricMainChannel
type FabricIdentityStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Message    string            `json:"message"`
	// Status of the FabricCA
	Status DeploymentStatus `json:"status"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=fabricidentity,singular=fabricidentity
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +k8s:openapi-gen=true

// FabricIdentity is the Schema for the hlfs API
type FabricIdentity struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              FabricIdentitySpec   `json:"spec,omitempty"`
	Status            FabricIdentityStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FabricIdentityList contains a list of FabricIdentity
type FabricIdentityList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricIdentity `json:"items"`
}

// FabricIdentitySpec defines the desired state of FabricIdentity
type FabricIdentitySpec struct {
	// +optional
	// +nullable
	Cahost string `json:"cahost"`
	// +optional
	// +nullable
	Caname string `json:"caname"`
	// +optional
	// +nullable
	Caport int `json:"caport"`
	// +optional
	// +nullable
	Catls *Catls `json:"catls"`
	// +optional
	// +nullable
	Enrollid string `json:"enrollid"`
	// +optional
	// +nullable
	Enrollsecret string `json:"enrollsecret"`
	MSPID        string `json:"mspid"`
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:={}
	AttributeRequest []FabricIdentityAttributeRequest `json:"attributeRequest"`
	// +optional
	// +nullable
	Register *FabricIdentityRegister `json:"register"`
	// +optional
	// +nullable
	UpdateCertificateTime *metav1.Time `json:"updateCertificateTime"`

	// +optional
	// +nullable
	Vault *VaultComponent `json:"vault"`

	// +kubebuilder:default:="kubernetes"
	// +kubebuilder:validation:Enum=kubernetes;vault
	CredentialStore CredentialStore `json:"credentialStore"`
}

type FabricIdentityAttributeRequest struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=false
	Optional bool `json:"optional"`
}

type FabricIdentityRegister struct {
	// +kubebuilder:validation:MinLength=1
	Enrollid string `json:"enrollid"`
	// +kubebuilder:validation:MinLength=1
	Enrollsecret string `json:"enrollsecret"`
	// +kubebuilder:validation:MinLength=1
	Type string `json:"type"`

	Affiliation string `json:"affiliation"`

	MaxEnrollments int `json:"maxenrollments"`
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:={}
	Attributes []FabricIdentityAttributes `json:"attributes"`
	Attrs      []string                   `json:"attrs"`
}
type FabricIdentityAttributes struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// +kubebuilder:validation:MinLength=1
	Value string `json:"value"`

	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=false
	ECert bool `json:"ecert"`
}

// FabricMainChannelStatus defines the observed state of FabricMainChannel
type FabricMainChannelStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Message    string            `json:"message"`
	// Status of the FabricCA
	Status DeploymentStatus `json:"status"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=fabricmainchannel,singular=fabricmainchannel
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +k8s:openapi-gen=true

// FabricMainChannel is the Schema for the hlfs API
type FabricMainChannel struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              FabricMainChannelSpec   `json:"spec,omitempty"`
	Status            FabricMainChannelStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FabricMainChannelList contains a list of FabricMainChannel
type FabricMainChannelList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricMainChannel `json:"items"`
}

// FabricMainChannelSpec defines the desired state of FabricMainChannel
type FabricMainChannelSpec struct {
	// Name of the channel
	Name string `json:"name"`
	// HLF Identities to be used to create and manage the channel
	Identities map[string]FabricMainChannelIdentity `json:"identities"`

	// Organizations that manage the `application` configuration of the channel
	AdminPeerOrganizations []FabricMainChannelAdminPeerOrganizationSpec `json:"adminPeerOrganizations"`
	// Peer organizations that are external to the Kubernetes cluster
	PeerOrganizations []FabricMainChannelPeerOrganization `json:"peerOrganizations"`
	// External peer organizations that are inside the kubernetes cluster
	ExternalPeerOrganizations []FabricMainChannelExternalPeerOrganization `json:"externalPeerOrganizations"`

	// +nullable
	// Configuration about the channel
	ChannelConfig *FabricMainChannelConfig `json:"channelConfig"`

	// Organizations that manage the `orderer` configuration of the channel
	AdminOrdererOrganizations []FabricMainChannelAdminOrdererOrganizationSpec `json:"adminOrdererOrganizations"`
	// External orderer organizations that are inside the kubernetes cluster
	OrdererOrganizations []FabricMainChannelOrdererOrganization `json:"ordererOrganizations"`
	// Orderer organizations that are external to the Kubernetes cluster
	ExternalOrdererOrganizations []FabricMainChannelExternalOrdererOrganization `json:"externalOrdererOrganizations"`

	// Consenters are the orderer nodes that are part of the channel consensus
	Consenters []FabricMainChannelConsenter `json:"orderers"`
}

type FabricMainChannelAdminPeerOrganizationSpec struct {
	// MSP ID of the organization
	MSPID string `json:"mspID"`
}
type FabricMainChannelAdminOrdererOrganizationSpec struct {
	// MSP ID of the organization
	MSPID string `json:"mspID"`
}
type FabricMainChannelConfig struct {
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// Application configuration of the channel
	Application *FabricMainChannelApplicationConfig `json:"application"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// Orderer configuration of the channel
	Orderer *FabricMainChannelOrdererConfig `json:"orderer"`
	// Capabilities for the channel
	// +kubebuilder:default:={"V2_0"}
	Capabilities []string `json:"capabilities"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// Policies for the channel
	Policies *map[string]FabricMainChannelPoliciesConfig `json:"policies"`
}

type FabricMainChannelApplicationConfig struct {
	// Capabilities of the application channel configuration
	// +kubebuilder:default:={"V2_0"}
	Capabilities []string `json:"capabilities"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// Policies of the application channel configuration
	Policies *map[string]FabricMainChannelPoliciesConfig `json:"policies"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// ACLs of the application channel configuration
	ACLs *map[string]string `json:"acls"`
}
type FabricMainChannelOrdererConfig struct {
	// OrdererType of the consensus, default "etcdraft"
	// +kubebuilder:default:="etcdraft"
	OrdererType OrdererConsensusType `json:"ordererType"`
	// Capabilities of the channel
	// +kubebuilder:default:={"V2_0"}
	Capabilities []string `json:"capabilities"`
	// Policies of the orderer section of the channel
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Policies *map[string]FabricMainChannelPoliciesConfig `json:"policies"`
	// Interval of the ordering service to create a block and send to the peers
	// +kubebuilder:default:="2s"
	BatchTimeout string `json:"batchTimeout"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	BatchSize *FabricMainChannelOrdererBatchSize `json:"batchSize"`
	// State about the channel, can only be `STATE_NORMAL` or `STATE_MAINTENANCE`.
	// +kubebuilder:default:="STATE_NORMAL"
	State FabricMainChannelConsensusState `json:"state"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	EtcdRaft *FabricMainChannelEtcdRaft `json:"etcdRaft"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	SmartBFT *FabricMainChannelSmartBFT `json:"smartBFT"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	ConsenterMapping []FabricMainChannelConsenterItem `json:"consenterMapping"`
}

type FabricMainChannelSmartBFT struct {
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=100
	RequestBatchMaxCount uint64 `json:"request_batch_max_count,omitempty"`
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=10485760
	RequestBatchMaxBytes uint64 `json:"request_batch_max_bytes,omitempty"`
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:="50ms"
	RequestBatchMaxInterval string `json:"request_batch_max_interval,omitempty"`
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=200
	IncomingMessageBufferSize uint64 `json:"incoming_message_buffer_size,omitempty"`
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=400
	RequestPoolSize uint64 `json:"request_pool_size,omitempty"`
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:="2s"
	RequestForwardTimeout string `json:"request_forward_timeout,omitempty"`
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:="20s"
	RequestComplainTimeout string `json:"request_complain_timeout,omitempty"`
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:="3m"
	RequestAutoRemoveTimeout string `json:"request_auto_remove_timeout,omitempty"`
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=10485760
	RequestMaxBytes uint64 `json:"request_max_bytes,omitempty"`
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:="5s"
	ViewChangeResendInterval string `json:"view_change_resend_interval,omitempty"`
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:="20s"
	ViewChangeTimeout string `json:"view_change_timeout,omitempty"`
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:="1m"
	LeaderHeartbeatTimeout string `json:"leader_heartbeat_timeout,omitempty"`
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=10
	LeaderHeartbeatCount uint64 `json:"leader_heartbeat_count,omitempty"`
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:="1s"
	CollectTimeout string `json:"collect_timeout,omitempty"`
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=false
	SyncOnStart bool `json:"sync_on_start,omitempty"`
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=false
	SpeedUpViewChange bool `json:"speed_up_view_change,omitempty"`
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=1
	LeaderRotation sb.Options_Rotation `json:"leader_rotation,omitempty"`
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=3
	DecisionsPerLeader uint64 `json:"decisions_per_leader,omitempty"`
}
type FabricMainChannelEtcdRaft struct {
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Options *FabricMainChannelEtcdRaftOptions `json:"options"`
}

type FabricMainChannelEtcdRaftOptions struct {
	// +kubebuilder:default:="500ms"
	TickInterval string `json:"tickInterval"`
	// +kubebuilder:default:=10
	ElectionTick uint32 `json:"electionTick"`
	// HeartbeatTick is the number of ticks that must pass between heartbeats
	// +kubebuilder:default:=1
	HeartbeatTick uint32 `json:"heartbeatTick"`
	// MaxInflightBlocks is the maximum number of in-flight blocks that may be sent to followers at any given time.
	// +kubebuilder:default:=5
	MaxInflightBlocks uint32 `json:"maxInflightBlocks"`
	// Maximum size of each raft snapshot file.
	// +kubebuilder:default:=16777216
	SnapshotIntervalSize uint32 `json:"snapshotIntervalSize"`
}

type OrdererConsensusType string

const (
	OrdererConsensusEtcdraft OrdererConsensusType = "etcdraft"
	OrdererConsensusBFT      OrdererConsensusType = "BFT"
)

type FabricMainChannelConsensusState string

const (
	ConsensusStateNormal FabricMainChannelConsensusState = "STATE_NORMAL"

	ConsensusStateMaintenance FabricMainChannelConsensusState = "STATE_MAINTENANCE"
)

type ConsensusTypeValue struct {
	value   *OrdererConsensusType
	allowed []OrdererConsensusType
}

func (c *ConsensusTypeValue) String() string {
	if c.value == nil {
		return ""
	}
	return string(*c.value)
}

func (c *ConsensusTypeValue) Set(s string) error {
	for _, v := range c.allowed {
		if string(v) == s {
			*c.value = v
			return nil
		}
	}
	return fmt.Errorf("invalid consensus type: %s. Valid types are: %s", s, strings.Join(c.allowedStrings(), ", "))
}

func (c *ConsensusTypeValue) Type() string {
	return "ConsensusType"
}

func (c *ConsensusTypeValue) allowedStrings() []string {
	var allowedStrs []string
	for _, v := range c.allowed {
		allowedStrs = append(allowedStrs, string(v))
	}
	return allowedStrs
}

func NewConsensusTypeValue(val OrdererConsensusType, allowed []OrdererConsensusType, p *OrdererConsensusType) *ConsensusTypeValue {
	*p = val
	return &ConsensusTypeValue{
		value:   p,
		allowed: allowed,
	}
}

type FabricMainChannelOrdererBatchSize struct {
	// The number of transactions that can fit in a block.
	// +kubebuilder:default:=100
	MaxMessageCount int `json:"maxMessageCount"`
	// The absolute maximum size of a block, including all metadata.
	// +kubebuilder:default:=1048576
	AbsoluteMaxBytes int `json:"absoluteMaxBytes"`
	// The preferred maximum size of a block, including all metadata.
	// +kubebuilder:default:=524288
	PreferredMaxBytes int `json:"preferredMaxBytes"`
}

type FabricMainChannelPoliciesConfig struct {
	// Type of policy, can only be `ImplicitMeta` or `Signature`.
	Type string `json:"type"`
	// Rule of policy
	Rule      string `json:"rule"`
	ModPolicy string `json:"modPolicy"`
}

type FabricMainChannelIdentity struct {
	// +kubebuilder:default:=default
	// Secret namespace
	SecretNamespace string `json:"secretNamespace"`
	// Secret name
	SecretName string `json:"secretName"`
	// Key inside the secret that holds the private key and certificate to interact with the network
	SecretKey string `json:"secretKey"`
}

type FabricMainChannelConsenterItem struct {
	Id            uint32 `json:"id,omitempty"`
	Host          string `json:"host,omitempty"`
	Port          uint32 `json:"port,omitempty"`
	MspId         string `json:"msp_id,omitempty"`
	Identity      string `json:"identity,omitempty"`
	ClientTlsCert string `json:"client_tls_cert,omitempty"`
	ServerTlsCert string `json:"server_tls_cert,omitempty"`
}
type FabricMainChannelConsenter struct {
	// Orderer host of the consenter
	Host string `json:"host"`
	// Orderer port of the consenter
	Port int `json:"port"`
	// TLS Certificate of the orderer node
	TLSCert string `json:"tlsCert"`
}

type FabricMainChannelExternalPeerOrganization struct {
	// MSP ID of the organization
	MSPID string `json:"mspID"`
	// TLS Root certificate authority of the orderer organization
	TLSRootCert string `json:"tlsRootCert"`
	// Root certificate authority for signing
	SignRootCert string `json:"signRootCert"`
}

type FabricMainChannelExternalOrdererOrganization struct {
	// MSP ID of the organization
	MSPID string `json:"mspID"`
	// TLS Root certificate authority of the orderer organization
	TLSRootCert string `json:"tlsRootCert"`
	// Root certificate authority for signing
	SignRootCert string `json:"signRootCert"`
	// Orderer endpoints for the organization in the channel configuration
	OrdererEndpoints []string `json:"ordererEndpoints"`
	// +optional
	// +nullable
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:={}
	RevocationList []string `json:"revocationList"`
}
type OrgCertsRef struct {
}
type CARef struct {
	CAName string `json:"caName"`
	// FabricCA Namespace of the organization
	CANamespace string `json:"caNamespace"`
}
type FabricMainChannelPeerOrganization struct {
	// MSP ID of the organization
	MSPID string `json:"mspID"`
	// FabricCA Name of the organization
	CAName string `json:"caName"`
	// FabricCA Namespace of the organization
	CANamespace string `json:"caNamespace"`
}

type FabricMainChannelOrdererOrganization struct {
	// MSP ID of the organization
	MSPID string `json:"mspID"`
	// +optional
	// FabricCA Name of the organization
	CAName string `json:"caName"`
	// +optional
	// FabricCA Namespace of the organization
	CANamespace string `json:"caNamespace"`
	// +optional
	// TLS Root certificate authority of the orderer organization
	TLSCACert string `json:"tlsCACert"`
	// +optional
	// Root certificate authority for signing
	SignCACert string `json:"signCACert"`
	// +optional
	// +nullable
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:={}
	RevocationList []string `json:"revocationList"`
	// Orderer endpoints for the organization in the channel configuration
	OrdererEndpoints []string `json:"ordererEndpoints"`
	// Orderer nodes within the kubernetes cluster to be added to the channel
	OrderersToJoin []FabricMainChannelOrdererNode `json:"orderersToJoin"`
	// External orderers to be added to the channel
	ExternalOrderersToJoin []FabricMainChannelExternalOrdererNode `json:"externalOrderersToJoin"`
}

type FabricMainChannelExternalOrdererNode struct {
	// Admin host of the orderer node
	Host string `json:"host"`
	// Admin port of the orderer node
	AdminPort int `json:"port"`
}

type FabricMainChannelOrdererNode struct {
	// Name of the orderer node
	Name string `json:"name"`
	// Kubernetes namespace of the orderer node
	Namespace string `json:"namespace"`
}

type FabricMainChannelAnchorPeer struct {
	// Host of the peer
	Host string `json:"host"`
	// Port of the peer
	Port int `json:"port"`
}

// FabricFollowerChannelStatus defines the observed state of FabricFollowerChannel
type FabricFollowerChannelStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Message    string            `json:"message"`
	// Status of the FabricCA
	Status DeploymentStatus `json:"status"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=fabricfollowerchannel,singular=fabricfollowerchannel
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +k8s:openapi-gen=true

// FabricFollowerChannel is the Schema for the hlfs API
type FabricFollowerChannel struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              FabricFollowerChannelSpec   `json:"spec,omitempty"`
	Status            FabricFollowerChannelStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FabricFollowerChannelList contains a list of FabricFollowerChannel
type FabricFollowerChannelList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricFollowerChannel `json:"items"`
}

// FabricFollowerChannelSpec defines the desired state of FabricFollowerChannel
type FabricFollowerChannelSpec struct {
	// Name of the channel
	Name string `json:"name"`
	// MSP ID of the organization to join the channel
	MSPID string `json:"mspId"`
	// Orderers to fetch the configuration block from
	Orderers []FabricFollowerChannelOrderer `json:"orderers"`
	// Peers to join the channel
	PeersToJoin []FabricFollowerChannelPeer `json:"peersToJoin"`
	// Peers to join the channel
	ExternalPeersToJoin []FabricFollowerChannelExternalPeer `json:"externalPeersToJoin"`
	// Anchor peers defined for the current organization
	AnchorPeers []FabricFollowerChannelAnchorPeer `json:"anchorPeers"`
	// Identity to use to interact with the peers and the orderers
	HLFIdentity HLFIdentity `json:"hlfIdentity"`
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:={}
	RevocationList []string `json:"revocationList"`
}

type FabricFollowerChannelAnchorPeer struct {
	// Host of the anchor peer
	Host string `json:"host"`
	// Port of the anchor peer
	Port int `json:"port"`
}

type HLFIdentity struct {
	// Secret name
	SecretName string `json:"secretName"`
	// +kubebuilder:default:=default
	// Secret namespace
	SecretNamespace string `json:"secretNamespace"`
	// Key inside the secret that holds the private key and certificate to interact with the network
	SecretKey string `json:"secretKey"`
}

type FabricFollowerChannelExternalPeer struct {
	// FabricPeer URL of the peer
	URL string `json:"url"`
	// FabricPeer TLS CA certificate of the peer
	TLSCACert string `json:"tlsCACert"`
}
type FabricFollowerChannelPeer struct {
	// FabricPeer Name of the peer inside the kubernetes cluster
	Name string `json:"name"`
	// FabricPeer Namespace of the peer inside the kubernetes cluster
	Namespace string `json:"namespace"`
}

type FabricFollowerChannelOrderer struct {
	// URL of the orderer, e.g.: "grpcs://xxxxx:443"
	URL string `json:"url"`
	// TLS Certificate of the orderer node
	Certificate string `json:"certificate"`
}

// FabricChaincodeTemplateStatus defines the observed state of FabricChaincodeTemplate
type FabricChaincodeTemplateStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Message    string            `json:"message"`
	// Status of the FabricCA
	Status DeploymentStatus `json:"status"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=fabricchaincodetemplate,singular=fabricchaincodetemplate
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// FabricChaincodeTemplate is the Schema for the hlfs API
type FabricChaincodeTemplate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              FabricChaincodeTemplateSpec   `json:"spec,omitempty"`
	Status            FabricChaincodeTemplateStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FabricChaincodeTemplateList contains a list of FabricChaincodeTemplate
type FabricChaincodeTemplateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricChaincodeTemplate `json:"items"`
}

// FabricChaincodeTemplateSpec defines the desired state of FabricChaincodeTemplate
type FabricChaincodeTemplateSpec struct {
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:={}
	Annotations map[string]string `json:"annotations"`
	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:={}
	Labels map[string]string `json:"labels"`

	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:={}
	PodAnnotations map[string]string `json:"podAnnotations"`

	// +nullable
	// +optional
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:={}
	PodLabels map[string]string `json:"podLabels"`

	// +kubebuilder:default:="IfNotPresent"
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy"`

	// +kubebuilder:validation:Default={}
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets"`

	// Entrypoint array. Not executed within a shell.
	// The container image's ENTRYPOINT is used if this is not provided.
	// +optional
	Command []string `json:"command,omitempty" protobuf:"bytes,3,rep,name=command"`

	// Arguments to the entrypoint.
	// The container image's CMD is used if this is not provided.
	// +optional
	Args []string `json:"args,omitempty" protobuf:"bytes,4,rep,name=args"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Affinity *corev1.Affinity `json:"affinity"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Tolerations []corev1.Toleration `json:"tolerations"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources"`

	// +kubebuilder:validation:Default=1
	Replicas int `json:"replicas"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Env []corev1.EnvVar `json:"env"`

	// +kubebuilder:default=7052
	ChaincodeServerPort int `json:"chaincodeServerPort"`

	// +optional
	// +kubebuilder:validation:Optional
	MspID string `json:"mspID"`
}
