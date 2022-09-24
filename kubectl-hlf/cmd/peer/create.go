package peer

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/pkg/errors"
	"io"
	"k8s.io/apimachinery/pkg/api/resource"
	"strings"

	"github.com/kfsoftware/hlf-operator/api/hlf.kungfusoftware.es/v1alpha1"
	"github.com/kfsoftware/hlf-operator/controllers/utils"
	"github.com/kfsoftware/hlf-operator/kubectl-hlf/cmd/helpers"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Options struct {
	Name                            string
	StorageClass                    string
	PeerCapacity                    string
	DbCapacity                      string
	ChaincodeCapacity               string
	NS                              string
	Image                           string
	Version                         string
	MspID                           string
	StateDB                         string
	IngressGateway                  string
	IngressPort                     int
	EnrollPW                        string
	CAName                          string
	EnrollID                        string
	Hosts                           []string
	HostAliases                     []string
	BootstrapPeers                  []string
	Leader                          bool
	Output                          bool
	KubernetesBuilder               bool
	ExternalChaincodeServiceBuilder bool
	CouchDBImage                    string
	CouchDBTag                      string
	CouchDBPassword                 string
	CAPort                          int
	CAHost                          string
}

func (o Options) Validate() error {
	return nil
}

type createCmd struct {
	out      io.Writer
	errOut   io.Writer
	peerOpts Options
}

func (c *createCmd) validate() error {
	return c.peerOpts.Validate()
}
func (c *createCmd) run() error {
	oclient, err := helpers.GetKubeOperatorClient()
	if err != nil {
		return err
	}
	clientSet, err := helpers.GetKubeClient()
	if err != nil {
		return err
	}
	certAuth, err := helpers.GetCertAuthByFullName(clientSet, oclient, c.peerOpts.CAName)
	if err != nil {
		return err
	}
	if certAuth.Status.Status != v1alpha1.RunningStatus {
		return errors.Errorf("ca %s is in %s status", certAuth.Name, certAuth.Status.Status)
	}
	k8sIPs, err := utils.GetPublicIPsKubernetes(clientSet)
	if err != nil {
		return err
	}
	externalEndpoint := ""
	if len(c.peerOpts.Hosts) > 0 {
		externalEndpoint = fmt.Sprintf("%s:%d", c.peerOpts.Hosts[0], c.peerOpts.IngressPort)
	}
	ingressGateway := c.peerOpts.IngressGateway
	istio := &v1alpha1.FabricIstio{
		Port:           c.peerOpts.IngressPort,
		Hosts:          []string{},
		IngressGateway: ingressGateway,
	}
	if len(c.peerOpts.Hosts) > 0 {
		istio = &v1alpha1.FabricIstio{
			Port:           c.peerOpts.IngressPort,
			Hosts:          c.peerOpts.Hosts,
			IngressGateway: ingressGateway,
		}
	}
	k8sIP, err := utils.GetPublicIPKubernetes(clientSet)
	if err != nil {
		return err
	}
	peerRequirements, err := getPeerResourceRequirements()
	if err != nil {
		return err
	}
	couchdbRequirements, err := getCouchdbResourceRequirements()
	if err != nil {
		return err
	}
	chaincodeRequirements, err := getChaincodeResourceRequirements()
	if err != nil {
		return err
	}
	csrHosts := []string{
		"127.0.0.1",
		"localhost",
	}
	for _, k8sIP := range k8sIPs {
		csrHosts = append(csrHosts, k8sIP)
	}
	csrHosts = append(csrHosts, c.peerOpts.Name)
	csrHosts = append(csrHosts, fmt.Sprintf("%s.%s", c.peerOpts.Name, c.peerOpts.NS))
	var externalBuilders []v1alpha1.ExternalBuilder
	if c.peerOpts.ExternalChaincodeServiceBuilder {
		externalBuilders = append(externalBuilders, v1alpha1.ExternalBuilder{
			Name: "ccaas_builder",
			Path: "/opt/hyperledger/ccaas_builder",
			PropagateEnvironment: []string{
				"CHAINCODE_AS_A_SERVICE_BUILDER_CONFIG",
			},
		})
	}
	kubernetesBuilder := c.peerOpts.KubernetesBuilder
	if c.peerOpts.KubernetesBuilder {
		externalBuilders = append(externalBuilders, v1alpha1.ExternalBuilder{
			Name: "k8s-builder",
			Path: "/builders/golang",
			PropagateEnvironment: []string{
				"CHAINCODE_SHARED_DIR",
				"FILE_SERVER_BASE_IP",
				"KUBERNETES_SERVICE_HOST",
				"KUBERNETES_SERVICE_PORT",
				"K8SCC_CFGFILE",
				"TMPDIR",
				"LD_LIBRARY_PATH",
				"LIBPATH",
				"PATH",
				"EXTERNAL_BUILDER_HTTP_PROXY",
				"EXTERNAL_BUILDER_HTTPS_PROXY",
				"EXTERNAL_BUILDER_NO_PROXY",
				"EXTERNAL_BUILDER_PEER_URL",
			},
		})
	}
	couchDB := v1alpha1.FabricPeerCouchDB{
		User:     "couchdb",
		Password: "couchdb",
	}
	if c.peerOpts.CouchDBPassword != "" {
		couchDB.Password = c.peerOpts.CouchDBPassword
	}
	if c.peerOpts.CouchDBImage != "" && c.peerOpts.CouchDBTag != "" {
		couchDB.Image = c.peerOpts.CouchDBImage
		couchDB.Tag = c.peerOpts.CouchDBTag
	}
	caHost := k8sIP
	if c.peerOpts.CAHost != "" {
		caHost = c.peerOpts.CAHost
	}
	caPort := certAuth.Status.NodePort
	if c.peerOpts.CAPort != 0 {
		caPort = c.peerOpts.CAPort
	}
	component := v1alpha1.Component{
		Cahost: caHost,
		Caport: caPort,
		Caname: certAuth.Spec.CA.Name,
		Catls: v1alpha1.Catls{
			Cacert: base64.StdEncoding.EncodeToString([]byte(certAuth.Status.TlsCert)),
		},
		Enrollid:     c.peerOpts.EnrollID,
		Enrollsecret: c.peerOpts.EnrollPW,
	}
	tls := v1alpha1.TLS{
		Cahost: caHost,
		Caport: caPort,
		Caname: certAuth.Spec.TLSCA.Name,
		Catls: v1alpha1.Catls{
			Cacert: base64.StdEncoding.EncodeToString([]byte(certAuth.Status.TlsCert)),
		},
		Csr: v1alpha1.Csr{
			Hosts: csrHosts,
			CN:    "",
		},
		Enrollid:     c.peerOpts.EnrollID,
		Enrollsecret: c.peerOpts.EnrollPW,
	}

	var hostAliases []corev1.HostAlias
	for _, hostAlias := range c.peerOpts.HostAliases {
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

	fabricPeer := &v1alpha1.FabricPeer{
		TypeMeta: v1.TypeMeta{
			Kind:       "FabricPeer",
			APIVersion: v1alpha1.GroupVersion.String(),
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      c.peerOpts.Name,
			Namespace: c.peerOpts.NS,
		},
		Spec: v1alpha1.FabricPeerSpec{
			ServiceMonitor:           nil,
			HostAliases:              hostAliases,
			Replicas:                 1,
			DockerSocketPath:         "",
			Image:                    c.peerOpts.Image,
			ExternalChaincodeBuilder: kubernetesBuilder,
			ExternalBuilders:         externalBuilders,
			Istio:                    istio,
			Gossip: v1alpha1.FabricPeerSpecGossip{
				ExternalEndpoint:  externalEndpoint,
				Bootstrap:         "",
				Endpoint:          "",
				UseLeaderElection: !c.peerOpts.Leader,
				OrgLeader:         c.peerOpts.Leader,
			},
			ExternalEndpoint: externalEndpoint,
			Tag:              c.peerOpts.Version,
			ImagePullPolicy:  "Always",
			CouchDB:          couchDB,
			MspID:            c.peerOpts.MspID,
			Secret: v1alpha1.Secret{
				Enrollment: v1alpha1.Enrollment{
					Component: component,
					TLS:       tls,
				},
			},
			Service: v1alpha1.PeerService{
				Type: "NodePort",
			},
			StateDb: v1alpha1.StateDB(c.peerOpts.StateDB),
			Storage: v1alpha1.FabricPeerStorage{
				CouchDB: v1alpha1.Storage{
					Size:         c.peerOpts.DbCapacity,
					StorageClass: c.peerOpts.StorageClass,
					AccessMode:   "ReadWriteOnce",
				},
				Peer: v1alpha1.Storage{
					Size:         c.peerOpts.PeerCapacity,
					StorageClass: c.peerOpts.StorageClass,
					AccessMode:   "ReadWriteOnce",
				},
				Chaincode: v1alpha1.Storage{
					Size:         c.peerOpts.ChaincodeCapacity,
					StorageClass: c.peerOpts.StorageClass,
					AccessMode:   "ReadWriteOnce",
				},
			},
			Discovery: v1alpha1.FabricPeerDiscovery{
				Period:      "60s",
				TouchPeriod: "60s",
			},
			Logging: v1alpha1.FabricPeerLogging{
				Level:    "info",
				Peer:     "info",
				Cauthdsl: "info",
				Gossip:   "info",
				Grpc:     "info",
				Ledger:   "info",
				Msp:      "info",
				Policies: "info",
			},
			Resources: v1alpha1.FabricPeerResources{
				Peer:      peerRequirements,
				CouchDB:   couchdbRequirements,
				Chaincode: chaincodeRequirements,
			},
			Hosts: c.peerOpts.Hosts,
		},
		Status: v1alpha1.FabricPeerStatus{},
	}
	if c.peerOpts.Output {
		ot, err := helpers.MarshallWithoutStatus(&fabricPeer)
		if err != nil {
			return err
		}
		fmt.Println(string(ot))
	} else {
		ctx := context.Background()
		_, err = oclient.HlfV1alpha1().FabricPeers(c.peerOpts.NS).Create(
			ctx,
			fabricPeer,
			v1.CreateOptions{},
		)
		if err != nil {
			return err
		}
		log.Infof("Peer %s created on namespace %s", fabricPeer.Name, fabricPeer.Namespace)
	}
	return nil
}

func getChaincodeResourceRequirements() (corev1.ResourceRequirements, error) {
	requestCpu, err := resource.ParseQuantity("10m")
	if err != nil {
		return corev1.ResourceRequirements{}, err
	}
	requestMemory, err := resource.ParseQuantity("10m")
	if err != nil {
		return corev1.ResourceRequirements{}, err
	}
	limitsCpu, err := resource.ParseQuantity("1")
	if err != nil {
		return corev1.ResourceRequirements{}, err
	}
	limitsMemory, err := resource.ParseQuantity("100Mi")
	if err != nil {
		return corev1.ResourceRequirements{}, err
	}
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    requestCpu,
			corev1.ResourceMemory: requestMemory,
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    limitsCpu,
			corev1.ResourceMemory: limitsMemory,
		},
	}, nil
}

func getCouchdbResourceRequirements() (corev1.ResourceRequirements, error) {
	requestCpu, err := resource.ParseQuantity("10m")
	if err != nil {
		return corev1.ResourceRequirements{}, err
	}
	requestMemory, err := resource.ParseQuantity("10m")
	if err != nil {
		return corev1.ResourceRequirements{}, err
	}
	limitsCpu, err := resource.ParseQuantity("1")
	if err != nil {
		return corev1.ResourceRequirements{}, err
	}
	limitsMemory, err := resource.ParseQuantity("512Mi")
	if err != nil {
		return corev1.ResourceRequirements{}, err
	}
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    requestCpu,
			corev1.ResourceMemory: requestMemory,
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    limitsCpu,
			corev1.ResourceMemory: limitsMemory,
		},
	}, nil
}

func getPeerResourceRequirements() (corev1.ResourceRequirements, error) {
	requestCpu, err := resource.ParseQuantity("10m")
	if err != nil {
		return corev1.ResourceRequirements{}, err
	}
	requestMemory, err := resource.ParseQuantity("128Mi")
	if err != nil {
		return corev1.ResourceRequirements{}, err
	}
	limitsCpu, err := resource.ParseQuantity("1")
	if err != nil {
		return corev1.ResourceRequirements{}, err
	}
	limitsMemory, err := resource.ParseQuantity("512Mi")
	if err != nil {
		return corev1.ResourceRequirements{}, err
	}
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    requestCpu,
			corev1.ResourceMemory: requestMemory,
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    limitsCpu,
			corev1.ResourceMemory: limitsMemory,
		},
	}, nil
}
func newCreatePeerCmd(out io.Writer, errOut io.Writer) *cobra.Command {
	c := createCmd{out: out, errOut: errOut}
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a Fabric Peer",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			return c.run()
		},
	}
	f := cmd.Flags()
	f.StringVar(&c.peerOpts.Name, "name", "", "Name of the Fabric Peer to create")
	f.StringVar(&c.peerOpts.CAName, "ca-name", "", "CA name to enroll the peer identity")
	f.StringVar(&c.peerOpts.CAHost, "ca-host", "", "CA host to enroll the peer identity")
	f.IntVar(&c.peerOpts.CAPort, "ca-port", 0, "CA host to enroll the peer identity")
	f.StringVar(&c.peerOpts.EnrollID, "enroll-id", "", "Enroll ID of the CA")
	f.StringVar(&c.peerOpts.EnrollPW, "enroll-pw", "", "Enroll secret of the CA")
	f.StringVar(&c.peerOpts.PeerCapacity, "capacity", "5Gi", "Total raw capacity of Fabric Peer in this zone, e.g. 16Ti")
	f.StringVar(&c.peerOpts.DbCapacity, "db-capacity", "5Gi", "Total raw capacity of CouchDB in this zone, e.g. 16Ti")
	f.StringVar(&c.peerOpts.ChaincodeCapacity, "chaincode-capacity", "5Gi", "Total raw capacity of chaincode in this zone, e.g. 16Ti")
	f.StringVarP(&c.peerOpts.NS, "namespace", "n", helpers.DefaultNamespace, "Namespace scope for this request")
	f.StringVarP(&c.peerOpts.StorageClass, "storage-class", "s", helpers.DefaultStorageclass, "Storage class for this Fabric Peer")
	f.StringVarP(&c.peerOpts.Image, "image", "", helpers.DefaultPeerImage, "Version of the Fabric Peer")
	f.StringVarP(&c.peerOpts.Version, "version", "", helpers.DefaultPeerVersion, "Version of the Fabric Peer")
	f.StringVarP(&c.peerOpts.MspID, "mspid", "", "", "MSP ID of the organization")
	f.StringVarP(&c.peerOpts.StateDB, "statedb", "", "leveldb", "State database")
	f.StringVarP(&c.peerOpts.IngressGateway, "istio-ingressgateway", "", "ingressgateway", "Istio ingress gateway name")
	f.IntVarP(&c.peerOpts.IngressPort, "istio-port", "", 443, "Istio ingress port")
	f.BoolVarP(&c.peerOpts.Leader, "leader", "", false, "Force peer to be leader")
	f.StringArrayVarP(&c.peerOpts.BootstrapPeers, "bootstrap-peer", "", []string{}, "Bootstrap peers")
	f.StringArrayVarP(&c.peerOpts.Hosts, "hosts", "", []string{}, "External hosts")
	f.BoolVarP(&c.peerOpts.Output, "output", "o", false, "Output in yaml")
	f.BoolVarP(&c.peerOpts.KubernetesBuilder, "k8s-builder", "", false, "Enable kubernetes builder (deprecated)")
	f.BoolVarP(&c.peerOpts.ExternalChaincodeServiceBuilder, "external-service-builder", "", true, "External chaincode service builder enabled(only use in 2.4.1+)")
	f.StringArrayVarP(&c.peerOpts.HostAliases, "host-aliases", "", []string{}, "Host aliases (e.g.: \"1.2.3.4:osn1.example.com,osn2.example.com\")")

	f.StringVarP(&c.peerOpts.CouchDBImage, "couchdb-repository", "", helpers.DefaultCouchDBImage, "CouchDB image")
	f.StringVarP(&c.peerOpts.CouchDBTag, "couchdb-tag", "", helpers.DefaultCouchDBVersion, "CouchDB version")
	f.StringVarP(&c.peerOpts.CouchDBPassword, "couchdb-password", "", "", "CouchDB password")
	return cmd
}
