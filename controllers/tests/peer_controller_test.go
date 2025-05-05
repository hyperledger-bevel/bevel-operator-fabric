package tests

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	pb "github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/ccpackager/lifecycle"
	"github.com/kfsoftware/hlf-operator/controllers/certs"
	"github.com/kfsoftware/hlf-operator/controllers/utils"
	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	// +kubebuilder:scaffold:imports
)

type createPeerParams struct {
	MSPID   string
	StateDB hlfv1alpha1.StateDB
}

func createPeer(releaseName string, namespace string, params createPeerParams, certauth *hlfv1alpha1.FabricCA) *hlfv1alpha1.FabricPeer {
	publicIP, err := utils.GetPublicIPKubernetes(ClientSet)
	Expect(err).ToNot(HaveOccurred())
	mspID := params.MSPID
	caHost := publicIP
	caPort := certauth.Status.NodePort
	caName := "ca"
	caTLSCert := certauth.Status.TlsCert
	enrollID := certauth.Spec.CA.Registry.Identities[0].Name
	enrollSecret := certauth.Spec.CA.Registry.Identities[0].Pass
	caURL := fmt.Sprintf("https://%s:%d", publicIP, certauth.Status.NodePort)

	registerParams := certs.RegisterUserRequest{
		TLSCert:      caTLSCert,
		URL:          caURL,
		Name:         caName,
		MSPID:        mspID,
		EnrollID:     enrollID,
		EnrollSecret: enrollSecret,
		User:         "peer",
		Secret:       "peerpw",
		Type:         "peer",
		Attributes:   nil,
	}
	secret, err := certs.RegisterUser(registerParams)
	Expect(err).ToNot(HaveOccurred())
	Expect(secret).To(Equal(registerParams.Secret))
	peerEnrollID := "peer"
	peerEnrollSecret := "peerpw"
	hosts := []string{
		"127.0.0.1",
		publicIP,
	}
	resources, err := getDefaultResources()
	Expect(err).ToNot(HaveOccurred())
	fabricPeer := &hlfv1alpha1.FabricPeer{
		TypeMeta: NewTypeMeta("FabricPeer"),
		ObjectMeta: v1.ObjectMeta{
			Name:      releaseName,
			Namespace: namespace,
		},
		Spec: hlfv1alpha1.FabricPeerSpec{
			CredentialStore:       hlfv1alpha1.CredentialStoreKubernetes,
			UpdateCertificateTime: nil,
			ServiceMonitor:        nil,
			HostAliases:           nil,
			CouchDBExporter: &hlfv1alpha1.FabricPeerCouchdbExporter{
				Enabled:         false,
				Image:           "gesellix/couchdb-prometheus-exporter",
				Tag:             "v30.0.0",
				ImagePullPolicy: corev1.PullAlways,
			},
			Replicas:         1,
			DockerSocketPath: "",
			Image:            "ghcr.io/kfsoftware/fabric-peer",
			ExternalBuilders: []hlfv1alpha1.ExternalBuilder{},
			Istio: &hlfv1alpha1.FabricIstio{
				Port:           443,
				IngressGateway: "",
				Hosts:          []string{},
			},
			Gossip: hlfv1alpha1.FabricPeerSpecGossip{
				ExternalEndpoint:  "",
				Bootstrap:         "",
				Endpoint:          "",
				UseLeaderElection: true,
				OrgLeader:         false,
			},
			ExternalEndpoint:         "",
			Tag:                      "2.4.3-v0.0.6",
			ImagePullPolicy:          "Always",
			ExternalChaincodeBuilder: true,
			CouchDB: hlfv1alpha1.FabricPeerCouchDB{
				User:            "couchdb",
				Password:        "couchdb",
				Image:           "couchdb",
				Tag:             "3.1.1",
				PullPolicy:      corev1.PullAlways,
				ExternalCouchDB: nil,
			},
			FSServer: &hlfv1alpha1.FabricFSServer{
				Image:      "quay.io/kfsoftware/fs-peer",
				Tag:        "amd64-2.2.0",
				PullPolicy: corev1.PullAlways,
			},
			MspID: mspID,
			Secret: hlfv1alpha1.Secret{
				Enrollment: hlfv1alpha1.Enrollment{
					Component: hlfv1alpha1.Component{
						Cahost: caHost,
						Caname: caName,
						Caport: caPort,
						Catls: &hlfv1alpha1.Catls{
							Cacert: base64.StdEncoding.EncodeToString([]byte(caTLSCert)),
						},
						Enrollid:     peerEnrollID,
						Enrollsecret: peerEnrollSecret,
					},
					TLS: hlfv1alpha1.TLSComponent{
						Cahost: caHost,
						Caname: caName,
						Caport: caPort,
						Catls: &hlfv1alpha1.Catls{
							Cacert: base64.StdEncoding.EncodeToString([]byte(caTLSCert)),
						},
						Csr: hlfv1alpha1.Csr{
							Hosts: hosts,
							CN:    "",
						},
						Enrollid:     peerEnrollID,
						Enrollsecret: peerEnrollSecret,
					},
				},
			},
			Service: hlfv1alpha1.PeerService{
				Type: hlfv1alpha1.ServiceTypeNodePort,
			},
			StateDb: params.StateDB,
			Storage: hlfv1alpha1.FabricPeerStorage{
				CouchDB: hlfv1alpha1.Storage{
					Size:         "1Gi",
					StorageClass: "",
					AccessMode:   "ReadWriteOnce",
				},
				Peer: hlfv1alpha1.Storage{
					Size:         "1Gi",
					StorageClass: "",
					AccessMode:   "ReadWriteOnce",
				},
				Chaincode: hlfv1alpha1.Storage{
					Size:         "1Gi",
					StorageClass: "",
					AccessMode:   "ReadWriteOnce",
				},
			},
			Discovery: hlfv1alpha1.FabricPeerDiscovery{
				Period:      "60s",
				TouchPeriod: "60s",
			},
			Logging: hlfv1alpha1.FabricPeerLogging{
				Level:    "info",
				Peer:     "info",
				Cauthdsl: "info",
				Gossip:   "info",
				Grpc:     "info",
				Ledger:   "info",
				Msp:      "info",
				Policies: "info",
			},
			Resources: hlfv1alpha1.FabricPeerResources{
				Peer:            &resources,
				CouchDB:         &resources,
				Chaincode:       &resources,
				CouchDBExporter: &resources,
			},
			Hosts:       []string{},
			Tolerations: []corev1.Toleration{},
			Env:         []corev1.EnvVar{},
		},
	}
	Expect(K8sClient.Create(context.Background(), fabricPeer)).Should(Succeed())
	return fabricPeer
}

var _ = Describe("Fabric Peer Controller", func() {
	FabricNamespace := ""
	BeforeEach(func() {
		FabricNamespace = "hlf-operator-" + getRandomChannelID()
		testNamespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: FabricNamespace,
			},
		}
		log.Infof("Creating namespace %s", FabricNamespace)
		Expect(K8sClient.Create(context.Background(), testNamespace)).Should(Succeed())
	})
	Specify("create a new Fabric Peer", func() {
		By("create a fabric peer")
		releaseNameCA := "org1-ca"
		releaseNamePeer := "org1-peer"
		mspID := "Org1MSP"
		By("create a fabric ca")
		updatedCA := randomFabricCA(releaseNameCA, FabricNamespace)
		Expect(updatedCA).ToNot(BeNil())
		By("create a fabric peer with leveldb")
		params := createPeerParams{
			MSPID:   mspID,
			StateDB: hlfv1alpha1.StateDBCouchDB,
		}
		createPeer(
			releaseNamePeer,
			FabricNamespace,
			params,
			updatedCA,
		)
		peer := &hlfv1alpha1.FabricPeer{}
		peerKey := types.NamespacedName{Namespace: FabricNamespace, Name: releaseNamePeer}
		Eventually(
			func() bool {
				err := K8sClient.Get(context.Background(), peerKey, peer)
				if err != nil {
					return false
				}
				ctrl.Log.WithName("test").Info("after update", "peer", peer)
				return peer.Status.Status == hlfv1alpha1.RunningStatus
			},
			peerTimeoutSecs,
			defInterval,
		).Should(BeTrue(), "peer status should have been updated")
		ip, err := utils.GetPublicIPKubernetes(ClientSet)
		Expect(err).ToNot(HaveOccurred())
		peerURL := fmt.Sprintf("grpcs://%s:%d", ip, peer.Status.NodePort)
		Expect(peerURL).ToNot(BeEmpty())
		Expect(peer.Status.TlsCert).ToNot(BeEmpty())

		By("test the peer API")
		Eventually(
			func() bool {
				resClient := getClientForPeer(peer, updatedCA)
				channelResponse, err := resClient.QueryChannels(
					resmgmt.WithTargetEndpoints("peer"),
				)
				if err != nil {
					return false
				}
				return len(channelResponse.Channels) == 0
			},
			peerTimeoutSecs,
			defInterval,
		).Should(BeTrue(), "peer channels should be 0")
		resClient := getClientForPeer(peer, updatedCA)
		By("Installing a new chaincode")
		pkgLabel := "fabcar"
		packageBytes, err := lifecycle.NewCCPackage(&lifecycle.Descriptor{
			Path:  "../../fixtures/chaincodes/fabcar/go",
			Type:  pb.ChaincodeSpec_GOLANG,
			Label: pkgLabel,
		})
		Expect(err).ToNot(HaveOccurred())
		responses, err := resClient.LifecycleInstallCC(
			resmgmt.LifecycleInstallCCRequest{
				Label:   pkgLabel,
				Package: packageBytes,
			},
			resmgmt.WithTimeout(fab.ResMgmt, 20*time.Minute),
			resmgmt.WithTimeout(fab.PeerResponse, 20*time.Minute),
		)
		Expect(err).ToNot(HaveOccurred())
		Expect(responses).To(HaveLen(1))
		installedRes, err := resClient.LifecycleQueryInstalledCC(
			resmgmt.WithTargetEndpoints("peer"),
		)
		Expect(err).ToNot(HaveOccurred())
		Expect(installedRes).To(HaveLen(1))

	})
})
