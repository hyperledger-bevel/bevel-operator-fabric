package tests

import (
	"context"
	"fmt"

	"github.com/kfsoftware/hlf-operator/controllers/certs"
	"github.com/kfsoftware/hlf-operator/controllers/utils"
	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	// +kubebuilder:scaffold:imports
)

var _ = Describe("Channel Lifecycle", func() {
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
	AfterEach(func() {
		log.Infof("Deleting namespace %s", FabricNamespace)
	})

	Specify("create a main channel and join a peer via follower channel", func() {
		ctx := context.Background()
		publicIP, err := utils.GetPublicIPKubernetes(ClientSet)
		Expect(err).ToNot(HaveOccurred())

		// Step 1: Create a CA
		By("creating a CA for the orderer organization")
		ordererCAName := "orderer-ca"
		ordererCA := randomFabricCA(ordererCAName, FabricNamespace)
		Expect(ordererCA).ToNot(BeNil())

		By("creating a CA for the peer organization")
		peerCAName := "peer-ca"
		peerCA := randomFabricCA(peerCAName, FabricNamespace)
		Expect(peerCA).ToNot(BeNil())

		// Step 2: Register and enroll an admin identity for channel operations, store in a secret
		By("registering and enrolling an admin identity for channel operations")
		ordererMSPID := "OrdererMSP"
		peerMSPID := "Org1MSP"

		// Register admin user with orderer CA
		ordererCATLSCert := ordererCA.Status.TlsCert
		ordererCAURL := fmt.Sprintf("https://%s:%d", publicIP, ordererCA.Status.NodePort)
		ordererCAEnrollID := ordererCA.Spec.CA.Registry.Identities[0].Name
		ordererCAEnrollSecret := ordererCA.Spec.CA.Registry.Identities[0].Pass

		adminUser := "channel-admin"
		adminPassword := "channel-adminpw"
		_, err = certs.RegisterUser(certs.RegisterUserRequest{
			TLSCert:      ordererCATLSCert,
			URL:          ordererCAURL,
			Name:         "ca",
			MSPID:        ordererMSPID,
			EnrollID:     ordererCAEnrollID,
			EnrollSecret: ordererCAEnrollSecret,
			User:         adminUser,
			Secret:       adminPassword,
			Type:         "admin",
			Attributes:   nil,
		})
		if err != nil {
			log.Warnf("Admin user registration may have already occurred: %v", err)
		}

		adminCrt, adminPK, _, err := certs.EnrollUser(certs.EnrollUserRequest{
			TLSCert: ordererCATLSCert,
			URL:     ordererCAURL,
			Name:    "ca",
			MSPID:   ordererMSPID,
			User:    adminUser,
			Secret:  adminPassword,
			Profile: "",
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(adminCrt).ToNot(BeNil())
		Expect(adminPK).ToNot(BeNil())

		adminCertPem := string(utils.EncodeX509Certificate(adminCrt))
		adminKeyPem, err := utils.EncodePrivateKey(adminPK)
		Expect(err).ToNot(HaveOccurred())

		// Create a Kubernetes secret with the admin identity
		// The mainchannel controller expects YAML-encoded identity struct:
		//   cert:
		//     pem: <PEM cert>
		//   key:
		//     pem: <PEM key>
		type pemStruct struct {
			Pem string `yaml:"pem"`
		}
		type identityStruct struct {
			Cert pemStruct `yaml:"cert"`
			Key  pemStruct `yaml:"key"`
		}
		adminIdentity := identityStruct{
			Cert: pemStruct{Pem: adminCertPem},
			Key:  pemStruct{Pem: string(adminKeyPem)},
		}
		adminIdentityYAML, err := yaml.Marshal(adminIdentity)
		Expect(err).ToNot(HaveOccurred())

		adminSecretName := "channel-admin-identity"
		adminSecretKey := "user.yaml"
		adminSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      adminSecretName,
				Namespace: FabricNamespace,
			},
			Data: map[string][]byte{
				adminSecretKey: adminIdentityYAML,
			},
		}
		Expect(K8sClient.Create(ctx, adminSecret)).Should(Succeed())

		// Also register and enroll an admin for the peer org
		peerCATLSCert := peerCA.Status.TlsCert
		peerCAURL := fmt.Sprintf("https://%s:%d", publicIP, peerCA.Status.NodePort)
		peerCAEnrollID := peerCA.Spec.CA.Registry.Identities[0].Name
		peerCAEnrollSecret := peerCA.Spec.CA.Registry.Identities[0].Pass

		peerAdminUser := "peer-admin"
		peerAdminPassword := "peer-adminpw"
		_, err = certs.RegisterUser(certs.RegisterUserRequest{
			TLSCert:      peerCATLSCert,
			URL:          peerCAURL,
			Name:         "ca",
			MSPID:        peerMSPID,
			EnrollID:     peerCAEnrollID,
			EnrollSecret: peerCAEnrollSecret,
			User:         peerAdminUser,
			Secret:       peerAdminPassword,
			Type:         "admin",
			Attributes:   nil,
		})
		if err != nil {
			log.Warnf("Peer admin user registration may have already occurred: %v", err)
		}

		peerAdminCrt, peerAdminPK, _, err := certs.EnrollUser(certs.EnrollUserRequest{
			TLSCert: peerCATLSCert,
			URL:     peerCAURL,
			Name:    "ca",
			MSPID:   peerMSPID,
			User:    peerAdminUser,
			Secret:  peerAdminPassword,
			Profile: "",
		})
		Expect(err).ToNot(HaveOccurred())

		peerAdminCertPem := string(utils.EncodeX509Certificate(peerAdminCrt))
		peerAdminKeyPem, err := utils.EncodePrivateKey(peerAdminPK)
		Expect(err).ToNot(HaveOccurred())

		// Create a Kubernetes secret for the peer admin identity (same YAML format)
		peerAdminIdentity := identityStruct{
			Cert: pemStruct{Pem: peerAdminCertPem},
			Key:  pemStruct{Pem: string(peerAdminKeyPem)},
		}
		peerAdminIdentityYAML, err := yaml.Marshal(peerAdminIdentity)
		Expect(err).ToNot(HaveOccurred())

		peerAdminSecretName := "peer-admin-identity"
		peerAdminSecretKey := "user.yaml"
		peerAdminSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      peerAdminSecretName,
				Namespace: FabricNamespace,
			},
			Data: map[string][]byte{
				peerAdminSecretKey: peerAdminIdentityYAML,
			},
		}
		Expect(K8sClient.Create(ctx, peerAdminSecret)).Should(Succeed())

		// Step 3: Create an orderer node
		By("creating an orderer node")
		ordererReleaseName := "org1-orderer"
		ordParams := createOrdererParams{
			MSPID: ordererMSPID,
		}
		createOrdererNode(ordererReleaseName, FabricNamespace, ordParams, ordererCA)

		orderer := &hlfv1alpha1.FabricOrdererNode{}
		ordererKey := types.NamespacedName{
			Namespace: FabricNamespace,
			Name:      ordererReleaseName,
		}
		Eventually(
			func() bool {
				err := K8sClient.Get(ctx, ordererKey, orderer)
				if err != nil {
					return false
				}
				ctrl.Log.WithName("test").Info("orderer status", "status", orderer.Status.Status)
				return orderer.Status.Status == hlfv1alpha1.RunningStatus
			},
			defTimeoutSecs,
			defInterval,
		).Should(BeTrue(), "orderer should reach running status")

		// Step 4: Create a peer
		By("creating a peer node")
		peerReleaseName := "org1-peer"
		peerParams := createPeerParams{
			MSPID:   peerMSPID,
			StateDB: hlfv1alpha1.StateDBCouchDB,
		}
		createPeer(peerReleaseName, FabricNamespace, peerParams, peerCA)

		peerObj := &hlfv1alpha1.FabricPeer{}
		peerKey := types.NamespacedName{
			Namespace: FabricNamespace,
			Name:      peerReleaseName,
		}
		Eventually(
			func() bool {
				err := K8sClient.Get(ctx, peerKey, peerObj)
				if err != nil {
					return false
				}
				ctrl.Log.WithName("test").Info("peer status", "status", peerObj.Status.Status)
				return peerObj.Status.Status == hlfv1alpha1.RunningStatus
			},
			defTimeoutSecs,
			defInterval,
		).Should(BeTrue(), "peer should reach running status")

		// Re-fetch orderer to get latest status with TLS certs
		err = K8sClient.Get(ctx, ordererKey, orderer)
		Expect(err).ToNot(HaveOccurred())

		// Step 5: Create a FabricMainChannel
		By("creating a FabricMainChannel")
		channelName := getRandomChannelID()
		ordererHost := publicIP
		ordererPort := orderer.Status.NodePort
		ordererTLSCert := orderer.Status.TlsCert
		ordererTLSCACert := orderer.Status.TlsCACert
		ordererSignCACert := orderer.Status.SignCACert

		// Use peer CA certs for the peer organization
		peerSignCACert := peerCA.Status.CACert
		peerTLSCACert := peerCA.Status.TLSCACert

		mainChannelName := fmt.Sprintf("mainchannel-%s", channelName)
		fabricMainChannel := &hlfv1alpha1.FabricMainChannel{
			TypeMeta: NewTypeMeta("FabricMainChannel"),
			ObjectMeta: metav1.ObjectMeta{
				Name: mainChannelName,
			},
			Spec: hlfv1alpha1.FabricMainChannelSpec{
				Name: channelName,
				Identities: map[string]hlfv1alpha1.FabricMainChannelIdentity{
					ordererMSPID: {
						SecretNamespace: FabricNamespace,
						SecretName:      adminSecretName,
						SecretKey:       adminSecretKey,
					},
				},
				AdminPeerOrganizations: []hlfv1alpha1.FabricMainChannelAdminPeerOrganizationSpec{
					{
						MSPID: peerMSPID,
					},
				},
				PeerOrganizations: []hlfv1alpha1.FabricMainChannelPeerOrganization{
					{
						MSPID:       peerMSPID,
						CAName:      peerCAName,
						CANamespace: FabricNamespace,
						TLSCACert:   peerTLSCACert,
						SignCACert:  peerSignCACert,
					},
				},
				ExternalPeerOrganizations: []hlfv1alpha1.FabricMainChannelExternalPeerOrganization{},
				ChannelConfig: &hlfv1alpha1.FabricMainChannelConfig{
					Application: &hlfv1alpha1.FabricMainChannelApplicationConfig{
						Capabilities: []string{"V2_0"},
						Policies:     nil,
						ACLs:         nil,
					},
					Orderer: &hlfv1alpha1.FabricMainChannelOrdererConfig{
						OrdererType:  hlfv1alpha1.OrdererConsensusEtcdraft,
						Capabilities: []string{"V2_0"},
						Policies:     nil,
						BatchTimeout: "2s",
						BatchSize:    nil,
						State:        hlfv1alpha1.ConsensusStateNormal,
						EtcdRaft:     nil,
					},
					Capabilities: []string{"V2_0"},
					Policies:     nil,
				},
				AdminOrdererOrganizations: []hlfv1alpha1.FabricMainChannelAdminOrdererOrganizationSpec{
					{
						MSPID: ordererMSPID,
					},
				},
				OrdererOrganizations: []hlfv1alpha1.FabricMainChannelOrdererOrganization{
					{
						MSPID:       ordererMSPID,
						CAName:      ordererCAName,
						CANamespace: FabricNamespace,
						TLSCACert:   ordererTLSCACert,
						SignCACert:  ordererSignCACert,
						OrdererEndpoints: []string{
							fmt.Sprintf("grpcs://%s:%d", ordererHost, ordererPort),
						},
						OrderersToJoin: []hlfv1alpha1.FabricMainChannelOrdererNode{
							{
								Name:      ordererReleaseName,
								Namespace: FabricNamespace,
							},
						},
						ExternalOrderersToJoin: []hlfv1alpha1.FabricMainChannelExternalOrdererNode{},
					},
				},
				ExternalOrdererOrganizations: []hlfv1alpha1.FabricMainChannelExternalOrdererOrganization{},
				Consenters: []hlfv1alpha1.FabricMainChannelConsenter{
					{
						Host:    ordererHost,
						Port:    ordererPort,
						TLSCert: ordererTLSCert,
					},
				},
			},
		}

		log.Infof("Creating FabricMainChannel %s for channel %s", mainChannelName, channelName)
		Expect(K8sClient.Create(ctx, fabricMainChannel)).Should(Succeed())

		updatedMainChannel := &hlfv1alpha1.FabricMainChannel{}
		mainChannelKey := types.NamespacedName{Name: mainChannelName}
		Eventually(
			func() bool {
				err := K8sClient.Get(ctx, mainChannelKey, updatedMainChannel)
				if err != nil {
					return false
				}
				ctrl.Log.WithName("test").Info("main channel status", "status", updatedMainChannel.Status.Status, "message", updatedMainChannel.Status.Message)
				return updatedMainChannel.Status.Status == hlfv1alpha1.RunningStatus
			},
			"300s",
			defInterval,
		).Should(BeTrue(), "main channel should reach running status")

		// Step 6: Create a FabricFollowerChannel to join the peer to the channel
		By("creating a FabricFollowerChannel to join peer to channel")
		followerChannelName := fmt.Sprintf("followerchannel-%s", channelName)
		fabricFollowerChannel := &hlfv1alpha1.FabricFollowerChannel{
			TypeMeta: NewTypeMeta("FabricFollowerChannel"),
			ObjectMeta: metav1.ObjectMeta{
				Name: followerChannelName,
			},
			Spec: hlfv1alpha1.FabricFollowerChannelSpec{
				Name:  channelName,
				MSPID: peerMSPID,
				Orderers: []hlfv1alpha1.FabricFollowerChannelOrderer{
					{
						URL:         fmt.Sprintf("grpcs://%s:%d", ordererHost, ordererPort),
						Certificate: ordererTLSCACert,
					},
				},
				PeersToJoin: []hlfv1alpha1.FabricFollowerChannelPeer{
					{
						Name:      peerReleaseName,
						Namespace: FabricNamespace,
					},
				},
				ExternalPeersToJoin: []hlfv1alpha1.FabricFollowerChannelExternalPeer{},
				AnchorPeers:         []hlfv1alpha1.FabricFollowerChannelAnchorPeer{},
				HLFIdentity: hlfv1alpha1.HLFIdentity{
					SecretName:      peerAdminSecretName,
					SecretNamespace: FabricNamespace,
					SecretKey:       peerAdminSecretKey,
				},
			},
		}

		log.Infof("Creating FabricFollowerChannel %s for channel %s", followerChannelName, channelName)
		Expect(K8sClient.Create(ctx, fabricFollowerChannel)).Should(Succeed())

		updatedFollowerChannel := &hlfv1alpha1.FabricFollowerChannel{}
		followerChannelKey := types.NamespacedName{Name: followerChannelName}
		Eventually(
			func() bool {
				err := K8sClient.Get(ctx, followerChannelKey, updatedFollowerChannel)
				if err != nil {
					return false
				}
				ctrl.Log.WithName("test").Info("follower channel status", "status", updatedFollowerChannel.Status.Status, "message", updatedFollowerChannel.Status.Message)
				return updatedFollowerChannel.Status.Status == hlfv1alpha1.RunningStatus
			},
			"300s",
			defInterval,
		).Should(BeTrue(), "follower channel should reach running status")

		// Step 7: Verify the peer has joined the channel
		By("verifying peer has joined the channel")
		resClient := getClientForPeer(peerObj, peerCA)
		channelResponse, err := resClient.QueryChannels()
		Expect(err).ToNot(HaveOccurred())

		channelFound := false
		for _, ch := range channelResponse.Channels {
			if ch.ChannelId == channelName {
				channelFound = true
				break
			}
		}
		Expect(channelFound).To(BeTrue(), fmt.Sprintf("peer should have joined channel %s", channelName))

		// Cleanup: delete the follower channel and main channel
		By("cleaning up channel resources")
		Expect(K8sClient.Delete(ctx, updatedFollowerChannel)).Should(Succeed())
		Expect(K8sClient.Delete(ctx, updatedMainChannel)).Should(Succeed())
	})
})
