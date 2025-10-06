package channel

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-config/configtx/orderer"
	"github.com/kfsoftware/hlf-operator/controllers/testutils"
	"github.com/kfsoftware/hlf-operator/controllers/utils"
	"github.com/kfsoftware/hlf-operator/kubectl-hlf/cmd/helpers"
	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type generateChannelCmd struct {
	channelName          string
	organizations        []string
	ordererOrganizations []string
	consenterNodes       []string
	output               string
	maxMessageCount      int
	absoluteMaxBytes     int
	preferredMaxBytes    int
	batchTimeout         int
	consensus            hlfv1alpha1.OrdererConsensusType
}

var validConsensusTypes = []hlfv1alpha1.OrdererConsensusType{hlfv1alpha1.OrdererConsensusBFT, hlfv1alpha1.OrdererConsensusEtcdraft}

func (c generateChannelCmd) validate() error {
	if c.channelName == "" {
		return errors.Errorf("--channelName is required")
	}
	if len(c.ordererOrganizations) == 0 {
		return errors.Errorf("--ordererOrganizations is required")
	}
	if len(c.organizations) == 0 {
		return errors.Errorf("--organizations is required")
	}
	if c.output == "" {
		return errors.Errorf("--output is required")
	}
	return nil
}

func (c generateChannelCmd) run() error {
	oclient, err := helpers.GetKubeOperatorClient()
	if err != nil {
		return err
	}
	clientSet, err := helpers.GetKubeClient()
	if err != nil {
		return err
	}
	ns := ""
	chStore := testutils.NewChannelStore()
	ctx := context.Background()
	var consenters []testutils.Consenter
	orderers, err := helpers.GetClusterOrdererNodes(clientSet, oclient, ns)
	if err != nil {
		return err
	}
	ordererMap := map[string][]*helpers.ClusterOrdererNode{}
	log.Debugf("orderers: %v", orderers)
	for _, consenter := range orderers {
		log.Debugf("orderer: %v", consenter.Spec.MspID)
		if !utils.Contains(c.ordererOrganizations, consenter.Spec.MspID) {
			continue
		}
		if len(c.consenterNodes) > 0 {
			// check if the orderer is in the list of consenter nodes specified
			found := false
			for _, consenterNode := range c.consenterNodes {
				if consenterNode == consenter.Item.Name {
					found = true
				}
			}
			if !found {
				continue
			}
		}
		tlsCert, err := utils.ParseX509Certificate([]byte(consenter.Status.TlsCert))
		if err != nil {
			return err
		}
		signCert, err := utils.ParseX509Certificate([]byte(consenter.Status.SignCert))
		if err != nil {
			return err
		}
		consenterHost, consenterPort, err := helpers.GetOrdererHostAndPort(
			clientSet,
			consenter.Spec,
			consenter.Status,
		)
		if err != nil {
			return err
		}
		createConsenter := testutils.CreateConsenter(
			consenterHost,
			consenterPort,
			tlsCert,
			signCert,
			consenter.Spec.MspID,
		)
		consenters = append(consenters, createConsenter)
		_, ok := ordererMap[consenter.Spec.MspID]
		if !ok {
			ordererMap[consenter.Spec.MspID] = []*helpers.ClusterOrdererNode{}
		}
		ordererMap[consenter.Spec.MspID] = append(ordererMap[consenter.Spec.MspID], consenter)

	}
	var ordererOrgs []testutils.OrdererOrg
	for mspID, orderers := range ordererMap {
		orderer := orderers[0]

		var tlsCert, signCert *x509.Certificate
		var err error

		// Check credential store type and get certificates accordingly
		if orderer.Spec.CredentialStore == hlfv1alpha1.CredentialStoreVault {
			// For Vault credential store, get certificates from orderer status
			tlsCert, err = utils.ParseX509Certificate([]byte(orderer.Status.TlsCACert))
			if err != nil {
				return errors.Wrapf(err, "failed to parse TLS CA certificate for orderer %s", orderer.Item.Name)
			}
			signCert, err = utils.ParseX509Certificate([]byte(orderer.Status.SignCACert))
			if err != nil {
				return errors.Wrapf(err, "failed to parse Sign CA certificate for orderer %s", orderer.Item.Name)
			}
		} else {
			// For Kubernetes credential store, get certificates from CA component
			cahost := orderer.Spec.Secret.Enrollment.Component.Cahost
			certAuth, err := helpers.GetCertAuthByURL(
				clientSet,
				oclient,
				cahost,
				orderer.Spec.Secret.Enrollment.Component.Caport,
			)
			if err != nil {
				return errors.Wrapf(err, "failed to get certificate authority for orderer %s", orderer.Item.Name)
			}
			tlsCert, err = utils.ParseX509Certificate([]byte(certAuth.Status.TLSCACert))
			if err != nil {
				return errors.Wrapf(err, "failed to parse TLS CA certificate from CA %s", certAuth.Name)
			}
			signCert, err = utils.ParseX509Certificate([]byte(certAuth.Status.CACert))
			if err != nil {
				return errors.Wrapf(err, "failed to parse Sign CA certificate from CA %s", certAuth.Name)
			}
		}
		var ordererUrls []string
		for _, node := range orderers {
			ordererURL, err := helpers.GetOrdererPublicURL(clientSet, node.Item)
			if err != nil {
				return err
			}
			ordererUrls = append(
				ordererUrls,
				ordererURL,
			)
		}
		ordererOrgs = append(ordererOrgs, testutils.CreateOrdererOrg(
			mspID,
			tlsCert,
			signCert,
			ordererUrls,
		))
	}
	var peerOrgs []testutils.PeerOrg
	_, peers, err := helpers.GetClusterPeers(clientSet, oclient, ns)
	if err != nil {
		return err
	}

	// Group peers by MSP ID to avoid duplicates
	peerOrgMap := make(map[string]*helpers.ClusterPeer)
	for _, peer := range peers {
		if !utils.Contains(c.organizations, peer.Spec.MspID) {
			continue
		}
		// Use the first peer found for each MSP ID
		if _, exists := peerOrgMap[peer.Spec.MspID]; !exists {
			peerOrgMap[peer.Spec.MspID] = peer
		}
	}

	for mspID, peer := range peerOrgMap {
		var rootCert, tlsRootCert *x509.Certificate
		var err error

		// Check credential store type and get certificates accordingly
		if peer.Spec.CredentialStore == hlfv1alpha1.CredentialStoreVault {
			// For Vault credential store, get certificates from peer status
			tlsRootCert, err = utils.ParseX509Certificate([]byte(peer.Status.TlsCACert))
			if err != nil {
				return errors.Wrapf(err, "failed to parse TLS CA certificate for peer %s", peer.Name)
			}
			rootCert, err = utils.ParseX509Certificate([]byte(peer.Status.SignCACert))
			if err != nil {
				return errors.Wrapf(err, "failed to parse Sign CA certificate for peer %s", peer.Name)
			}
		} else {
			// For Kubernetes credential store, get certificates from CA component
			caHost := strings.Split(peer.Spec.Secret.Enrollment.Component.Cahost, ".")[0]
			certAuth, err := helpers.GetCertAuthByURL(
				clientSet,
				oclient,
				caHost,
				peer.Spec.Secret.Enrollment.Component.Caport,
			)
			if err != nil {
				return errors.Wrapf(err, "failed to get certificate authority for peer %s", peer.Name)
			}
			rootCert, err = utils.ParseX509Certificate([]byte(certAuth.Status.CACert))
			if err != nil {
				return errors.Wrapf(err, "failed to parse Sign CA certificate from CA %s", certAuth.Name)
			}
			tlsRootCert, err = utils.ParseX509Certificate([]byte(certAuth.Status.TLSCACert))
			if err != nil {
				return errors.Wrapf(err, "failed to parse TLS CA certificate from CA %s", certAuth.Name)
			}
		}

		peerOrgs = append(peerOrgs, testutils.CreatePeerOrg(
			mspID,
			tlsRootCert,
			rootCert,
		))
	}
	log.Infof("Peer organizations=%v", peerOrgs)
	log.Infof("Orderer organizations=%v", ordererOrgs)

	block, err := chStore.GetApplicationChannelBlock(
		ctx,
		testutils.WithName(c.channelName),
		testutils.WithOrdererOrgs(ordererOrgs...),
		testutils.WithPeerOrgs(peerOrgs...),
		testutils.WithConsenters(consenters...),
		testutils.WithBatchSize(&orderer.BatchSize{
			MaxMessageCount:   uint32(c.maxMessageCount),
			AbsoluteMaxBytes:  uint32(c.absoluteMaxBytes),
			PreferredMaxBytes: uint32(c.preferredMaxBytes),
		}),
		testutils.WithBatchTimeout(time.Duration(c.batchTimeout)*time.Second),
		testutils.WithConsensus(c.consensus),
	)
	if err != nil {
		return err
	}
	blockBytes, err := proto.Marshal(block)
	if err != nil {
		return err
	}
	err = os.WriteFile(c.output, blockBytes, 0755)
	if err != nil {
		return err
	}
	return nil
}
func newGenerateChannelCMD(io.Writer, io.Writer) *cobra.Command {
	c := &generateChannelCmd{}
	cmd := &cobra.Command{
		Use: "generate",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			return c.run()
		},
	}
	persistentFlags := cmd.PersistentFlags()
	persistentFlags.StringVarP(&c.channelName, "name", "", "", "Channel name")
	persistentFlags.StringVarP(&c.output, "output", "o", "", "Output block")
	persistentFlags.StringSliceVarP(&c.organizations, "organizations", "p", nil, "Organizations belonging to the channel")
	persistentFlags.StringSliceVarP(&c.ordererOrganizations, "ordererOrganizations", "", nil, "Orderer organizations belonging to the channel")
	persistentFlags.StringSliceVarP(&c.consenterNodes, "consenterNodes", "c", []string{}, "Consenter nodes belonging to the channel")
	persistentFlags.IntVarP(&c.maxMessageCount, "maxMessageCount", "", 100, "Max transactions per block")
	persistentFlags.IntVarP(&c.absoluteMaxBytes, "absoluteMaxBytes", "", 1024*1024, "Max size per block")
	persistentFlags.IntVarP(&c.preferredMaxBytes, "preferredMaxBytes", "", 512*1024, "Max size per block")
	persistentFlags.IntVarP(&c.batchTimeout, "batchTimeout", "", 2, "Batch timeout in seconds")
	persistentFlags.Var(hlfv1alpha1.NewConsensusTypeValue(hlfv1alpha1.OrdererConsensusEtcdraft, validConsensusTypes, &c.consensus), "consensus", fmt.Sprintf("Consensus type ( %s, %s), default etcdraft", hlfv1alpha1.OrdererConsensusBFT, hlfv1alpha1.OrdererConsensusEtcdraft))
	cmd.MarkPersistentFlagRequired("name")
	cmd.MarkPersistentFlagRequired("organizations")
	cmd.MarkPersistentFlagRequired("ordererOrganizations")
	cmd.MarkPersistentFlagRequired("output")
	return cmd
}
