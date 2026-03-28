package mainchannel

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net"
	"strconv"
	"strings"

	"github.com/kfsoftware/hlf-operator/controllers/utils"
	"github.com/kfsoftware/hlf-operator/kubectl-hlf/cmd/helpers"
	"github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Options struct {
	Name                         string
	Output                       bool
	Capabilities                 []string
	BatchTimeout                 string
	MaxMessageCount              int
	AbsoluteMaxBytes             int
	PreferredMaxBytes            int
	EtcdRaftTickInterval         string
	EtcdRaftElectionTick         int
	EtcdRaftHeartbeatTick        int
	EtcdRaftMaxInflightBlocks    int
	EtcdRaftSnapshotIntervalSize int
	ChannelName                  string
	AdminPeerOrgs                []string
	AdminOrdererOrgs             []string
	PeerOrgs                     []string
	OrdererOrgs                  []string
	Consenters                   []string
	ConsenterCertificates        []string
	SecretName                   string
	SecretNS                     string
	Identities                   []string
}

func (o Options) mapToFabricMainChannel() (*v1alpha1.FabricMainChannelSpec, error) {
	oclient, err := helpers.GetKubeOperatorClient()
	if err != nil {
		return nil, err
	}
	clientSet, err := helpers.GetKubeClient()
	if err != nil {
		return nil, err
	}
	identities := map[string]v1alpha1.FabricMainChannelIdentity{}
	for _, identity := range o.Identities {
		chunks := strings.Split(identity, ";")
		if len(chunks) != 2 {
			return nil, fmt.Errorf("invalid identity %s, example format <msp_id>;<secret_key>", identity)
		}
		mspID := chunks[0]
		secretKey := chunks[1]
		identities[mspID] = v1alpha1.FabricMainChannelIdentity{
			SecretName:      o.SecretName,
			SecretNamespace: o.SecretNS,
			SecretKey:       secretKey,
		}

	}
	ordererOrganizations := []v1alpha1.FabricMainChannelOrdererOrganization{}
	adminPeerOrganizations := []v1alpha1.FabricMainChannelAdminPeerOrganizationSpec{}
	peerOrganizations := []v1alpha1.FabricMainChannelPeerOrganization{}
	adminOrdererOrganizations := []v1alpha1.FabricMainChannelAdminOrdererOrganizationSpec{}
	externalOrdererOrganizations := []v1alpha1.FabricMainChannelExternalOrdererOrganization{}
	consenters := []v1alpha1.FabricMainChannelConsenter{}
	ns := ""
	orderers, err := helpers.GetClusterOrdererNodes(clientSet, oclient, ns)
	if err != nil {
		return nil, err
	}
	ordererMap := map[string][]*helpers.ClusterOrdererNode{}
	for _, orderer := range orderers {
		if !utils.Contains(o.OrdererOrgs, orderer.Spec.MspID) {
			continue
		}
		_, ok := ordererMap[orderer.Spec.MspID]
		if !ok {
			ordererMap[orderer.Spec.MspID] = []*helpers.ClusterOrdererNode{}
		}
		ordererMap[orderer.Spec.MspID] = append(ordererMap[orderer.Spec.MspID], orderer)
	}
	for idx, consenter := range o.Consenters {
		host, port, err := net.SplitHostPort(consenter)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid consenter %s", consenter)
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid port %s", port)
		}
		if len(o.ConsenterCertificates) <= idx {
			return nil, fmt.Errorf("missing consenter certificate for %s", consenter)
		}
		consenterCRT := o.ConsenterCertificates[idx]
		consenterCRTContents, err := ioutil.ReadFile(consenterCRT)
		if err != nil {
			return nil, errors.Wrapf(err, "error reading consenter certificate %s", consenterCRT)
		}
		consenters = append(consenters, v1alpha1.FabricMainChannelConsenter{
			Host:    host,
			Port:    portNumber,
			TLSCert: string(consenterCRTContents),
		})
	}
	for mspID, nodes := range ordererMap {
		node := nodes[0]
		var ordererEndpoints []string
		for _, ordererNode := range nodes {
			ordererHost, ordererPort, err := helpers.GetOrdererHostAndPort(clientSet, ordererNode.Spec, ordererNode.Status)
			if err != nil {
				return nil, err
			}
			ordererEndpoints = append(ordererEndpoints, fmt.Sprintf("%s:%d", ordererHost, ordererPort))
		}
		tlsCACert := node.Status.TlsCACert
		signCACert := node.Status.SignCACert
		ordererNodes := []v1alpha1.FabricMainChannelExternalOrdererNode{}
		channelOrdererNodes := []v1alpha1.FabricMainChannelOrdererNode{}
		for _, ordererNode := range nodes {
			namespace := ordererNode.Item.Namespace
			if namespace == "" {
				namespace = "default"
			}
			channelOrdererNodes = append(channelOrdererNodes, v1alpha1.FabricMainChannelOrdererNode{
				Name:      ordererNode.Item.Name,
				Namespace: namespace,
			})
		}
		ordererOrganizations = append(ordererOrganizations, v1alpha1.FabricMainChannelOrdererOrganization{
			MSPID:                  mspID,
			TLSCACert:              tlsCACert,
			SignCACert:             signCACert,
			OrdererEndpoints:       ordererEndpoints,
			OrderersToJoin:         channelOrdererNodes,
			ExternalOrderersToJoin: ordererNodes,
		})
	}
	for _, adminPeerOrg := range o.AdminPeerOrgs {
		adminPeerOrganizations = append(adminPeerOrganizations, v1alpha1.FabricMainChannelAdminPeerOrganizationSpec{
			MSPID: adminPeerOrg,
		})
	}
	externalPeerOrganizations := []v1alpha1.FabricMainChannelExternalPeerOrganization{}
	peerOrgs, _, err := helpers.GetClusterPeers(clientSet, oclient, ns)
	if err != nil {
		return nil, err
	}
	for _, peerOrg := range peerOrgs {
		if len(peerOrg.Peers) == 0 {
			return nil, fmt.Errorf("no peers found for organization %s", peerOrg.MspID)
		}
		if !utils.Contains(o.PeerOrgs, peerOrg.MspID) {
			continue
		}
		firstPeer := peerOrg.Peers[0]
		externalPeerOrganizations = append(externalPeerOrganizations, v1alpha1.FabricMainChannelExternalPeerOrganization{
			MSPID:        peerOrg.MspID,
			TLSRootCert:  firstPeer.Status.TlsCACert,
			SignRootCert: firstPeer.Status.SignCACert,
		})
	}
	for _, adminOrdererOrgMSPID := range o.AdminOrdererOrgs {
		adminOrdererOrganizations = append(adminOrdererOrganizations, v1alpha1.FabricMainChannelAdminOrdererOrganizationSpec{
			MSPID: adminOrdererOrgMSPID,
		})
	}

	channelConfig := &v1alpha1.FabricMainChannelConfig{
		Application: &v1alpha1.FabricMainChannelApplicationConfig{
			Capabilities: o.Capabilities,
			Policies:     nil,
			ACLs:         nil,
		},
		Orderer: &v1alpha1.FabricMainChannelOrdererConfig{
			OrdererType:  "etcdraft",
			Capabilities: o.Capabilities,
			Policies:     nil,
			BatchTimeout: o.BatchTimeout,
			BatchSize: &v1alpha1.FabricMainChannelOrdererBatchSize{
				MaxMessageCount:   o.MaxMessageCount,
				AbsoluteMaxBytes:  o.AbsoluteMaxBytes,
				PreferredMaxBytes: o.PreferredMaxBytes,
			},
			State: "STATE_NORMAL",
			EtcdRaft: &v1alpha1.FabricMainChannelEtcdRaft{
				Options: &v1alpha1.FabricMainChannelEtcdRaftOptions{
					TickInterval:         o.EtcdRaftTickInterval,
					ElectionTick:         safeUint32(o.EtcdRaftElectionTick),
					HeartbeatTick:        safeUint32(o.EtcdRaftHeartbeatTick),
					MaxInflightBlocks:    safeUint32(o.EtcdRaftMaxInflightBlocks),
					SnapshotIntervalSize: safeUint32(o.EtcdRaftSnapshotIntervalSize),
				},
			},
		},
		Capabilities: o.Capabilities,
		Policies:     nil,
	}
	fabricMainChannelSpec := &v1alpha1.FabricMainChannelSpec{
		Name:                         o.ChannelName,
		Identities:                   identities,
		AdminPeerOrganizations:       adminPeerOrganizations,
		PeerOrganizations:            peerOrganizations,
		ExternalPeerOrganizations:    externalPeerOrganizations,
		ChannelConfig:                channelConfig,
		AdminOrdererOrganizations:    adminOrdererOrganizations,
		OrdererOrganizations:         ordererOrganizations,
		ExternalOrdererOrganizations: externalOrdererOrganizations,
		Consenters:                   consenters,
	}
	return fabricMainChannelSpec, nil
}
func (o Options) Validate() error {
	if o.Name == "" {
		return fmt.Errorf("--name is required")
	}
	if o.SecretName == "" {
		return fmt.Errorf("--secret-name is required")
	}
	if o.SecretNS == "" {
		return fmt.Errorf("--secret-ns is required")
	}
	if len(o.Identities) == 0 {
		return fmt.Errorf("--identities is required")
	}
	if len(o.AdminPeerOrgs) == 0 {
		return fmt.Errorf("--admin-peer-orgs is required")
	}
	if len(o.AdminOrdererOrgs) == 0 {
		return fmt.Errorf("--admin-orderer-orgs is required")
	}
	if len(o.OrdererOrgs) == 0 {
		return fmt.Errorf("--orderer-orgs is required")
	}
	if len(o.PeerOrgs) == 0 {
		return fmt.Errorf("--peer-orgs is required")
	}
	if len(o.Consenters) == 0 {
		return fmt.Errorf("--consenters is required")
	}
	if len(o.ConsenterCertificates) == 0 {
		return fmt.Errorf("--consenter-certificates is required")
	}
	if o.BatchTimeout == "" {
		return fmt.Errorf("--batch-timeout is required")
	}
	if o.EtcdRaftTickInterval == "" {
		return fmt.Errorf("--etcdraft-tick-interval is required")
	}
	if o.ChannelName == "" {
		return fmt.Errorf("--channel-name is required")
	}
	if len(o.Capabilities) == 0 {
		return fmt.Errorf("--capabilities is required")
	}
	if o.MaxMessageCount == 0 {
		return fmt.Errorf("--max-message-count is required")
	}
	if o.AbsoluteMaxBytes == 0 {
		return fmt.Errorf("--absolute-max-bytes is required")
	}
	return nil
}

type createCmd struct {
	out         io.Writer
	errOut      io.Writer
	channelOpts Options
}

func (c *createCmd) validate() error {
	return c.channelOpts.Validate()
}
func (c *createCmd) run() error {
	oclient, err := helpers.GetKubeOperatorClient()
	if err != nil {
		return err
	}
	fabricMainChannelSpec, err := c.channelOpts.mapToFabricMainChannel()
	if err != nil {
		return err
	}
	fabricMainChannel := &v1alpha1.FabricMainChannel{
		TypeMeta: v1.TypeMeta{
			Kind:       "FabricMainChannel",
			APIVersion: v1alpha1.GroupVersion.String(),
		},
		ObjectMeta: v1.ObjectMeta{
			Name: c.channelOpts.Name,
		},
		Spec: *fabricMainChannelSpec,
	}
	if c.channelOpts.Output {
		ot, err := helpers.MarshallWithoutStatus(&fabricMainChannel)
		if err != nil {
			return err
		}
		fmt.Println(string(ot))
	} else {
		ctx := context.Background()
		_, err = oclient.HlfV1alpha1().FabricMainChannels().Create(
			ctx,
			fabricMainChannel,
			v1.CreateOptions{},
		)
		if err != nil {
			return err
		}
		log.Infof("MainChannel %s created on namespace %s", fabricMainChannel.Name, fabricMainChannel.Namespace)
	}
	return nil
}
func newCreateMainChannelCmd(out io.Writer, errOut io.Writer) *cobra.Command {
	c := createCmd{out: out, errOut: errOut}
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a main channel",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			return c.run()
		},
	}
	f := cmd.Flags()
	f.StringVar(&c.channelOpts.Name, "name", "", "Name of the Fabric Console to create")
	f.StringSliceVar(&c.channelOpts.Capabilities, "capabilities", []string{"V2_0"}, "Capabilities of the channel")
	f.StringSliceVar(&c.channelOpts.AdminPeerOrgs, "admin-peer-orgs", []string{}, "MSP IDs of the admin peer organizations")
	f.StringSliceVar(&c.channelOpts.AdminOrdererOrgs, "admin-orderer-orgs", []string{}, "MSP IDs of the admin orderer organizations")
	f.StringSliceVar(&c.channelOpts.OrdererOrgs, "orderer-orgs", []string{}, "MSP IDs of the orderer organizations")
	f.StringSliceVar(&c.channelOpts.PeerOrgs, "peer-orgs", []string{}, "MSP IDs of the peer organizations")
	f.StringSliceVar(&c.channelOpts.Consenters, "consenters", []string{}, "Consenters of the channel")
	f.StringSliceVar(&c.channelOpts.ConsenterCertificates, "consenter-certificates", []string{}, "Consenter certificates of the channel")

	f.StringVar(&c.channelOpts.ChannelName, "channel-name", "mychannel", "Name of the channel")
	f.StringVar(&c.channelOpts.BatchTimeout, "batch-timeout", "2s", "Batch timeout")
	f.IntVar(&c.channelOpts.MaxMessageCount, "max-message-count", 10, "Max message count")
	f.IntVar(&c.channelOpts.AbsoluteMaxBytes, "absolute-max-bytes", 1048576, "Absolute max bytes")
	f.IntVar(&c.channelOpts.PreferredMaxBytes, "preferred-max-bytes", 524288, "Preferred max bytes")
	f.StringVar(&c.channelOpts.EtcdRaftTickInterval, "etcd-raft-tick-interval", "500ms", "Etcd raft tick interval")
	f.IntVar(&c.channelOpts.EtcdRaftElectionTick, "etcd-raft-election-tick", 10, "Etcd raft election tick")
	f.IntVar(&c.channelOpts.EtcdRaftHeartbeatTick, "etcd-raft-heartbeat-tick", 1, "Etcd raft heartbeat tick")
	f.IntVar(&c.channelOpts.EtcdRaftMaxInflightBlocks, "etcd-raft-max-inflight-blocks", 5, "Etcd raft max inflight blocks")
	f.IntVar(&c.channelOpts.EtcdRaftSnapshotIntervalSize, "etcd-raft-snapshot-interval-size", 16777216, "Etcd raft snapshot interval size")

	f.StringVar(&c.channelOpts.SecretName, "secret-name", "", "Secret name for the identities")
	f.StringVar(&c.channelOpts.SecretNS, "secret-ns", "", "Secret namespace for the identities")
	f.StringSliceVar(&c.channelOpts.Identities, "identities", []string{}, "Identity map")

	f.BoolVarP(&c.channelOpts.Output, "output", "o", false, "Output in yaml")
	return cmd
}

func safeUint32(v int) uint32 {
	if v < 0 {
		return 0
	}
	if v > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(v) // #nosec G115 -- bounds checked above
}
