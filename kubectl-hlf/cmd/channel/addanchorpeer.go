package channel

import (
	"bytes"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-config/configtx"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/resource"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/kfsoftware/hlf-operator/kubectl-hlf/cmd/helpers"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"io"
)

type addAnchorPeerCmd struct {
	configPath  string
	peer        string
	channelName string
	userName    string
}

func (c *addAnchorPeerCmd) validate() error {
	return nil
}

func uniqueAnchorPeers(anchorPeers []*peer.AnchorPeer) []*peer.AnchorPeer {
	keys := make(map[string]bool)
	var list []*peer.AnchorPeer
	for _, entry := range anchorPeers {
		key := fmt.Sprintf("%s:%d", entry.Host, entry.Port)
		if _, value := keys[key]; !value {
			keys[key] = true
			list = append(list, entry)
		}
	}
	return list
}
func (c *addAnchorPeerCmd) run() error {
	oclient, err := helpers.GetKubeOperatorClient()
	if err != nil {
		return err
	}
	configBackend := config.FromFile(c.configPath)
	sdk, err := fabsdk.New(configBackend)
	if err != nil {
		return err
	}
	clientSet, err := helpers.GetKubeClient()
	if err != nil {
		return err
	}
	adminPeer, err := helpers.GetPeerByFullName(clientSet, oclient, c.peer)
	if err != nil {
		return err
	}
	mspID := adminPeer.Spec.MspID
	org1AdminClientContext := sdk.Context(
		fabsdk.WithUser(c.userName),
		fabsdk.WithOrg(mspID),
	)
	resClient, err := resmgmt.New(org1AdminClientContext)
	if err != nil {
		return err
	}
	block, err := resClient.QueryConfigBlockFromOrderer(c.channelName)
	if err != nil {
		return err
	}
	cfgBlock, err := resource.ExtractConfigFromBlock(block)
	if err != nil {
		return err
	}
	cftxGen := configtx.New(cfgBlock)
	app := cftxGen.Application().Organization(mspID)
	peerHostName, peerPort, err := helpers.GetPeerHostAndPort(clientSet, adminPeer.Object)
	if err != nil {
		return err
	}
	anchorPeers, err := app.AnchorPeers()
	if err != nil {
		return err
	}
	log.Printf("Anchor peers %v", anchorPeers)
	anchorPeers = []configtx.Address{}
	err = app.AddAnchorPeer(configtx.Address{
		Host: peerHostName,
		Port: peerPort,
	})
	if err != nil {
		return err
	}
	configUpdateBytes, err := cftxGen.ComputeMarshaledUpdate(c.channelName)
	if err != nil {
		return err
	}
	configUpdate := &common.ConfigUpdate{}
	err = proto.Unmarshal(configUpdateBytes, configUpdate)
	if err != nil {
		return err
	}
	channelConfigBytes, err := CreateConfigUpdateEnvelope(c.channelName, configUpdate)
	if err != nil {
		return err
	}
	configUpdateReader := bytes.NewReader(channelConfigBytes)
	chResponse, err := resClient.SaveChannel(resmgmt.SaveChannelRequest{
		ChannelID:     c.channelName,
		ChannelConfig: configUpdateReader,
	})
	if err != nil {
		return err
	}
	log.Infof("anchor anchorPeers added: %s", chResponse.TransactionID)
	return nil
}
func newAddAnchorPeerCMD(io.Writer, io.Writer) *cobra.Command {
	c := &addAnchorPeerCmd{}
	cmd := &cobra.Command{
		Use: "addanchorpeer",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			return c.run()
		},
	}
	persistentFlags := cmd.PersistentFlags()
	persistentFlags.StringVarP(&c.peer, "peer", "", "", "Name of the peer to invoke the updates")
	persistentFlags.StringVarP(&c.channelName, "channel", "", "", "Channel name")
	persistentFlags.StringVarP(&c.configPath, "config", "", "", "Configuration file for the SDK")
	persistentFlags.StringVarP(&c.userName, "user", "", "", "User name for the transaction")
	cmd.MarkPersistentFlagRequired("channel")
	cmd.MarkPersistentFlagRequired("config")
	cmd.MarkPersistentFlagRequired("user")
	cmd.MarkPersistentFlagRequired("peer")
	return cmd
}

func CreateConfigUpdateEnvelope(channelID string, configUpdate *common.ConfigUpdate) ([]byte, error) {
	configUpdate.ChannelId = channelID
	configUpdateData, err := proto.Marshal(configUpdate)
	if err != nil {
		return nil, err
	}
	configUpdateEnvelope := &common.ConfigUpdateEnvelope{}
	configUpdateEnvelope.ConfigUpdate = configUpdateData
	envelope, err := protoutil.CreateSignedEnvelope(common.HeaderType_CONFIG_UPDATE, channelID, nil, configUpdateEnvelope, 0, 0)
	if err != nil {
		return nil, err
	}
	envelopeData, err := proto.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	return envelopeData, nil
}
