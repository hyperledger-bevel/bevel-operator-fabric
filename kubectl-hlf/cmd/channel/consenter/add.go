package consenter

import (
	"github.com/gogo/protobuf/proto"
	"github.com/hyperledger/fabric-config/configtx"
	"github.com/hyperledger/fabric-config/configtx/orderer"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/resource"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/kfsoftware/hlf-operator/controllers/utils"
	"github.com/kfsoftware/hlf-operator/kubectl-hlf/cmd/helpers"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"io"
	"io/ioutil"
)

type addConsenterCmd struct {
	configPath   string
	channelName  string
	userName     string
	ordNodeNames []string
	mspID        string
	output       string
}

func (c *addConsenterCmd) validate() error {
	return nil
}

func (c *addConsenterCmd) run() error {
	oClient, err := helpers.GetKubeOperatorClient()
	if err != nil {
		return err
	}
	clientSet, err := helpers.GetKubeClient()
	if err != nil {
		return err
	}
	configBackend := config.FromFile(c.configPath)
	sdk, err := fabsdk.New(configBackend)
	if err != nil {
		return err
	}
	mspID := c.mspID
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
	cfgOrd := cftxGen.Orderer()
	for _, ordNodeName := range c.ordNodeNames {
		ordNode, err := helpers.GetOrdererNodeByFullName(clientSet, oClient, ordNodeName)
		if err != nil {
			return err
		}
		tlsCert, err := utils.ParseX509Certificate([]byte(ordNode.Status.TlsCert))
		if err != nil {
			return err
		}
		ordererHostPort, err := helpers.GetOrdererHostPort(clientSet, ordNode.Item)
		if err != nil {
			return err
		}
		log.Infof("Orderer host=%s port=%d", ordererHostPort.Host, ordererHostPort.Port)
		err = cfgOrd.AddConsenter(orderer.Consenter{
			Address: orderer.EtcdAddress{
				Host: ordererHostPort.Host,
				Port: ordererHostPort.Port,
			},
			ClientTLSCert: tlsCert,
			ServerTLSCert: tlsCert,
		})
		if err != nil {
			return err
		}
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
	channelConfigBytes, err := helpers.CreateConfigUpdateEnvelope(c.channelName, configUpdate)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(c.output, channelConfigBytes, 0600)
	if err != nil {
		return err
	}
	log.Infof("output file: %s", c.output)
	return nil
}
func newAddConsenterCMD(io.Writer, io.Writer) *cobra.Command {
	c := &addConsenterCmd{}
	cmd := &cobra.Command{
		Use: "add",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			return c.run()
		},
	}
	persistentFlags := cmd.PersistentFlags()
	persistentFlags.StringVarP(&c.channelName, "channel", "", "", "Channel name")
	persistentFlags.StringVarP(&c.configPath, "config", "", "", "Configuration file for the SDK")
	persistentFlags.StringVarP(&c.mspID, "mspid", "", "", "MSP ID of the organization")
	persistentFlags.StringSliceVarP(&c.ordNodeNames, "orderers", "", []string{}, "Orderer name")
	persistentFlags.StringVarP(&c.userName, "user", "", "", "User name for the transaction")
	persistentFlags.StringVarP(&c.output, "output", "o", "", "Output block")
	cmd.MarkPersistentFlagRequired("channel")
	cmd.MarkPersistentFlagRequired("config")
	cmd.MarkPersistentFlagRequired("user")
	cmd.MarkPersistentFlagRequired("orderers")
	cmd.MarkPersistentFlagRequired("mspid")
	cmd.MarkPersistentFlagRequired("output")
	return cmd
}
