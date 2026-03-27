package ordorg

import (
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-config/configtx"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/resource"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/kfsoftware/hlf-operator/kubectl-hlf/cmd/helpers"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"io"
	"io/ioutil"
)

type removeOrgCmd struct {
	configPath  string
	channelName string
	userName    string
	mspID       string
	signMSPID   string
	output      string
}

func (c *removeOrgCmd) validate() error {
	return nil
}
func (c *removeOrgCmd) run(out io.Writer) error {
	mspID := c.signMSPID
	configBackend := config.FromFile(c.configPath)
	sdk, err := fabsdk.New(configBackend)
	if err != nil {
		return err
	}
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
	cftxGen.Orderer().RemoveOrganization(c.mspID)
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
func newRemoveOrgToChannelCMD(out io.Writer, errOut io.Writer) *cobra.Command {
	c := &removeOrgCmd{}
	cmd := &cobra.Command{
		Use: "del",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			return c.run(out)
		},
	}
	persistentFlags := cmd.PersistentFlags()
	persistentFlags.StringVarP(&c.channelName, "name", "", "", "Channel name")
	persistentFlags.StringVarP(&c.configPath, "config", "", "", "Configuration file for the SDK")
	persistentFlags.StringVarP(&c.userName, "user", "", "", "User name for the transaction")
	persistentFlags.StringVarP(&c.signMSPID, "config-msp-id", "", "", "MSP ID for the transaction")
	persistentFlags.StringVarP(&c.mspID, "msp-id", "", "", "MSP ID of the organization to remove")
	persistentFlags.StringVarP(&c.output, "output", "", "", "Output file")
	cmd.MarkPersistentFlagRequired("name")
	cmd.MarkPersistentFlagRequired("config")
	cmd.MarkPersistentFlagRequired("config-msp-id")
	cmd.MarkPersistentFlagRequired("msp-id")
	cmd.MarkPersistentFlagRequired("user")
	cmd.MarkPersistentFlagRequired("output")
	return cmd
}
