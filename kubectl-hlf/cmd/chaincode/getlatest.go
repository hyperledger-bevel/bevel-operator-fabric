package chaincode

import (
	"io"
	"io/ioutil"
	"strconv"

	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type getLatestInfoCmd struct {
	configPath  string
	userName    string
	channelName string
	name        string
	mspID       string
	property    string
	outFile     string
	peer        string
}

func (c *getLatestInfoCmd) validate() error {
	if c.property != "version" && c.property != "sequence" {
		return errors.New("property must be either version or sequence")
	}
	if c.outFile == "" {
		return errors.New("output file is required")
	}
	return nil
}
func (c *getLatestInfoCmd) run(out io.Writer, stdErr io.Writer) error {
	mspID := c.mspID
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
	resmgmtOptions := []resmgmt.RequestOption{}
	if c.peer != "" {
		resmgmtOptions = append(resmgmtOptions, resmgmt.WithTargetEndpoints(c.peer))
	}
	committedCCs, err := resClient.LifecycleQueryCommittedCC(
		c.channelName,
		resmgmt.LifecycleQueryCommittedCCRequest{Name: c.name},
		resmgmtOptions...,
	)
	if err != nil {
		return err
	}
	if len(committedCCs) == 0 {
		return errors.New("no chaincode found")
	}
	latestCC := committedCCs[len(committedCCs)-1]
	var data []byte
	if c.property == "version" {
		data = []byte(latestCC.Version)
	} else {
		data = []byte(strconv.FormatInt(latestCC.Sequence, 10))
	}
	err = ioutil.WriteFile(c.outFile, data, 0600)
	if err != nil {
		return err
	}
	return nil
}
func newGetLatestInfoCMD(out io.Writer, errOut io.Writer) *cobra.Command {
	c := &getLatestInfoCmd{}
	cmd := &cobra.Command{
		Use: "getlatest",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			return c.run(out, errOut)
		},
	}
	persistentFlags := cmd.PersistentFlags()
	persistentFlags.StringVarP(&c.configPath, "config", "", "", "Configuration file for the SDK")
	persistentFlags.StringVarP(&c.userName, "user", "", "", "User name for the transaction")
	persistentFlags.StringVarP(&c.channelName, "channel", "", "", "Channel name")
	persistentFlags.StringVarP(&c.name, "name", "", "", "Chaincode name")
	persistentFlags.StringVarP(&c.mspID, "msp-id", "", "", "MSP ID of the organization")
	persistentFlags.StringVarP(&c.property, "property", "", "", "Property to get(\"version\" or \"sequence\")")
	persistentFlags.StringVarP(&c.outFile, "out", "o", "", "File to write the property to")
	persistentFlags.StringVarP(&c.peer, "peer", "p", "", "Peer org to invoke the updates")

	cmd.MarkPersistentFlagRequired("user")
	cmd.MarkPersistentFlagRequired("config")
	cmd.MarkPersistentFlagRequired("channel")
	cmd.MarkPersistentFlagRequired("name")
	cmd.MarkPersistentFlagRequired("msp-id")
	cmd.MarkPersistentFlagRequired("out")
	return cmd
}
