package chaincode

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/kfsoftware/hlf-operator/kubectl-hlf/cmd/helpers"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

type queryApprovedCmd struct {
	configPath    string
	peer          string
	userName      string
	channelName   string
	chaincodeName string
	output        string
}

func (c *queryApprovedCmd) validate() error {
	return nil
}
func (c *queryApprovedCmd) run(out io.Writer) error {
	oclient, err := helpers.GetKubeOperatorClient()
	if err != nil {
		return err
	}
	clientSet, err := helpers.GetKubeClient()
	if err != nil {
		return err
	}
	peer, err := helpers.GetPeerByFullName(clientSet, oclient, c.peer)
	if err != nil {
		return err
	}
	mspID := peer.Spec.MspID
	peerName := peer.Name
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

	chaincode, err := resClient.LifecycleQueryApprovedCC(
		c.channelName,
		resmgmt.LifecycleQueryApprovedCCRequest{
			Name: c.chaincodeName,
		},
		resmgmt.WithTargetEndpoints(peerName),
	)
	if err != nil {
		return err
	}
	if c.output == "json" {
		b, err := json.MarshalIndent(chaincode, "", "  ")
		if err != nil {
			return err
		}
		_, err = out.Write(b)
		return err
	}
	signaturePolicyBytes, err := json.Marshal(chaincode.SignaturePolicy)
	if err != nil {
		return err
	}
	data := [][]string{
		{chaincode.Name, chaincode.PackageID, chaincode.Version, fmt.Sprint(chaincode.Sequence), string(signaturePolicyBytes)}}
	table := tablewriter.NewWriter(out)
	table.SetHeader([]string{"Chaincode", "Package ID", "Version", "Sequence", "Signature Policy"})
	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetTablePadding("\t") // pad with tabs
	table.SetNoWhiteSpace(true)
	table.AppendBulk(data) // Add Bulk Data
	table.Render()
	return nil
}
func newQueryApprovedCMD(out io.Writer, errOut io.Writer) *cobra.Command {
	c := &queryApprovedCmd{}
	cmd := &cobra.Command{
		Use: "queryapproved",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			return c.run(out)
		},
	}
	persistentFlags := cmd.PersistentFlags()
	persistentFlags.StringVarP(&c.peer, "peer", "p", "", "Peer org to invoke the updates")
	persistentFlags.StringVarP(&c.userName, "user", "", "", "User name for the transaction")
	persistentFlags.StringVarP(&c.configPath, "config", "", "", "Configuration file for the SDK")
	persistentFlags.StringVarP(&c.channelName, "channel", "C", "", "Channel name")
	persistentFlags.StringVarP(&c.chaincodeName, "chaincode", "c", "", "Chaincode label")
	persistentFlags.StringVarP(&c.output, "output", "o", "table", "Output format, can be table or json")
	cmd.MarkPersistentFlagRequired("user")
	cmd.MarkPersistentFlagRequired("peer")
	cmd.MarkPersistentFlagRequired("config")
	cmd.MarkPersistentFlagRequired("channel")
	return cmd
}
