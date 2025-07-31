package chaincode

import (
	"encoding/json"
	"io"

	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/kfsoftware/hlf-operator/kubectl-hlf/cmd/helpers"
	"github.com/olekukonko/tablewriter"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type queryInstalledCmd struct {
	configPath string
	peer       string
	userName   string
	mspID      string
	output     string
}

func (c *queryInstalledCmd) validate() error {
	return nil
}
func (c *queryInstalledCmd) run(out io.Writer) error {
	var mspID string
	if c.mspID != "" {
		mspID = c.mspID
	} else {
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
		mspID = peer.Spec.MspID
	}
	peerName := c.peer
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

	chaincodes, err := resClient.LifecycleQueryInstalledCC(
		resmgmt.WithTargetEndpoints(peerName),
	)
	if err != nil {
		return err
	}
	if len(chaincodes) == 0 {
		log.Infof("No chaincodes installed")
		return nil
	}
	if c.output == "json" {
		b, err := json.MarshalIndent(chaincodes, "", "  ")
		if err != nil {
			return err
		}
		_, err = out.Write(b)
		return err
	}
	var data [][]string
	for _, chaincode := range chaincodes {
		referencesJson, err := json.Marshal(chaincode.References)
		if err != nil {
			return err
		}
		data = append(data, []string{
			chaincode.PackageID, chaincode.Label, string(referencesJson),
		})
	}
	table := tablewriter.NewWriter(out)
	table.SetHeader([]string{"Package ID", "Label", "References"})
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
func newChaincodeQueryInstalledCMD(out io.Writer, errOut io.Writer) *cobra.Command {
	c := &queryInstalledCmd{}
	cmd := &cobra.Command{
		Use: "queryinstalled",
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
	persistentFlags.StringVarP(&c.mspID, "mspID", "", "", "MSP ID of the peer")
	persistentFlags.StringVarP(&c.output, "output", "o", "table", "Output format, can be table or json")
	cmd.MarkPersistentFlagRequired("user")
	cmd.MarkPersistentFlagRequired("peer")
	cmd.MarkPersistentFlagRequired("config")
	return cmd
}
