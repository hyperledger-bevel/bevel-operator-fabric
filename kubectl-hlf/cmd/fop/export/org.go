package export

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/kfsoftware/hlf-operator/kubectl-hlf/cmd/helpers"
	"github.com/spf13/cobra"
	"io/ioutil"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type exportOrgCmd struct {
	caName      string
	caNamespace string
	outFile     string
	hostURL     string
	mspID       string
}

func (c exportOrgCmd) validate() error {
	if c.caNamespace == "" {
		return fmt.Errorf("--namespace is required")
	}
	if c.caName == "" {
		return fmt.Errorf("--name is required")
	}
	if c.outFile == "" {
		return fmt.Errorf("--out is required")
	}
	if c.mspID == "" {
		return fmt.Errorf("--msp-id is required")
	}
	if c.hostURL == "" {
		return fmt.Errorf("--host-url is required")
	}
	return nil
}
func (c exportOrgCmd) run(args []string) error {
	oclient, err := helpers.GetKubeOperatorClient()
	if err != nil {
		return err
	}
	clientSet, err := helpers.GetKubeClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	fabricCA, err := oclient.HlfV1alpha1().FabricCAs(c.caNamespace).Get(ctx, c.caName, v1.GetOptions{})
	if err != nil {
		return err
	}
	clusterCA, err := helpers.MapClusterCA(clientSet, *fabricCA)
	if err != nil {
		return err
	}
	opOrg, err := mapFabricOperationsOrg(clusterCA, MapFabricOperationsOrg{
		MSPID:   c.mspID,
		HostURL: c.hostURL,
	})
	if err != nil {
		return err
	}
	caBytes, err := json.MarshalIndent(opOrg, "", "  ")
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(c.outFile, caBytes, 0600)
	if err != nil {
		return err
	}
	return nil
}
func newExportOrgCMD() *cobra.Command {
	c := &exportOrgCmd{}
	cmd := &cobra.Command{
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			return c.run(args)
		},
		Use: "org",
	}
	persistentFlags := cmd.PersistentFlags()
	persistentFlags.StringVarP(&c.caName, "name", "", "", "Name of the Org")
	persistentFlags.StringVarP(&c.caNamespace, "namespace", "", "", "Namespace of the Org")
	persistentFlags.StringVarP(&c.outFile, "out", "p", "", "JSON Output file")
	persistentFlags.StringVarP(&c.mspID, "msp-id", "m", "", "MSP ID of the Org")
	persistentFlags.StringVarP(&c.hostURL, "host-url", "u", "", "URL of the Fabric Console")
	cmd.MarkPersistentFlagRequired("name")
	cmd.MarkPersistentFlagRequired("namespace")
	cmd.MarkPersistentFlagRequired("out")
	cmd.MarkPersistentFlagRequired("msp-id")
	cmd.MarkPersistentFlagRequired("host-url")
	return cmd
}
