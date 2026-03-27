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

type exportOrdererCmd struct {
	ordererName      string
	ordererNamespace string
	outFile          string
	clusterName      string
	clusterID        string
}

func (c exportOrdererCmd) validate() error {
	if c.ordererNamespace == "" {
		return fmt.Errorf("--namespace is required")
	}
	if c.ordererName == "" {
		return fmt.Errorf("--name is required")
	}
	if c.outFile == "" {
		return fmt.Errorf("--out is required")
	}
	if c.clusterName == "" {
		return fmt.Errorf("--cluster-name is required")
	}
	if c.clusterID == "" {
		return fmt.Errorf("--cluster-id is required")
	}
	return nil
}
func (c exportOrdererCmd) run(args []string) error {
	oclient, err := helpers.GetKubeOperatorClient()
	if err != nil {
		return err
	}
	clientSet, err := helpers.GetKubeClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	fabricOrderer, err := oclient.HlfV1alpha1().FabricOrdererNodes(c.ordererNamespace).Get(ctx, c.ordererName, v1.GetOptions{})
	if err != nil {
		return err
	}
	clusterOrderer, err := helpers.MapClusterOrdererNode(clientSet, *fabricOrderer)
	if err != nil {
		return err
	}
	ordererHostName, adminPort, err := helpers.GetOrdererAdminHostAndPort(clientSet, fabricOrderer.Spec, fabricOrderer.Status)
	if err != nil {
		return err
	}

	osnUrl := fmt.Sprintf("https://%s:%d", ordererHostName, adminPort)
	opOrderer, err := mapFabricOperationsOrderer(clusterOrderer, MapFabricOperationsOrderer{
		ClusterID:   c.clusterID,
		ClusterName: c.clusterName,
		OSNAdminURL: osnUrl,
	})
	if err != nil {
		return err
	}
	ordererBytes, err := json.MarshalIndent(opOrderer, "", "  ")
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(c.outFile, ordererBytes, 0600)
	if err != nil {
		return err
	}
	return nil
}
func newExportOrdererCMD() *cobra.Command {
	c := &exportOrdererCmd{}
	cmd := &cobra.Command{
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			return c.run(args)
		},
		Use: "orderer",
	}
	persistentFlags := cmd.PersistentFlags()
	persistentFlags.StringVarP(&c.ordererName, "name", "", "", "Name of the Orderer")
	persistentFlags.StringVarP(&c.ordererNamespace, "namespace", "", "", "Namespace of the Orderer")
	persistentFlags.StringVarP(&c.clusterID, "cluster-id", "", "", "Cluster ID for the console")
	persistentFlags.StringVarP(&c.clusterName, "cluster-name", "", "", "Cluster Name for the console")
	persistentFlags.StringVarP(&c.outFile, "out", "p", "", "JSON Output file")
	cmd.MarkPersistentFlagRequired("name")
	cmd.MarkPersistentFlagRequired("namespace")
	cmd.MarkPersistentFlagRequired("out")
	return cmd
}
