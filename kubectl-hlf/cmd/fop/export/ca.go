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

type exportCACmd struct {
	caName      string
	caNamespace string
	outFile     string
}

func (c exportCACmd) validate() error {
	if c.caNamespace == "" {
		return fmt.Errorf("--namespace is required")
	}
	if c.caName == "" {
		return fmt.Errorf("--name is required")
	}
	if c.outFile == "" {
		return fmt.Errorf("--out is required")
	}
	return nil
}
func (c exportCACmd) run(args []string) error {
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
	ca := mapFabricOperationsCA(clusterCA)
	caBytes, err := json.MarshalIndent(ca, "", "  ")
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(c.outFile, caBytes, 0600)
	if err != nil {
		return err
	}
	return nil
}
func newExportCACMD() *cobra.Command {
	c := &exportCACmd{}
	cmd := &cobra.Command{
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			return c.run(args)
		},
		Use: "ca",
	}
	persistentFlags := cmd.PersistentFlags()
	persistentFlags.StringVarP(&c.caName, "name", "", "", "Name of the CA")
	persistentFlags.StringVarP(&c.caNamespace, "namespace", "", "", "Namespace of the CA")
	persistentFlags.StringVarP(&c.outFile, "out", "p", "", "JSON Output file")
	cmd.MarkPersistentFlagRequired("name")
	cmd.MarkPersistentFlagRequired("namespace")
	cmd.MarkPersistentFlagRequired("out")
	return cmd
}
