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

type exportPeerCmd struct {
	peerName      string
	peerNamespace string
	outFile       string
}

func (c exportPeerCmd) validate() error {
	if c.peerNamespace == "" {
		return fmt.Errorf("--namespace is required")
	}
	if c.peerName == "" {
		return fmt.Errorf("--name is required")
	}
	if c.outFile == "" {
		return fmt.Errorf("--out is required")
	}
	return nil
}
func (c exportPeerCmd) run(args []string) error {
	oclient, err := helpers.GetKubeOperatorClient()
	if err != nil {
		return err
	}
	clientSet, err := helpers.GetKubeClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	fabricPeer, err := oclient.HlfV1alpha1().FabricPeers(c.peerNamespace).Get(ctx, c.peerName, v1.GetOptions{})
	if err != nil {
		return err
	}
	clusterPeer, err := helpers.MapClusterPeer(clientSet, *fabricPeer)
	if err != nil {
		return err
	}
	opPeer, err := mapFabricOperationsPeer(clusterPeer)
	if err != nil {
		return err
	}
	peerBytes, err := json.MarshalIndent(opPeer, "", "  ")
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(c.outFile, peerBytes, 0600)
	if err != nil {
		return err
	}
	return nil
}
func newExportPeerCMD() *cobra.Command {
	c := &exportPeerCmd{}
	cmd := &cobra.Command{
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			return c.run(args)
		},
		Use: "peer",
	}
	persistentFlags := cmd.PersistentFlags()
	persistentFlags.StringVarP(&c.peerName, "name", "", "", "Name of the Peer")
	persistentFlags.StringVarP(&c.peerNamespace, "namespace", "", "", "Namespace of the Peer")
	persistentFlags.StringVarP(&c.outFile, "out", "p", "", "JSON Output file")
	cmd.MarkPersistentFlagRequired("name")
	cmd.MarkPersistentFlagRequired("namespace")
	cmd.MarkPersistentFlagRequired("out")
	return cmd
}
