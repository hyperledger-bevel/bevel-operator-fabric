package networkconfig

import (
	"context"
	"github.com/kfsoftware/hlf-operator/kubectl-hlf/cmd/helpers"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"io"
	"io/ioutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	networkConfigExportDesc = `
'export' command deletes a Hyperledger Fabric Network Config tenant`
	networkConfigExportExample = `  kubectl hlf networkconfig export --name org1-nc --namespace default --output=connection-org.yaml`
)

type networkConfigExportCmd struct {
	out    io.Writer
	errOut io.Writer
	name   string
	ns     string
	output string
}

func newExportNetworkConfigCmd(out io.Writer, errOut io.Writer) *cobra.Command {
	c := &networkConfigExportCmd{out: out, errOut: errOut}

	cmd := &cobra.Command{
		Use:     "export",
		Short:   "Export a Network Config CRD",
		Long:    networkConfigExportDesc,
		Example: networkConfigExportExample,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			return c.run(args)
		},
	}

	f := cmd.Flags()
	f.StringVar(&c.name, "name", "", "Name of the Network Config to export")
	f.StringVarP(&c.ns, "namespace", "n", helpers.DefaultNamespace, "Namespace scope for this request")
	f.StringVarP(&c.output, "output", "o", "", "File to write the secret")
	return cmd
}

func (d *networkConfigExportCmd) validate() error {
	if d.name == "" {
		return errors.New("--name flag is required for CA deletion")
	}
	return nil
}

func (d *networkConfigExportCmd) run(args []string) error {
	oclient, err := helpers.GetKubeOperatorClient()
	if err != nil {
		return err
	}
	clientSet, err := helpers.GetKubeClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	networkConfig, err := oclient.HlfV1alpha1().FabricNetworkConfigs(d.ns).Get(ctx, d.name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	secret, err := clientSet.CoreV1().Secrets(d.ns).Get(ctx, networkConfig.Spec.SecretName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	networkConfigBytes := secret.Data["config.yaml"]
	if d.output != "" {
		err = ioutil.WriteFile(d.output, networkConfigBytes, 0600)
		if err != nil {
			return err
		}
	} else {
		_, err = d.out.Write(networkConfigBytes)
		if err != nil {
			return err
		}
	}
	return nil
}
