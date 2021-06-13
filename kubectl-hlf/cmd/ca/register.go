package ca

import (
	"fmt"
	"io"

	"github.com/kfsoftware/hlf-operator/controllers/certs"
	"github.com/kfsoftware/hlf-operator/controllers/utils"
	"github.com/kfsoftware/hlf-operator/kubectl-hlf/cmd/helpers"
	"github.com/spf13/cobra"
)

type RegisterOptions struct {
	Name         string
	NS           string
	User         string
	Secret       string
	Type         string
	MspID        string
	EnrollID     string
	EnrollSecret string
}

func (o RegisterOptions) Validate() error {
	return nil
}

type registerCmd struct {
	out    io.Writer
	errOut io.Writer
	caOpts RegisterOptions
}

func (c *registerCmd) validate() error {
	return c.caOpts.Validate()
}
func (c *registerCmd) run(args []string) error {
	oclient, err := helpers.GetKubeOperatorClient()
	if err != nil {
		return err
	}
	certAuth, err := helpers.GetCertAuthByName(oclient, c.caOpts.Name, c.caOpts.NS)
	if err != nil {
		return err
	}
	client, err := helpers.GetKubeClient()
	if err != nil {
		return err
	}
	ip, err := utils.GetPublicIPKubernetes(client)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("https://%s:%d", ip, certAuth.Status.NodePort)
	_, err = certs.RegisterUser(certs.RegisterUserRequest{
		TLSCert:      certAuth.Status.TlsCert,
		URL:          url,
		Name:         "",
		MSPID:        c.caOpts.MspID,
		EnrollID:     c.caOpts.EnrollID,
		EnrollSecret: c.caOpts.EnrollSecret,
		User:         c.caOpts.User,
		Secret:       c.caOpts.Secret,
		Type:         c.caOpts.Type,
		Attributes:   nil,
	})
	if err != nil {
		return err
	}
	return nil
}
func newCARegisterCmd(out io.Writer, errOut io.Writer) *cobra.Command {
	c := registerCmd{out: out, errOut: errOut}
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Create a Fabric Certificate authority",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			return c.run(args)
		},
	}
	f := cmd.Flags()
	f.StringVar(&c.caOpts.Name, "name", "", "name of the Certificate Authority in the cluster, e.g ca.default")
	f.StringVarP(&c.caOpts.NS, "namespace", "n", helpers.DefaultNamespace, "namespace scope for this request")
	f.StringVarP(&c.caOpts.EnrollID, "enroll-id", "", "", "namespace scope for this request")
	f.StringVarP(&c.caOpts.EnrollSecret, "enroll-secret", "", "", "namespace scope for this request")
	f.StringVarP(&c.caOpts.User, "user", "", "", "namespace scope for this request")
	f.StringVarP(&c.caOpts.Secret, "secret", "", "", "namespace scope for this request")
	f.StringVarP(&c.caOpts.Type, "type", "", "", "namespace scope for this request")
	f.StringVarP(&c.caOpts.MspID, "mspid", "", "", "namespace scope for this request")

	return cmd
}
