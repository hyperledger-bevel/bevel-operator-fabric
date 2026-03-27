package ca

import (
	"fmt"
	"io"
	"strings"

	"github.com/kfsoftware/hlf-operator/controllers/certs"
	"github.com/kfsoftware/hlf-operator/internal/github.com/hyperledger/fabric-ca/api"
	"github.com/kfsoftware/hlf-operator/kubectl-hlf/cmd/helpers"
	"github.com/pkg/errors"
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
	Attributes   string
	CAURL        string
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
	clientSet, err := helpers.GetKubeClient()
	if err != nil {
		return err
	}
	certAuth, err := helpers.GetCertAuthByName(clientSet, oclient, c.caOpts.Name, c.caOpts.NS)
	if err != nil {
		return err
	}
	var url string
	if c.caOpts.CAURL != "" {
		url = c.caOpts.CAURL
	} else {
		url, err = helpers.GetURLForCA(certAuth)
		if err != nil {
			return err
		}
	}
	attrMap := make(map[string]string)
	attributeList := strings.Split(c.caOpts.Attributes, ",")
	for _, attr := range attributeList {
		// skipping empty attributes
		if len(attr) == 0 {
			continue
		}
		sattr := strings.SplitN(attr, "=", 2)
		if len(sattr) != 2 {
			return errors.Errorf("Attribute '%s' is missing '=' ; it "+
				"must be of the form <name>=<value>", attr)
		}
		attrMap[sattr[0]] = sattr[1]
	}
	fabricSDKAttrs, err := ConvertAttrs(attrMap)
	if err != nil {
		return err
	}
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
		Attributes:   fabricSDKAttrs,
	})
	if err != nil {
		if strings.Contains(err.Error(), "is already registered") {
			fmt.Fprintf(c.out, "User '%s' is already registered, skipping\n", c.caOpts.User)
			return nil
		}
		return err
	}
	fmt.Fprintf(c.out, "User '%s' registered successfully\n", c.caOpts.User)
	return nil
}
func newCARegisterCmd(out io.Writer, errOut io.Writer) *cobra.Command {
	c := registerCmd{out: out, errOut: errOut}
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a new identity with a Fabric Certificate Authority",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			return c.run(args)
		},
	}
	f := cmd.Flags()
	f.StringVar(&c.caOpts.Name, "name", "", "Name of the Certificate Authority in the cluster, e.g ca.default")
	f.StringVarP(&c.caOpts.NS, "namespace", "n", helpers.DefaultNamespace, "Namespace scope for this request")
	f.StringVarP(&c.caOpts.EnrollID, "enroll-id", "", "", "Enroll ID to register new users")
	f.StringVarP(&c.caOpts.EnrollSecret, "enroll-secret", "", "", "Enroll secret to register new users")
	f.StringVarP(&c.caOpts.User, "user", "", "", "Username for the new user")
	f.StringVarP(&c.caOpts.Secret, "secret", "", "", "Password for the new user")
	f.StringVarP(&c.caOpts.Type, "type", "", "", "Type of the identity to create (peer/client/orderer/admin)")
	f.StringVarP(&c.caOpts.MspID, "mspid", "", "", "MSP ID of the organization")
	f.StringVarP(&c.caOpts.Attributes, "attributes", "", "", "Attributes of the user")
	f.StringVarP(&c.caOpts.CAURL, "ca-url", "", "", "Fabric CA URL")

	return cmd
}

// ConvertAttrs converts attribute string into an Attribute object array
func ConvertAttrs(inAttrs map[string]string) ([]api.Attribute, error) {
	var outAttrs []api.Attribute
	for name, value := range inAttrs {
		sattr := strings.Split(value, ":")
		if len(sattr) > 2 {
			return []api.Attribute{}, errors.Errorf("Multiple ':' characters not allowed "+
				"in attribute specification '%s'; The attributes have been discarded!", value)
		}
		attrFlag := ""
		if len(sattr) > 1 {
			attrFlag = sattr[1]
		}
		ecert := false
		switch strings.ToLower(attrFlag) {
		case "":
		case "ecert":
			ecert = true
		default:
			return []api.Attribute{}, errors.Errorf("Invalid attribute flag: '%s'", attrFlag)
		}
		outAttrs = append(outAttrs, api.Attribute{
			Name:  name,
			Value: sattr[0],
			ECert: ecert,
		})
	}
	return outAttrs, nil
}
