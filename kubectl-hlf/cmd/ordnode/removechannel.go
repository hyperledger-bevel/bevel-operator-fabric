package ordnode

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/kfsoftware/hlf-operator/kubectl-hlf/cmd/helpers"
	"github.com/kfsoftware/hlf-operator/kubectl-hlf/cmd/helpers/osnadmin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"io"
	"io/ioutil"
	"sigs.k8s.io/yaml"
)

type removeChannelCmd struct {
	channel   string
	name      string
	namespace string
	identity  string
}

func (c *removeChannelCmd) validate() error {
	if c.namespace == "" {
		return errors.Errorf("--namespace is required")
	}
	if c.name == "" {
		return errors.Errorf("--name is required")
	}
	if c.identity == "" {
		return errors.Errorf("--identity is required")
	}
	if c.channel == "" {
		return errors.Errorf("--channel is required")
	}
	return nil
}
func (c *removeChannelCmd) run() error {
	clientSet, err := helpers.GetKubeClient()
	if err != nil {
		return err
	}
	hlfClient, err := helpers.GetKubeOperatorClient()
	if err != nil {
		return err
	}
	log.Printf("name=%s namespace=%s", c.name, c.namespace)
	ordererNode, err := helpers.GetOrdererNodeByFullName(clientSet, hlfClient, fmt.Sprintf("%s.%s", c.name, c.namespace))
	if err != nil {
		return err
	}
	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM([]byte(ordererNode.Status.TlsCert))
	if !ok {
		return errors.Errorf("failed to add certificate")
	}
	adminTlsCert := ordererNode.Status.TlsAdminCert
	ok = certPool.AppendCertsFromPEM([]byte(adminTlsCert))
	if !ok {
		return errors.Errorf("failed to add certificate")
	}
	identityBytes, err := ioutil.ReadFile(c.identity)
	if err != nil {
		return err
	}
	id := &identity{}
	err = yaml.Unmarshal(identityBytes, id)
	if err != nil {
		return err
	}
	tlsClientCert, err := tls.X509KeyPair(
		[]byte(id.Cert.Pem),
		[]byte(id.Key.Pem),
	)
	if err != nil {
		return err
	}
	ordererHostName, adminPort, err := helpers.GetOrdererAdminHostAndPort(clientSet, ordererNode.Item)
	if err != nil {
		return err
	}
	osnUrl := fmt.Sprintf("https://%s:%d", ordererHostName, adminPort)
	log.Infof("Removing channel %s from %s", c.channel, osnUrl)
	chResponse, err := osnadmin.Remove(osnUrl, c.channel, certPool, tlsClientCert)
	if err != nil {
		return err
	}
	defer chResponse.Body.Close()
	log.Infof("Status code=%d", chResponse.StatusCode)
	if chResponse.StatusCode != 204 {
		return errors.Errorf("error removing channel, got status code=%d", chResponse.StatusCode)
	}
	return nil
}

func newRemoveChannelCMD(io.Writer, io.Writer) *cobra.Command {
	c := &removeChannelCmd{}
	cmd := &cobra.Command{
		Use: "removechannel",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			return c.run()
		},
	}
	persistentFlags := cmd.PersistentFlags()
	persistentFlags.StringVarP(&c.identity, "identity", "", "", "Admin org to invoke the updates")
	persistentFlags.StringVarP(&c.channel, "channel", "", "", "Channel name to remove from the OSN")
	persistentFlags.StringVarP(&c.name, "name", "", "", "Orderer Service name")
	persistentFlags.StringVarP(&c.namespace, "namespace", "", "default", "Namespace scope for this request")
	cmd.MarkPersistentFlagRequired("identity")
	cmd.MarkPersistentFlagRequired("channel")
	cmd.MarkPersistentFlagRequired("name")
	cmd.MarkPersistentFlagRequired("namespace")
	return cmd
}
