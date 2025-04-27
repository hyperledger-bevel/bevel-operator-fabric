package identity

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/kfsoftware/hlf-operator/kubectl-hlf/cmd/helpers"
	"github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/spf13/cobra"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type updateIdentityCmd struct {
	name         string
	namespace    string
	caName       string
	caNamespace  string
	ca           string
	mspID        string
	enrollId     string
	enrollSecret string
}

func (c *updateIdentityCmd) validate() error {
	if c.name == "" {
		return fmt.Errorf("--name is required")
	}
	if c.namespace == "" {
		return fmt.Errorf("--namespace is required")
	}
	if c.mspID == "" {
		return fmt.Errorf("--mspid is required")
	}
	if c.ca == "" {
		return fmt.Errorf("--ca is required")
	}
	if c.caName == "" {
		return fmt.Errorf("--ca-name is required")
	}
	if c.caNamespace == "" {
		return fmt.Errorf("--ca-namespace is required")
	}
	if c.enrollId == "" {
		return fmt.Errorf("--enroll-id is required")
	}
	if c.enrollSecret == "" {
		return fmt.Errorf("--enroll-secret is required")
	}
	return nil
}
func (c *updateIdentityCmd) run() error {
	oclient, err := helpers.GetKubeOperatorClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	clientSet, err := helpers.GetKubeClient()
	if err != nil {
		return err
	}
	fabricCA, err := helpers.GetCertAuthByName(
		clientSet,
		oclient,
		c.caName,
		c.caNamespace,
	)
	if err != nil {
		return err
	}
	fabricIdentitySpec := v1alpha1.FabricIdentitySpec{
		Caname: c.ca,
		Cahost: fabricCA.Name,
		Caport: 7054,
		Catls: &v1alpha1.Catls{
			Cacert: base64.StdEncoding.EncodeToString([]byte(fabricCA.Status.TlsCert)),
		},
		Enrollid:     c.enrollId,
		Enrollsecret: c.enrollSecret,
		MSPID:        c.mspID,
	}
	fabricIdentity := &v1alpha1.FabricIdentity{
		ObjectMeta: v1.ObjectMeta{
			Name:      c.name,
			Namespace: c.namespace,
		},
		Spec: fabricIdentitySpec,
	}
	fabricIdentity, err = oclient.HlfV1alpha1().FabricIdentities(c.namespace).Update(
		ctx,
		fabricIdentity,
		v1.UpdateOptions{},
	)
	if err != nil {
		return err
	}
	fmt.Printf("Updated hlf identity %s/%s\n", fabricIdentity.Name, fabricIdentity.Namespace)
	return nil
}
func newIdentityUpdateCMD() *cobra.Command {
	c := &updateIdentityCmd{}
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update HLF identity",
		Long:  `Update HLF identity`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			if err := c.run(); err != nil {
				return err
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&c.name, "name", "", "Name of the external chaincode")
	f.StringVar(&c.namespace, "namespace", "", "Namespace of the external chaincode")
	f.StringVar(&c.caName, "ca-name", "", "Name of the CA")
	f.StringVar(&c.caNamespace, "ca-namespace", "", "Namespace of the CA")
	f.StringVar(&c.ca, "ca", "", "CA name")
	f.StringVar(&c.mspID, "mspid", "", "MSP ID")
	f.StringVar(&c.enrollId, "enroll-id", "", "Enroll ID")
	f.StringVar(&c.enrollSecret, "enroll-secret", "", "Enroll Secret")
	return cmd
}
