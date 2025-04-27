package externalchaincode

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/kfsoftware/hlf-operator/kubectl-hlf/cmd/helpers"
	"github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type updateExternalChaincodeCmd struct {
	name        string
	namespace   string
	image       string
	packageID   string
	caName      string
	caNamespace string

	enrollId     string
	enrollSecret string
	force        bool

	replicas int

	tlsRequired bool
}

func (c *updateExternalChaincodeCmd) validate() error {
	if c.name == "" {
		return fmt.Errorf("--name is required")
	}
	if c.namespace == "" {
		return fmt.Errorf("--namespace is required")
	}
	if c.image == "" {
		return fmt.Errorf("--image is required")
	}
	if c.packageID == "" {
		return fmt.Errorf("--package-id is required")
	}
	if c.tlsRequired {
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
	}
	if c.replicas < 0 {
		return fmt.Errorf("--replicas must be >= 0")
	}
	return nil
}
func (c *updateExternalChaincodeCmd) run() error {
	oclient, err := helpers.GetKubeOperatorClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	fabricChaincode, err := oclient.HlfV1alpha1().FabricChaincodes(c.namespace).Get(ctx, c.name, v1.GetOptions{})
	if err != nil {
		return err
	}
	if c.force {
		if fabricChaincode.Annotations == nil {
			fabricChaincode.Annotations = make(map[string]string)
		}
		fabricChaincode.Annotations["hlf.kungfusoftware.es/updatedtime"] = time.Now().UTC().Format(time.RFC3339)
	}
	fabricChaincode.Spec.Image = c.image
	fabricChaincode.Spec.ImagePullPolicy = corev1.PullAlways
	fabricChaincode.Spec.PackageID = c.packageID
	fabricChaincode.Spec.ImagePullSecrets = []corev1.LocalObjectReference{}
	fabricChaincode.Spec.Replicas = c.replicas
	if c.tlsRequired {
		fabricCA, err := oclient.HlfV1alpha1().FabricCAs(c.caNamespace).Get(ctx, c.caName, v1.GetOptions{})
		if err != nil {
			return err
		}
		fabricChaincode.Spec.Credentials = &v1alpha1.TLSComponent{
			Cahost: fmt.Sprintf("%s.%s", fabricCA.Name, fabricCA.Namespace),
			Caname: "tlsca",
			Caport: 7054,
			Catls: &v1alpha1.Catls{
				Cacert: base64.StdEncoding.EncodeToString([]byte(fabricCA.Status.TlsCert)),
			},
			Csr: v1alpha1.Csr{
				Hosts: []string{
					c.name,
					fmt.Sprintf("%s.%s", c.name, c.namespace),
				},
				CN: c.name,
			},
			Enrollid:     c.enrollId,
			Enrollsecret: c.enrollSecret,
		}
	} else {
		fabricChaincode.Spec.Credentials = nil
	}
	fabricChaincode, err = oclient.HlfV1alpha1().FabricChaincodes(c.namespace).Update(
		ctx,
		fabricChaincode,
		v1.UpdateOptions{},
	)
	if err != nil {
		return err
	}
	fmt.Printf("Updated external chaincode %s\n", fabricChaincode.Name)
	return nil
}
func newExternalChaincodeUpdateCmd() *cobra.Command {
	c := &updateExternalChaincodeCmd{}
	cmd := &cobra.Command{
		Use: "update",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			return c.run()
		},
	}
	f := cmd.Flags()
	f.StringVar(&c.name, "name", "", "Name of the external chaincode")
	f.StringVar(&c.namespace, "namespace", "", "Namespace of the external chaincode")
	f.StringVar(&c.image, "image", "", "Image of the external chaincode")
	f.StringVar(&c.packageID, "package-id", "", "Package ID of the external chaincode")
	f.StringVar(&c.caName, "ca-name", "", "CA name to enroll this user")
	f.StringVar(&c.caNamespace, "ca-namespace", "", "Namespace of the CA")
	f.StringVar(&c.enrollId, "enroll-id", "", "Enroll ID of the CA")
	f.StringVar(&c.enrollSecret, "enroll-secret", "", "Enroll secret of the CA")
	f.BoolVarP(&c.force, "force", "", false, "Force restart of chaincode")
	f.IntVar(&c.replicas, "replicas", 1, "Replicas of the chaincode")
	f.BoolVar(&c.tlsRequired, "tls-required", false, "Require TLS for chaincode")
	return cmd
}
