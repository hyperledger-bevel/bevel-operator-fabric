package externalchaincode

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/kfsoftware/hlf-operator/kubectl-hlf/cmd/helpers"
	"github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type createExternalChaincodeCmd struct {
	name             string
	namespace        string
	image            string
	packageID        string
	caName           string
	caNamespace      string
	imagePullPolicy  string
	enrollId         string
	enrollSecret     string
	replicas         int
	tlsRequired      bool
	ImagePullSecrets []string
}

func (c *createExternalChaincodeCmd) validate() error {
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
func (c *createExternalChaincodeCmd) run() error {
	oclient, err := helpers.GetKubeOperatorClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	imagePullPolicy := corev1.PullPolicy(c.imagePullPolicy)
	fabricChaincodeSpec := v1alpha1.FabricChaincodeSpec{
		Image:            c.image,
		ImagePullPolicy:  imagePullPolicy,
		PackageID:        c.packageID,
		ImagePullSecrets: []corev1.LocalObjectReference{},
		Credentials:      nil,
		Replicas:         c.replicas,
	}
	if len(c.ImagePullSecrets) > 0 {
		imagePullSecrets := []corev1.LocalObjectReference{}
		for _, v := range c.ImagePullSecrets {
			imagePullSecrets = append(imagePullSecrets, corev1.LocalObjectReference{
				Name: v,
			})
		}
		fabricChaincodeSpec.ImagePullSecrets = imagePullSecrets
	}
	if c.tlsRequired {
		fabricCA, err := oclient.HlfV1alpha1().FabricCAs(c.caNamespace).Get(ctx, c.caName, v1.GetOptions{})
		if err != nil {
			return err
		}
		fabricChaincodeSpec.Credentials = &v1alpha1.TLSComponent{
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
	}
	fabricChaincode := &v1alpha1.FabricChaincode{
		ObjectMeta: v1.ObjectMeta{
			Name:      c.name,
			Namespace: c.namespace,
		},
		Spec: fabricChaincodeSpec,
	}
	fabricChaincode, err = oclient.HlfV1alpha1().FabricChaincodes(c.namespace).Create(
		ctx,
		fabricChaincode,
		v1.CreateOptions{},
	)
	if err != nil {
		return err
	}
	fmt.Printf("Created external chaincode %s\n", fabricChaincode.Name)
	return nil
}
func newExternalChaincodeCreateCmd() *cobra.Command {
	c := &createExternalChaincodeCmd{}
	cmd := &cobra.Command{
		Use: "create",
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
	f.StringVar(&c.imagePullPolicy, "image-pull-policy", "IfNotPresent", "Image Pull Policy of the external chaincode")
	f.StringVar(&c.packageID, "package-id", "", "Package ID of the external chaincode")
	f.StringVar(&c.caName, "ca-name", "", "CA name to enroll this user")
	f.StringVar(&c.caNamespace, "ca-namespace", "", "Namespace of the CA")
	f.StringVar(&c.enrollId, "enroll-id", "", "Enroll ID of the CA")
	f.StringVar(&c.enrollSecret, "enroll-secret", "", "Enroll secret of the CA")
	f.IntVar(&c.replicas, "replicas", 1, "Replicas of the external chaincode")
	f.BoolVar(&c.tlsRequired, "tls-required", false, "Whether the chaincode requires TLS or not")
	f.StringArrayVarP(&c.ImagePullSecrets, "image-pull-secrets", "", []string{}, "Image Pull Secrets for the Chaincode Image")
	return cmd
}
