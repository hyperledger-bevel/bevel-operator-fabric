package externalchaincode

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/kfsoftware/hlf-operator/kubectl-hlf/cmd/helpers"
	"github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type syncExternalChaincodeCmd struct {
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

	tlsRequired         bool
	ImagePullSecret     []string
	Env                 []string
	chaincodeServerPort int
}

func (c *syncExternalChaincodeCmd) validate() error {
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
	return nil
}
func (c syncExternalChaincodeCmd) getFabricChaincodeSpec(ctx context.Context) (v1alpha1.FabricChaincodeSpec, error) {
	fabricChaincodeSpec := v1alpha1.FabricChaincodeSpec{
		Image:               c.image,
		ImagePullPolicy:     corev1.PullIfNotPresent,
		PackageID:           c.packageID,
		ImagePullSecrets:    []corev1.LocalObjectReference{},
		Affinity:            nil,
		Tolerations:         []corev1.Toleration{},
		Resources:           nil,
		Credentials:         nil,
		Replicas:            c.replicas,
		Env:                 []corev1.EnvVar{},
		ChaincodeServerPort: c.chaincodeServerPort,
	}

	if len(c.ImagePullSecret) > 0 {
		imagePullSecret := []corev1.LocalObjectReference{}
		for _, v := range c.ImagePullSecret {
			imagePullSecret = append(imagePullSecret, corev1.LocalObjectReference{
				Name: v,
			})
		}
		fabricChaincodeSpec.ImagePullSecrets = imagePullSecret
	}

	if len(c.Env) > 0 {
		env, err := c.handleEnv()
		if err != nil {
			return fabricChaincodeSpec, err
		}
		fabricChaincodeSpec.Env = env
	}

	oclient, err := helpers.GetKubeOperatorClient()
	if err != nil {
		return fabricChaincodeSpec, err
	}

	if c.tlsRequired {
		fabricCA, err := oclient.HlfV1alpha1().FabricCAs(c.caNamespace).Get(ctx, c.caName, v1.GetOptions{})
		if err != nil {
			return fabricChaincodeSpec, err
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
	return fabricChaincodeSpec, nil
}
func (c *syncExternalChaincodeCmd) run() error {
	oclient, err := helpers.GetKubeOperatorClient()
	if err != nil {
		return err
	}
	ctx := context.Background()

	fabricChaincode, err := oclient.HlfV1alpha1().FabricChaincodes(c.namespace).Get(ctx, c.name, v1.GetOptions{})
	if err != nil {
		// create fabricChaincode
		return c.createChaincode(ctx)
	} else {
		// update fabricChaincode
		return c.updateChaincode(ctx, fabricChaincode)
	}
}

func (c *syncExternalChaincodeCmd) createChaincode(ctx context.Context) error {
	fabricChaincodeSpec, err := c.getFabricChaincodeSpec(ctx)
	if err != nil {
		return err
	}
	fabricChaincode := &v1alpha1.FabricChaincode{
		ObjectMeta: v1.ObjectMeta{
			Name:      c.name,
			Namespace: c.namespace,
		},
		Spec: fabricChaincodeSpec,
	}
	oclient, err := helpers.GetKubeOperatorClient()
	if err != nil {
		return err
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

func (c *syncExternalChaincodeCmd) updateChaincode(ctx context.Context, fabricChaincode *v1alpha1.FabricChaincode) error {
	fabricChaincodeSpec, err := c.getFabricChaincodeSpec(ctx)
	if err != nil {
		return err
	}
	oclient, err := helpers.GetKubeOperatorClient()
	if err != nil {
		return err
	}
	fabricChaincode.Spec.Image = fabricChaincodeSpec.Image
	fabricChaincode.Spec.ImagePullPolicy = corev1.PullAlways
	fabricChaincode.Spec.Replicas = fabricChaincodeSpec.Replicas
	fabricChaincode.Spec.PackageID = fabricChaincodeSpec.PackageID
	fabricChaincode.Spec.ImagePullSecrets = fabricChaincodeSpec.ImagePullSecrets
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

func (c *syncExternalChaincodeCmd) handleEnv() ([]corev1.EnvVar, error) {
	var env []corev1.EnvVar
	for _, literalSource := range c.Env {
		keyName, value, err := ParseEnv(literalSource)
		if err != nil {
			return nil, err
		}
		env = append(env, corev1.EnvVar{
			Name:  keyName,
			Value: value,
		})
	}
	return env, nil
}

// ParseEnv parses the source key=val pair into its component pieces.
// This functionality is distinguished from strings.SplitN(source, "=", 2) since
// it returns an error in the case of empty keys, values, or a missing equals sign.
func ParseEnv(source string) (keyName, value string, err error) {
	// leading equal is invalid
	if strings.Index(source, "=") == 0 {
		return "", "", fmt.Errorf("invalid formart %v, expected key=value", source)
	}
	// split after the first equal (so values can have the = character)
	items := strings.SplitN(source, "=", 2)
	if len(items) != 2 {
		return "", "", fmt.Errorf("invalid format %v, expected key=value", source)
	}

	return items[0], items[1], nil
}

func newExternalChaincodeSyncCmd() *cobra.Command {
	c := &syncExternalChaincodeCmd{}
	cmd := &cobra.Command{
		Use: "sync",
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
	f.BoolVar(&c.tlsRequired, "tls-required", false, "Require TLS for chaincode")
	f.IntVarP(&c.replicas, "replicas", "", 1, "Number of replicas of the chaincode")
	f.StringArrayVarP(&c.ImagePullSecret, "image-pull-secret", "s", []string{}, "Image Pull Secret for the Chaincode Image")
	f.StringArrayVarP(&c.Env, "env", "", []string{}, "Environment variable for the Chaincode (key=value)")
	f.IntVar(&c.chaincodeServerPort, "port", 7052, "Chaincode Server Port")
	return cmd
}
