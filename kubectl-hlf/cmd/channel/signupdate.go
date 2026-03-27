package channel

import (
	"bytes"
	"fmt"
	mspclient "github.com/hyperledger/fabric-sdk-go/pkg/client/msp"
	"os"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/cryptosuite"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/cryptosuite/bccsp/sw"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab"

	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	mspimpl "github.com/hyperledger/fabric-sdk-go/pkg/msp"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"io"
)

type signUpdateChannelCmd struct {
	configPath  string
	channelName string
	userName    string
	file        string
	mspID       string
	signatures  []string
	identity    string
	output      string
}

func (c *signUpdateChannelCmd) validate() error {
	return nil
}

type identity struct {
	Cert Pem `json:"cert"`
	Key  Pem `json:"key"`
}
type Pem struct {
	Pem string
}

func (c *signUpdateChannelCmd) run(out io.Writer) error {
	configBackend := config.FromFile(c.configPath)
	sdk, err := fabsdk.New(configBackend)
	if err != nil {
		return err
	}
	org1AdminClientContext := sdk.Context(
		fabsdk.WithUser(c.userName),
		fabsdk.WithOrg(c.mspID),
	)
	resClient, err := resmgmt.New(org1AdminClientContext)
	if err != nil {
		return err
	}
	updateEnvelopeBytes, err := os.ReadFile(c.file)
	if err != nil {
		return err
	}
	configUpdateReader := bytes.NewReader(updateEnvelopeBytes)

	var signatureBytes []byte

	// use identity file if provided
	if c.identity != "" {
		sdkConfig, err := sdk.Config()
		if err != nil {
			return err
		}

		cryptoConfig := cryptosuite.ConfigFromBackend(sdkConfig)
		cryptoSuite, err := sw.GetSuiteByConfig(cryptoConfig)
		if err != nil {
			return err
		}
		userStore := mspimpl.NewMemoryUserStore()
		endpointConfig, err := fab.ConfigFromBackend(sdkConfig)
		if err != nil {
			return err
		}
		identityManager, err := mspimpl.NewIdentityManager(c.mspID, userStore, cryptoSuite, endpointConfig)
		if err != nil {
			return err
		}
		identityBytes, err := os.ReadFile(c.identity)
		if err != nil {
			return err
		}
		id := &identity{}
		err = yaml.Unmarshal(identityBytes, id)
		if err != nil {
			return err
		}
		signingIdentity, err := identityManager.CreateSigningIdentity(
			msp.WithPrivateKey([]byte(id.Key.Pem)),
			msp.WithCert([]byte(id.Cert.Pem)),
		)
		if err != nil {
			return err
		}
		signature, err := resClient.CreateConfigSignatureFromReader(signingIdentity, configUpdateReader)
		if err != nil {
			return err
		}
		signatureBytes, err = proto.Marshal(signature)
		if err != nil {
			return err
		}
	} else {
		mspClient, err := mspclient.New(org1AdminClientContext, mspclient.WithOrg(c.mspID))
		if err != nil {
			return err
		}
		usr, err := mspClient.GetSigningIdentity(c.userName)
		signature, err := resClient.CreateConfigSignatureFromReader(usr, configUpdateReader)
		signatureBytes, err = proto.Marshal(signature)
	}

	if c.output != "" {
		err = os.WriteFile(c.output, signatureBytes, 0600)
		if err != nil {
			return err
		}
	} else {
		_, err = fmt.Fprint(out, signatureBytes)
		if err != nil {
			return err
		}
	}
	return nil
}
func newSignUpdateChannelCMD(stdOut io.Writer, stdErr io.Writer) *cobra.Command {
	c := &signUpdateChannelCmd{}
	cmd := &cobra.Command{
		Use: "signupdate",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			return c.run(stdOut)
		},
	}
	persistentFlags := cmd.PersistentFlags()
	persistentFlags.StringVarP(&c.mspID, "mspid", "", "", "MSP ID of the organization")
	persistentFlags.StringVarP(&c.channelName, "channel", "", "", "Channel name")
	persistentFlags.StringVarP(&c.configPath, "config", "", "", "Configuration file for the SDK")
	persistentFlags.StringVarP(&c.identity, "identity", "", "", "Identity file")
	persistentFlags.StringVarP(&c.file, "file", "f", "", "Config update file")
	persistentFlags.StringVarP(&c.output, "output", "o", "", "Output signature")
	persistentFlags.StringVarP(&c.userName, "user", "", "", "User name for the transaction")
	cmd.MarkPersistentFlagRequired("mspid")
	cmd.MarkPersistentFlagRequired("channel")
	cmd.MarkPersistentFlagRequired("config")
	cmd.MarkPersistentFlagRequired("user")
	cmd.MarkPersistentFlagRequired("file")
	return cmd
}
