package chaincode

import (
	pb "github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/hyperledger/fabric/common/policydsl"
	"github.com/kfsoftware/hlf-operator/kubectl-hlf/cmd/helpers"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"io"
	"io/ioutil"
	"os"
	"strconv"
)

type getNextCmd struct {
	configPath        string
	userName          string
	channelName       string
	name              string
	mspID             string
	property          string
	outFile           string
	peer              string
	policy            string
	initRequired      bool
	collectionsConfig string
}

type mspFilter struct {
	mspID string
}

// Accept returns true if this peer is to be included in the target list
func (f *mspFilter) Accept(peer fab.Peer) bool {
	return peer.MSPID() == f.mspID
}

type mspFilterExclude struct {
	mspID string
}

// Accept returns true if this peer is to be included in the target list
func (f *mspFilterExclude) Accept(peer fab.Peer) bool {
	return peer.MSPID() != f.mspID
}
func (c *getNextCmd) validate() error {
	if c.property != "version" && c.property != "sequence" {
		return errors.New("property must be either version or sequence")
	}
	if c.outFile == "" {
		return errors.New("output file is required")
	}
	return nil
}

type mspFilterArray struct {
	mspIDs []string
}

// Accept returns true if this peer's MSPID is in the array of MSPIDs
func (f *mspFilterArray) Accept(peer fab.Peer) bool {
	if len(f.mspIDs) == 0 {
		return true
	}
	for _, mspID := range f.mspIDs {
		if peer.MSPID() == mspID {
			return true
		}
	}
	return false
}

func (c *getNextCmd) run(out io.Writer, stdErr io.Writer) error {
	mspID := c.mspID
	configBackend := config.FromFile(c.configPath)
	sdk, err := fabsdk.New(configBackend)
	if err != nil {
		return err
	}
	org1AdminClientContext := sdk.Context(
		fabsdk.WithUser(c.userName),
		fabsdk.WithOrg(mspID),
	)
	resClient, err := resmgmt.New(org1AdminClientContext)
	if err != nil {
		return err
	}
	committedCCs, err := resClient.LifecycleQueryCommittedCC(
		c.channelName,
		resmgmt.LifecycleQueryCommittedCCRequest{Name: c.name},
	)
	if err != nil {
		return err
	}
	if len(committedCCs) == 0 {
		return errors.New("no chaincode found")
	}
	var collections []*pb.CollectionConfig
	if c.collectionsConfig != "" {
		//
		pdcBytes, err := os.ReadFile(c.collectionsConfig)
		if err != nil {
			return err
		}
		collections, err = helpers.GetCollectionConfigFromBytes(pdcBytes)
		if err != nil {
			return err
		}
	}
	sp, err := policydsl.FromString(c.policy)
	if err != nil {
		return err
	}
	shouldCommit := len(committedCCs) == 0
	if len(committedCCs) > 0 {
		firstCommittedCC := committedCCs[0]
		signaturePolicyString := firstCommittedCC.SignaturePolicy.String()
		newSignaturePolicyString := sp.String()
		if signaturePolicyString != newSignaturePolicyString {
			log.Debugf("Signature policy changed, old=%s new=%s", signaturePolicyString, newSignaturePolicyString)
			shouldCommit = true
		} else {
			log.Debugf("Signature policy not changed, signaturePolicy=%s", signaturePolicyString)
		}
		// compare collections
		oldCollections := firstCommittedCC.CollectionConfig
		newCollections := collections
		if len(oldCollections) != len(newCollections) {
			log.Infof("Collection config changed, old=%d new=%d", len(oldCollections), len(newCollections))
			shouldCommit = true
		} else {
			for idx, oldCollection := range oldCollections {
				oldCollectionPayload := oldCollection.Payload.(*pb.CollectionConfig_StaticCollectionConfig)
				newCollection := newCollections[idx]
				newCollectionPayload := newCollection.Payload.(*pb.CollectionConfig_StaticCollectionConfig)
				if oldCollectionPayload.StaticCollectionConfig.Name != newCollectionPayload.StaticCollectionConfig.Name {
					log.Infof("Collection config changed, old=%s new=%s", oldCollectionPayload.StaticCollectionConfig.Name, newCollectionPayload.StaticCollectionConfig.Name)
					shouldCommit = true
					break
				}
				oldCollectionPolicy := oldCollection.GetStaticCollectionConfig().MemberOrgsPolicy
				newCollectionPolicy := newCollection.GetStaticCollectionConfig().MemberOrgsPolicy
				if oldCollectionPolicy.GetSignaturePolicy().String() != newCollectionPolicy.GetSignaturePolicy().String() {
					log.Infof("Collection config changed, old=%s new=%s", oldCollectionPolicy.GetSignaturePolicy().String(), newCollectionPolicy.GetSignaturePolicy().String())
					shouldCommit = true
					break
				}
			}
		}
	}

	latestCC := committedCCs[len(committedCCs)-1]
	var data []byte
	if c.property == "version" {
		data = []byte(latestCC.Version)
	} else {
		if shouldCommit {
			data = []byte(strconv.FormatInt(latestCC.Sequence+1, 10))
		} else {
			data = []byte(strconv.FormatInt(latestCC.Sequence, 10))
		}
	}
	err = ioutil.WriteFile(c.outFile, data, 0600)
	if err != nil {
		return err
	}
	return nil
}
func newGetNextCMD(out io.Writer, errOut io.Writer) *cobra.Command {
	c := &getNextCmd{}
	cmd := &cobra.Command{
		Use: "getnext",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			return c.run(out, errOut)
		},
	}
	persistentFlags := cmd.PersistentFlags()
	persistentFlags.StringVarP(&c.configPath, "config", "", "", "Configuration file for the SDK")
	persistentFlags.StringVarP(&c.userName, "user", "", "", "User name for the transaction")
	persistentFlags.StringVarP(&c.channelName, "channel", "", "", "Channel name")
	persistentFlags.StringVarP(&c.name, "name", "", "", "Chaincode name")
	persistentFlags.StringVarP(&c.mspID, "msp-id", "", "", "MSP ID of the organization")
	persistentFlags.StringVarP(&c.property, "property", "", "", "Property to get(\"version\" or \"sequence\")")
	persistentFlags.StringVarP(&c.outFile, "out", "o", "", "File to write the property to")
	persistentFlags.StringVarP(&c.peer, "peer", "p", "", "Peer org to invoke the updates")
	persistentFlags.StringVarP(&c.policy, "policy", "", "", "Policy")
	persistentFlags.BoolVarP(&c.initRequired, "init-required", "", false, "Init required")
	persistentFlags.StringVarP(&c.collectionsConfig, "collections-config", "", "", "Private data collections")

	cmd.MarkPersistentFlagRequired("user")
	cmd.MarkPersistentFlagRequired("config")
	cmd.MarkPersistentFlagRequired("channel")
	cmd.MarkPersistentFlagRequired("name")
	cmd.MarkPersistentFlagRequired("msp-id")
	cmd.MarkPersistentFlagRequired("out")
	return cmd
}
