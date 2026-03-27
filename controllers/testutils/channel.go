package testutils

import (
	"context"
	"crypto/x509"
	"fmt"
	"github.com/hyperledger/fabric-config/configtx"
	"github.com/hyperledger/fabric-config/configtx/membership"
	"github.com/hyperledger/fabric-config/configtx/orderer"
	cb "github.com/hyperledger/fabric-protos-go/common"
	sb "github.com/hyperledger/fabric-protos-go/orderer/smartbft"
	"github.com/kfsoftware/hlf-operator/controllers/utils"
	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/pkg/errors"
	"time"
)

type OrdererOrg struct {
	mspID        string
	tlsRootCert  *x509.Certificate
	signRootCert *x509.Certificate
	ordererUrls  []string
}
type PeerOrg struct {
	mspID        string
	tlsRootCert  *x509.Certificate
	signRootCert *x509.Certificate
}

type Consenter struct {
	host     string
	port     int
	tlsCert  *x509.Certificate
	signCert *x509.Certificate
	mspId    string
}
type channelStore struct {
}
type CreateChannelOptions struct {
	consenters    []Consenter
	peerOrgs      []PeerOrg
	ordererOrgs   []OrdererOrg
	name          string
	batchSize     *orderer.BatchSize
	batchDuration *time.Duration
	consensus     hlfv1alpha1.OrdererConsensusType
}

func (o CreateChannelOptions) validate() error {
	if o.name == "" {
		return errors.New("name is required")
	}
	if len(o.consenters) == 0 {
		return errors.New("at least 1 consenter is required")
	}
	if len(o.ordererOrgs) == 0 {
		return errors.New("at least 1 orderer org is required")
	}

	return nil
}

type ChannelOption func(*CreateChannelOptions)

func WithName(name string) ChannelOption {
	return func(o *CreateChannelOptions) {
		o.name = name
	}
}
func WithConsenters(consenters ...Consenter) ChannelOption {
	return func(o *CreateChannelOptions) {
		o.consenters = consenters
	}
}

func WithOrdererOrgs(ordererOrgs ...OrdererOrg) ChannelOption {
	return func(o *CreateChannelOptions) {
		o.ordererOrgs = ordererOrgs
	}
}
func WithBatchTimeout(batchTimeout time.Duration) ChannelOption {
	return func(o *CreateChannelOptions) {
		o.batchDuration = &batchTimeout
	}
}
func WithBatchSize(batchSize *orderer.BatchSize) ChannelOption {
	return func(o *CreateChannelOptions) {
		o.batchSize = batchSize
	}
}
func WithPeerOrgs(peerOrgs ...PeerOrg) ChannelOption {
	return func(o *CreateChannelOptions) {
		o.peerOrgs = peerOrgs
	}
}
func WithConsensus(consensus hlfv1alpha1.OrdererConsensusType) ChannelOption {
	return func(o *CreateChannelOptions) {
		o.consensus = consensus
	}
}
func CreateConsenter(host string, port int, tlsCert, signCert *x509.Certificate, mspId string) Consenter {
	return Consenter{
		host:     host,
		port:     port,
		tlsCert:  tlsCert,
		signCert: signCert,
		mspId:    mspId,
	}
}
func CreateOrdererOrg(mspID string, tlsRootCert *x509.Certificate, signRootCert *x509.Certificate, ordererUrls []string) OrdererOrg {
	return OrdererOrg{
		mspID:        mspID,
		tlsRootCert:  tlsRootCert,
		signRootCert: signRootCert,
		ordererUrls:  ordererUrls,
	}
}
func CreatePeerOrg(mspID string, tlsRootCert *x509.Certificate, signRootCert *x509.Certificate) PeerOrg {
	return PeerOrg{
		mspID:        mspID,
		tlsRootCert:  tlsRootCert,
		signRootCert: signRootCert,
	}
}

func NewChannelStore() *channelStore {
	return &channelStore{}
}
func (s channelStore) GetApplicationChannelBlock(ctx context.Context, opts ...ChannelOption) (*cb.Block, error) {
	o := &CreateChannelOptions{
		consenters:  []Consenter{},
		ordererOrgs: []OrdererOrg{},
		peerOrgs:    []PeerOrg{},
		name:        "",
	}
	for _, opt := range opts {
		opt(o)
	}
	err := o.validate()
	if err != nil {
		return nil, err
	}

	var ordererOrgs []configtx.Organization
	for _, ordOrg := range o.ordererOrgs {
		genesisOrdererOrg, err := memberToConfigtxOrg(ordOrg.mspID, ordOrg.tlsRootCert, ordOrg.signRootCert, ordOrg.ordererUrls, []configtx.Address{})
		if err != nil {
			return nil, err
		}
		ordererOrgs = append(ordererOrgs, genesisOrdererOrg)
	}
	var peerOrgs []configtx.Organization
	for _, peerOrg := range o.peerOrgs {
		anchorPeers := []configtx.Address{}
		genesisOrdererOrg, err := memberToConfigtxOrg(peerOrg.mspID, peerOrg.tlsRootCert, peerOrg.signRootCert, []string{}, anchorPeers)
		if err != nil {
			return nil, err
		}
		peerOrgs = append(peerOrgs, genesisOrdererOrg)
	}
	var consenters []orderer.Consenter   // raft consenter
	consenterMapping := []cb.Consenter{} // bft consenter
	var etcdRaft orderer.EtcdRaft
	var smartBFTOptions *sb.Options
	var ordererType string
	channelCapabilities := []string{"V2_0"}
	if o.consensus == hlfv1alpha1.OrdererConsensusEtcdraft {
		ordererType = orderer.ConsensusTypeEtcdRaft
		for _, consenter := range o.consenters {
			genesisConsenter := orderer.Consenter{
				Address: orderer.EtcdAddress{
					Host: consenter.host,
					Port: consenter.port,
				},
				ClientTLSCert: consenter.tlsCert,
				ServerTLSCert: consenter.tlsCert,
			}
			consenters = append(consenters, genesisConsenter)
		}
		etcdRaft = orderer.EtcdRaft{
			Consenters: consenters,
			Options: orderer.EtcdRaftOptions{
				TickInterval:         "500ms",
				ElectionTick:         10,
				HeartbeatTick:        1,
				MaxInflightBlocks:    5,
				SnapshotIntervalSize: 16 * 1024 * 1024, // 16 MB
			},
		}
	} else if o.consensus == hlfv1alpha1.OrdererConsensusBFT {
		ordererType = orderer.ConsensusTypeBFT
		channelCapabilities = append(channelCapabilities, "V3_0")
		for i, consenter := range o.consenters {
			consenterMapping = append(consenterMapping, cb.Consenter{
				Host:          consenter.host,
				Port:          uint32(consenter.port), //nolint:gosec // safe conversion
				MspId:         consenter.mspId,
				Id:            uint32(i + 1), //nolint:gosec // safe conversion
				Identity:      utils.EncodeX509Certificate(consenter.signCert),
				ClientTlsCert: utils.EncodeX509Certificate(consenter.tlsCert),
				ServerTlsCert: utils.EncodeX509Certificate(consenter.tlsCert),
			})
		}
		smartBFTOptions = &sb.Options{
			RequestBatchMaxCount:      100,
			RequestBatchMaxInterval:   "50ms",
			RequestForwardTimeout:     "2s",
			RequestComplainTimeout:    "20s",
			RequestAutoRemoveTimeout:  "3m0s",
			ViewChangeResendInterval:  "5s",
			ViewChangeTimeout:         "20s",
			LeaderHeartbeatTimeout:    "1m0s",
			CollectTimeout:            "1s",
			RequestBatchMaxBytes:      10485760,
			IncomingMessageBufferSize: 200,
			RequestPoolSize:           100000,
			LeaderHeartbeatCount:      10,
		}
	} else {
		return nil, fmt.Errorf("orderer type %s not supported", ordererType)
	}

	channelConfig := configtx.Channel{
		Orderer: configtx.Orderer{
			ConsenterMapping: consenterMapping,
			OrdererType:      ordererType,
			Organizations:    ordererOrgs,
			EtcdRaft:         etcdRaft,
			SmartBFT:         smartBFTOptions,
			Policies: map[string]configtx.Policy{
				"Readers": {
					Type: "ImplicitMeta",
					Rule: "ANY Readers",
				},
				"Writers": {
					Type: "ImplicitMeta",
					Rule: "ANY Writers",
				},
				"Admins": {
					Type: "ImplicitMeta",
					Rule: "MAJORITY Admins",
				},
				"BlockValidation": {
					Type: "ImplicitMeta",
					Rule: "ANY Writers",
				},
			},
			Capabilities: []string{"V2_0"},
			BatchSize: orderer.BatchSize{
				MaxMessageCount:   100,
				AbsoluteMaxBytes:  1024 * 1024,
				PreferredMaxBytes: 512 * 1024,
			},
			BatchTimeout: 2 * time.Second,
			State:        orderer.ConsensusStateNormal,
		},
		Application: configtx.Application{
			Organizations: peerOrgs,
			Capabilities:  []string{"V2_0"},
			Policies: map[string]configtx.Policy{
				"Readers": {
					Type: "ImplicitMeta",
					Rule: "ANY Readers",
				},
				"Writers": {
					Type: "ImplicitMeta",
					Rule: "ANY Writers",
				},
				"Admins": {
					Type: "ImplicitMeta",
					Rule: "MAJORITY Admins",
				},
				"Endorsement": {
					Type: "ImplicitMeta",
					Rule: "MAJORITY Endorsement",
				},
				"LifecycleEndorsement": {
					Type: "ImplicitMeta",
					Rule: "MAJORITY Endorsement",
				},
			},
			ACLs: defaultACLs(),
		},
		Capabilities: channelCapabilities,
		Policies: map[string]configtx.Policy{
			"Readers": {
				Type: "ImplicitMeta",
				Rule: "ANY Readers",
			},
			"Writers": {
				Type: "ImplicitMeta",
				Rule: "ANY Writers",
			},
			"Admins": {
				Type: "ImplicitMeta",
				Rule: "MAJORITY Admins",
			},
		},
	}
	if o.batchSize != nil {
		channelConfig.Orderer.BatchSize.MaxMessageCount = o.batchSize.MaxMessageCount
		channelConfig.Orderer.BatchSize.AbsoluteMaxBytes = o.batchSize.AbsoluteMaxBytes
		channelConfig.Orderer.BatchSize.PreferredMaxBytes = o.batchSize.PreferredMaxBytes
	}
	if o.batchDuration != nil {
		channelConfig.Orderer.BatchTimeout = *o.batchDuration
	}
	channelID := o.name
	genesisBlock, err := configtx.NewApplicationChannelGenesisBlock(channelConfig, channelID)
	if err != nil {
		return nil, err
	}
	return genesisBlock, nil
}
func defaultACLs() map[string]string {
	return map[string]string{
		"_lifecycle/CheckCommitReadiness": "/Channel/Application/Writers",

		//  ACL policy for _lifecycle's "CommitChaincodeDefinition" function
		"_lifecycle/CommitChaincodeDefinition": "/Channel/Application/Writers",

		//  ACL policy for _lifecycle's "QueryChaincodeDefinition" function
		"_lifecycle/QueryChaincodeDefinition": "/Channel/Application/Writers",

		//  ACL policy for _lifecycle's "QueryChaincodeDefinitions" function
		"_lifecycle/QueryChaincodeDefinitions": "/Channel/Application/Writers",

		// ---Lifecycle System Chaincode (lscc) function to policy mapping for access control---//

		//  ACL policy for lscc's "getid" function
		"lscc/ChaincodeExists": "/Channel/Application/Readers",

		//  ACL policy for lscc's "getdepspec" function
		"lscc/GetDeploymentSpec": "/Channel/Application/Readers",

		//  ACL policy for lscc's "getccdata" function
		"lscc/GetChaincodeData": "/Channel/Application/Readers",

		//  ACL Policy for lscc's "getchaincodes" function
		"lscc/GetInstantiatedChaincodes": "/Channel/Application/Readers",

		// ---Query System Chaincode (qscc) function to policy mapping for access control---//

		//  ACL policy for qscc's "GetChainInfo" function
		"qscc/GetChainInfo": "/Channel/Application/Readers",

		//  ACL policy for qscc's "GetBlockByNumber" function
		"qscc/GetBlockByNumber": "/Channel/Application/Readers",

		//  ACL policy for qscc's  "GetBlockByHash" function
		"qscc/GetBlockByHash": "/Channel/Application/Readers",

		//  ACL policy for qscc's "GetTransactionByID" function
		"qscc/GetTransactionByID": "/Channel/Application/Readers",

		//  ACL policy for qscc's "GetBlockByTxID" function
		"qscc/GetBlockByTxID": "/Channel/Application/Readers",

		// ---Configuration System Chaincode (cscc) function to policy mapping for access control---//

		//  ACL policy for cscc's "GetConfigBlock" function
		"cscc/GetConfigBlock": "/Channel/Application/Readers",

		//  ACL policy for cscc's "GetChannelConfig" function
		"cscc/GetChannelConfig": "/Channel/Application/Readers",

		// ---Miscellaneous peer function to policy mapping for access control---//

		//  ACL policy for invoking chaincodes on peer
		"peer/Propose": "/Channel/Application/Writers",

		//  ACL policy for chaincode to chaincode invocation
		"peer/ChaincodeToChaincode": "/Channel/Application/Writers",

		// ---Events resource to policy mapping for access control// // // ---//

		//  ACL policy for sending block events
		"event/Block": "/Channel/Application/Readers",

		//  ACL policy for sending filtered block events
		"event/FilteredBlock": "/Channel/Application/Readers",
	}
}
func memberToConfigtxOrg(mspID string, rootTlsCert *x509.Certificate, signTlsCert *x509.Certificate, ordererUrls []string, anchorPeers []configtx.Address) (configtx.Organization, error) {
	genesisOrg := configtx.Organization{
		Name: mspID,
		MSP: configtx.MSP{
			Name:                 mspID,
			RootCerts:            []*x509.Certificate{signTlsCert},
			CryptoConfig:         membership.CryptoConfig{},
			TLSRootCerts:         []*x509.Certificate{rootTlsCert},
			TLSIntermediateCerts: nil,
			NodeOUs: membership.NodeOUs{
				Enable: true,
				ClientOUIdentifier: membership.OUIdentifier{
					Certificate:                  signTlsCert,
					OrganizationalUnitIdentifier: "client",
				},
				PeerOUIdentifier: membership.OUIdentifier{
					Certificate:                  signTlsCert,
					OrganizationalUnitIdentifier: "peer",
				},
				AdminOUIdentifier: membership.OUIdentifier{
					Certificate:                  signTlsCert,
					OrganizationalUnitIdentifier: "admin",
				},
				OrdererOUIdentifier: membership.OUIdentifier{
					Certificate:                  signTlsCert,
					OrganizationalUnitIdentifier: "orderer",
				},
			},
		},
		OrdererEndpoints: ordererUrls,
		Policies: map[string]configtx.Policy{
			"Admins": {
				Type: "Signature",
				Rule: fmt.Sprintf("OR('%s.admin')", mspID),
			},
			"Readers": {
				Type: "Signature",
				Rule: fmt.Sprintf("OR('%s.member')", mspID),
			},
			"Writers": {
				Type: "Signature",
				Rule: fmt.Sprintf("OR('%s.member')", mspID),
			},
			"Endorsement": {
				Type: "Signature",
				Rule: fmt.Sprintf("OR('%s.member')", mspID),
			},
		},
		AnchorPeers: anchorPeers,
	}
	return genesisOrg, nil
}
