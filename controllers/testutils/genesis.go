package testutils

import (
	"bytes"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-config/protolator"
	cb "github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/orderer/etcdraft"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/resource/genesisconfig"
	"github.com/kfsoftware/hlf-operator/internal/github.com/hyperledger/fabric/common/channelconfig"
	"github.com/kfsoftware/hlf-operator/internal/github.com/hyperledger/fabric/sdkinternal/configtxgen/encoder"

	genesisconfig2 "github.com/kfsoftware/hlf-operator/internal/github.com/hyperledger/fabric/sdkinternal/configtxgen/genesisconfig"
	"log"
	"os"
	"path"
	"time"
)

type ConsortiumMember struct {
	MSPID string
}

type Consortium struct {
	Name          string
	Organizations []*ConsortiumMember
}

func ordererCapabilities() map[string]bool {
	return map[string]bool{
		"V2_0": true,
	}
}

type PeerNode struct {
	Host string
	Port int
}
type PeerOrganization struct {
	RootCert    string
	TLSRootCert string
	MspID       string
	Peers       []PeerNode
}

func memberToOrg(member PeerOrganization) (*genesisconfig.Organization, error) {
	serverTlsCertPem := []byte(member.TLSRootCert)
	serverRootCert := []byte(member.RootCert)
	mspID := member.MspID
	mspDir, err := os.MkdirTemp("", fmt.Sprintf("mspdir_%s", mspID))
	if err != nil {
		return nil, err
	}
	tlsCaCertsPath := path.Join(mspDir, "tlscacerts")
	err = os.Mkdir(tlsCaCertsPath, 0750)
	if err != nil {
		return nil, err
	}
	caCertsPath := path.Join(mspDir, "cacerts")
	err = os.Mkdir(caCertsPath, 0750)
	if err != nil {
		return nil, err
	}
	err = os.WriteFile(path.Join(caCertsPath, "cacert.pem"), serverRootCert, 0600)
	if err != nil {
		return nil, err
	}
	err = os.WriteFile(path.Join(tlsCaCertsPath, "tlscacert.pem"), serverTlsCertPem, 0600)
	if err != nil {
		return nil, err
	}
	configNodeOU := `
NodeOUs:
  Enable: true
  ClientOUIdentifier:
    Certificate: cacerts/cacert.pem
    OrganizationalUnitIdentifier: client
  PeerOUIdentifier:
    Certificate: cacerts/cacert.pem
    OrganizationalUnitIdentifier: peer
  AdminOUIdentifier:
    Certificate: cacerts/cacert.pem
    OrganizationalUnitIdentifier: admin
  OrdererOUIdentifier:
    Certificate: cacerts/cacert.pem
    OrganizationalUnitIdentifier: orderer
`
	err = os.WriteFile(path.Join(mspDir, "config.yaml"), []byte(configNodeOU), 0600)
	if err != nil {
		return nil, err
	}
	log.Printf("MSPDIR=%s", mspDir)
	anchorPeers := []*genesisconfig.AnchorPeer{}

	for _, peer := range member.Peers {
		anchorPeers = append(anchorPeers, &genesisconfig.AnchorPeer{
			Host: peer.Host,
			Port: peer.Port,
		})
	}
	genesisOrg := &genesisconfig.Organization{
		Name:    mspID,
		ID:      mspID,
		MSPDir:  mspDir,
		MSPType: "bccsp",
		Policies: map[string]*genesisconfig.Policy{
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
		},
		AnchorPeers:   anchorPeers,
		SkipAsForeign: false,
	}
	return genesisOrg, nil
}

type OrdererNode struct {
	TLSCert string
	Host    string
	Port    int
}
type OrdererOrganization struct {
	Nodes        []OrdererNode
	RootTLSCert  string
	RootSignCert string
	MspID        string
}

func memberToOrgUpdate(member PeerOrganization) (*genesisconfig2.Organization, error) {
	serverTlsCertPem := []byte(member.TLSRootCert)
	rootCertPem := []byte(member.RootCert)
	mspID := member.MspID
	mspDir, err := os.MkdirTemp("", fmt.Sprintf("mspdir_%s", mspID))
	if err != nil {
		return nil, err
	}
	tlsCaCertsPath := path.Join(mspDir, "tlscacerts")
	err = os.Mkdir(tlsCaCertsPath, 0750)
	if err != nil {
		return nil, err
	}
	caCertsPath := path.Join(mspDir, "cacerts")
	err = os.Mkdir(caCertsPath, 0750)
	if err != nil {
		return nil, err
	}
	err = os.WriteFile(path.Join(caCertsPath, "cacert.pem"), rootCertPem, 0600)
	if err != nil {
		return nil, err
	}
	err = os.WriteFile(path.Join(tlsCaCertsPath, "tlscacert.pem"), serverTlsCertPem, 0600)
	if err != nil {
		return nil, err
	}
	configNodeOU := `
NodeOUs:
  Enable: true
  ClientOUIdentifier:
    Certificate: cacerts/cacert.pem
    OrganizationalUnitIdentifier: client
  PeerOUIdentifier:
    Certificate: cacerts/cacert.pem
    OrganizationalUnitIdentifier: peer
  AdminOUIdentifier:
    Certificate: cacerts/cacert.pem
    OrganizationalUnitIdentifier: admin
  OrdererOUIdentifier:
    Certificate: cacerts/cacert.pem
    OrganizationalUnitIdentifier: orderer
`
	err = os.WriteFile(path.Join(mspDir, "config.yaml"), []byte(configNodeOU), 0600)
	if err != nil {
		return nil, err
	}
	log.Printf("MSPDIR=%s", mspDir)
	anchorPeers := []*genesisconfig2.AnchorPeer{}
	for _, peer := range member.Peers {
		anchorPeers = append(anchorPeers, &genesisconfig2.AnchorPeer{
			Host: peer.Host,
			Port: peer.Port,
		})
	}
	genesisOrg := &genesisconfig2.Organization{
		Name:    mspID,
		ID:      mspID,
		MSPDir:  mspDir,
		MSPType: "bccsp",
		Policies: map[string]*genesisconfig2.Policy{
			"Admins": {
				Type: "Signature",
				Rule: fmt.Sprintf("OR('%s.admin')", mspID),
			},
			"Endorsement": {
				Type: "Signature",
				Rule: fmt.Sprintf("OR('%s.peer')", mspID),
			},
			"Readers": {
				Type: "Signature",
				Rule: fmt.Sprintf("OR('%s.admin', '%s.peer', '%s.client')", mspID, mspID, mspID),
			},
			"Writers": {
				Type: "Signature",
				Rule: fmt.Sprintf("OR('%s.admin', '%s.client')", mspID, mspID),
			},
		},
		AnchorPeers:   anchorPeers,
		SkipAsForeign: false,
	}
	return genesisOrg, nil
}

type AddConsortiumRequest struct {
	Name          string
	Organizations []PeerOrganization
}

func AddConsortiumToConfig(channelConfig *cb.Config, request AddConsortiumRequest) (*cb.Config, error) {
	modifiedConfig := &cb.Config{}
	modifiedConfigBytes, err := proto.Marshal(channelConfig)
	if err != nil {
		return nil, err
	}
	err = proto.Unmarshal(modifiedConfigBytes, modifiedConfig)
	if err != nil {
		return nil, err
	}

	consortiumGroups := map[string]*cb.ConfigGroup{}
	peerOrgs := []*genesisconfig2.Organization{}
	for _, member := range request.Organizations {
		mspID := member.MspID
		peerOrg, err := memberToOrgUpdate(member)
		if err != nil {
			return nil, err
		}
		peerOrgs = append(peerOrgs, peerOrg)
		configGroup, err := encoder.NewConsortiumOrgGroup(peerOrg)
		if err != nil {
			return nil, err
		}
		consortiumGroups[mspID] = configGroup
	}
	_, ok := modifiedConfig.ChannelGroup.Groups["Consortiums"]
	if !ok {
		modifiedConfig.ChannelGroup.Groups["Consortiums"] = &cb.ConfigGroup{}
		modifiedConfig.ChannelGroup.Groups["Consortiums"].Groups[request.Name] = &cb.ConfigGroup{
			Version:  0,
			Groups:   nil,
			Values:   nil,
			Policies: nil,
		}
	}
	conf := map[string]*genesisconfig2.Consortium{
		request.Name: {
			Organizations: peerOrgs,
		},
	}
	consortiums, err := encoder.NewConsortiumsGroup(
		conf,
	)
	if err != nil {
		return nil, err
	}
	modifiedConfig.ChannelGroup.Groups[channelconfig.ConsortiumsGroupKey] = consortiums
	return modifiedConfig, nil
}

type OrdererCapabilities struct {
	V2_0 bool
}
type ApplicationCapabilities struct {
	V2_0 bool
}
type ChannelCapabilities struct {
	V2_0 bool
}
type GenesisConfig struct {
	BatchTimeout            time.Duration // 2 seconds
	MaxMessageCount         int           // 500
	AbsoluteMaxBytes        int           // 10 * 1024 * 1024 = 10MB
	PreferredMaxBytes       int           // 2 * 1024 * 1024 = 2MB
	OrdererCapabilities     OrdererCapabilities
	ApplicationCapabilities ApplicationCapabilities
	ChannelCapabilities     ChannelCapabilities
	SnapshotIntervalSize    int    // 19
	TickInterval            string // 500ms
	ElectionTick            int    // 10
	HeartbeatTick           int    // 1
	MaxInflightBlocks       int    // 5
}

const MB = 1024 * 1024

func fillWithDefaultOps(opts *GenesisConfig) {
	if opts.BatchTimeout.Seconds() <= 1 {
		opts.BatchTimeout = 2 * time.Second
	}
	if opts.MaxMessageCount == 0 {
		opts.MaxMessageCount = 500
	}
	if opts.AbsoluteMaxBytes == 0 {
		opts.AbsoluteMaxBytes = 10 * MB
	}
	if opts.PreferredMaxBytes == 0 {
		opts.PreferredMaxBytes = 2 * MB
	}
	if opts.SnapshotIntervalSize == 0 {
		opts.SnapshotIntervalSize = 19
	}
	if opts.MaxInflightBlocks == 0 {
		opts.MaxInflightBlocks = 5
	}
	if opts.HeartbeatTick == 0 {
		opts.HeartbeatTick = 1
	}
	if opts.ElectionTick == 0 {
		opts.ElectionTick = 10
	}
	if opts.SnapshotIntervalSize == 0 {
		opts.SnapshotIntervalSize = 19
	}
	if opts.TickInterval == "" {
		opts.TickInterval = "500ms"
	}
}
func GetProfileConfig(
	ordOrgs []OrdererOrganization,
	config GenesisConfig,
) (*genesisconfig.Profile, error) {
	fillWithDefaultOps(&config)
	organizations := []*genesisconfig.Organization{}
	ordererOrganizations := []*genesisconfig.Organization{}
	consenters := []*etcdraft.Consenter{}
	ordererAddresses := []string{}
	log.Printf("Orderer organization: %d", len(ordOrgs))
	for _, org := range ordOrgs {
		serverRootTlsCertPem := []byte(org.RootTLSCert)
		serverRootSignCertPem := []byte(org.RootSignCert)
		for _, node := range org.Nodes {
			clientTlsCertPem := []byte(node.TLSCert)
			serverTlsCertPem := []byte(node.TLSCert)
			clientCertFile, err := os.CreateTemp("", "clientcert")
			if err != nil {
				return nil, err
			}
			err = os.WriteFile(clientCertFile.Name(), clientTlsCertPem, 0600)
			if err != nil {
				return nil, err
			}

			serverCertFile, err := os.CreateTemp("", "servercert")
			if err != nil {
				return nil, err
			}
			err = os.WriteFile(serverCertFile.Name(), serverTlsCertPem, 0600)
			if err != nil {
				return nil, err
			}
			ordererHost := node.Host
			ordererPort := node.Port
			consenters = append(consenters, &etcdraft.Consenter{
				Host:          ordererHost,
				Port:          uint32(ordererPort),
				ClientTlsCert: []byte(clientCertFile.Name()),
				ServerTlsCert: []byte(serverCertFile.Name()),
			})

			ordererAddresses = append(ordererAddresses, fmt.Sprintf("%s:%d", ordererHost, ordererPort))
		}
		ordererOrgMspDir, err := os.MkdirTemp("", fmt.Sprintf("mspdir_%s", org.MspID))
		if err != nil {
			return nil, err
		}
		tlsCaCertsPath := path.Join(ordererOrgMspDir, "tlscacerts")
		err = os.Mkdir(tlsCaCertsPath, 0750)
		if err != nil {
			return nil, err
		}
		caCertsPath := path.Join(ordererOrgMspDir, "cacerts")
		err = os.Mkdir(caCertsPath, 0750)
		if err != nil {
			return nil, err
		}
		err = os.WriteFile(path.Join(caCertsPath, "cacert.pem"), serverRootSignCertPem, 0600)
		if err != nil {
			return nil, err
		}
		err = os.WriteFile(path.Join(tlsCaCertsPath, "tlscacert.pem"), serverRootTlsCertPem, 0600)
		if err != nil {
			return nil, err
		}
		configNodeOU := `
NodeOUs:
  Enable: true
  ClientOUIdentifier:
    Certificate: cacerts/cacert.pem
    OrganizationalUnitIdentifier: client
  PeerOUIdentifier:
    Certificate: cacerts/cacert.pem
    OrganizationalUnitIdentifier: peer
  AdminOUIdentifier:
    Certificate: cacerts/cacert.pem
    OrganizationalUnitIdentifier: admin
  OrdererOUIdentifier:
    Certificate: cacerts/cacert.pem
    OrganizationalUnitIdentifier: orderer
`
		err = os.WriteFile(path.Join(ordererOrgMspDir, "config.yaml"), []byte(configNodeOU), 0600)
		if err != nil {
			return nil, err
		}
		log.Printf("MSPDIR=%s", ordererOrgMspDir)
		ordererOrganizations = append(ordererOrganizations, &genesisconfig.Organization{
			Name:    org.MspID,
			ID:      org.MspID,
			MSPDir:  ordererOrgMspDir,
			MSPType: "bccsp",
			Policies: map[string]*genesisconfig.Policy{
				"Readers": {
					Type: "Signature",
					Rule: fmt.Sprintf("OR('%s.member')", org.MspID),
				},
				"Writers": {
					Type: "Signature",
					Rule: fmt.Sprintf("OR('%s.member')", org.MspID),
				},
				"Admins": {
					Type: "Signature",
					Rule: fmt.Sprintf("OR('%s.admin')", org.MspID),
				},
			},
			AnchorPeers:   nil,
			SkipAsForeign: false,
		})
	}
	profileConfig := &genesisconfig.Profile{
		Application: &genesisconfig.Application{
			Organizations: organizations,
			Capabilities: map[string]bool{
				"V2_0": config.ApplicationCapabilities.V2_0,
			},
			Policies: map[string]*genesisconfig.Policy{
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
				"Readers": {
					Type: "ImplicitMeta",
					Rule: "ANY Readers",
				},
				"Writers": {
					Type: "ImplicitMeta",
					Rule: "ANY Writers",
				},
			},
			ACLs: nil,
		},
		Orderer: &genesisconfig.Orderer{
			OrdererType: "etcdraft",
			EtcdRaft: &etcdraft.ConfigMetadata{
				Consenters: consenters,
				Options: &etcdraft.Options{
					SnapshotIntervalSize: uint32(config.SnapshotIntervalSize),
					TickInterval:         config.TickInterval,
					ElectionTick:         uint32(config.ElectionTick),
					HeartbeatTick:        uint32(config.HeartbeatTick),
					MaxInflightBlocks:    uint32(config.MaxInflightBlocks),
				},
			},
			Addresses:    ordererAddresses,
			BatchTimeout: config.BatchTimeout,
			BatchSize: genesisconfig.BatchSize{
				MaxMessageCount:   uint32(config.MaxMessageCount),
				AbsoluteMaxBytes:  uint32(config.AbsoluteMaxBytes),
				PreferredMaxBytes: uint32(config.PreferredMaxBytes),
			},
			Organizations: ordererOrganizations,
			Policies: map[string]*genesisconfig.Policy{
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
					Rule: "ANY Admins",
				},
				"BlockValidation": {
					Type: "ImplicitMeta",
					Rule: "ANY Writers",
				},
			},
			Capabilities: map[string]bool{
				"V2_0": config.OrdererCapabilities.V2_0,
			},
		},
		Consortiums: map[string]*genesisconfig.Consortium{},
		Capabilities: map[string]bool{
			"V2_0": config.ChannelCapabilities.V2_0,
		},
		Policies: map[string]*genesisconfig.Policy{
			"Admins": {
				Type: "ImplicitMeta",
				Rule: "MAJORITY Admins",
			},
			"Readers": {
				Type: "ImplicitMeta",
				Rule: "ANY Readers",
			},
			"Writers": {
				Type: "ImplicitMeta",
				Rule: "ANY Writers",
			},
		},
	}
	return profileConfig, nil
}

func GetConfigEnvelopeBytes(configUpdate *cb.ConfigUpdate) ([]byte, error) {
	var buf bytes.Buffer
	if err := protolator.DeepMarshalJSON(&buf, configUpdate); err != nil {
		return nil, err
	}
	channelConfigBytes, err := proto.Marshal(configUpdate)
	if err != nil {
		return nil, err
	}
	configUpdateEnvelope := &cb.ConfigUpdateEnvelope{
		ConfigUpdate: channelConfigBytes,
		Signatures:   nil,
	}
	configUpdateEnvelopeBytes, err := proto.Marshal(configUpdateEnvelope)
	if err != nil {
		return nil, err
	}
	payload := &cb.Payload{
		Data: configUpdateEnvelopeBytes,
	}
	payloadBytes, err := proto.Marshal(payload)
	if err != nil {
		return nil, err
	}
	configEnvelope := &cb.Envelope{
		Payload: payloadBytes,
	}
	return proto.Marshal(configEnvelope)
}

func GetChannelProfileConfig(
	ordService OrdererOrganization,
	members []PeerOrganization,
	consortiumName string,
	adminPolicy string,
) (*genesisconfig.Profile, error) {
	var organizations []*genesisconfig.Organization

	var ordererOrganizations []*genesisconfig.Organization
	var consenters []*etcdraft.Consenter
	var ordererAddresses []string

	for _, node := range ordService.Nodes {
		clientTlsCertPem := []byte(node.TLSCert)
		serverTlsCertPem := []byte(node.TLSCert)
		clientCertFile, err := os.CreateTemp("", "clientcert")
		if err != nil {
			return nil, err
		}
		err = os.WriteFile(clientCertFile.Name(), clientTlsCertPem, 0600)
		if err != nil {
			return nil, err
		}

		serverCertFile, err := os.CreateTemp("", "servercert")
		if err != nil {
			return nil, err
		}
		err = os.WriteFile(serverCertFile.Name(), serverTlsCertPem, 0600)
		if err != nil {
			return nil, err
		}
		ordererHost := node.Host
		ordererPort := node.Port
		consenters = append(consenters, &etcdraft.Consenter{
			Host:          ordererHost,
			Port:          uint32(ordererPort),
			ClientTlsCert: []byte(clientCertFile.Name()),
			ServerTlsCert: []byte(serverCertFile.Name()),
		})

		ordererAddresses = append(ordererAddresses, fmt.Sprintf("%s:%d", ordererHost, ordererPort))
	}
	ordererOrgMspDir, err := os.MkdirTemp("", fmt.Sprintf("mspdir_%s", ordService.MspID))
	if err != nil {
		return nil, err
	}
	tlsCaCertsPath := path.Join(ordererOrgMspDir, "tlscacerts")
	err = os.Mkdir(tlsCaCertsPath, 0750)
	if err != nil {
		return nil, err
	}
	caCertsPath := path.Join(ordererOrgMspDir, "cacerts")
	err = os.Mkdir(caCertsPath, 0750)
	if err != nil {
		return nil, err
	}

	serverRootCertPem := []byte(ordService.RootSignCert)
	serverRootTlsCertPem := []byte(ordService.RootTLSCert)
	err = os.WriteFile(path.Join(caCertsPath, "cacert.pem"), serverRootCertPem, 0600)
	if err != nil {
		return nil, err
	}
	err = os.WriteFile(path.Join(tlsCaCertsPath, "tlscacert.pem"), serverRootTlsCertPem, 0600)
	if err != nil {
		return nil, err
	}
	configNodeOU := `
NodeOUs:
  Enable: true
  ClientOUIdentifier:
    Certificate: cacerts/cacert.pem
    OrganizationalUnitIdentifier: client
  PeerOUIdentifier:
    Certificate: cacerts/cacert.pem
    OrganizationalUnitIdentifier: peer
  AdminOUIdentifier:
    Certificate: cacerts/cacert.pem
    OrganizationalUnitIdentifier: admin
  OrdererOUIdentifier:
    Certificate: cacerts/cacert.pem
    OrganizationalUnitIdentifier: orderer
`
	err = os.WriteFile(path.Join(ordererOrgMspDir, "config.yaml"), []byte(configNodeOU), 0600)
	if err != nil {
		return nil, err
	}
	log.Printf("MSPDIR=%s", ordererOrgMspDir)
	ordererOrganizations = append(ordererOrganizations, &genesisconfig.Organization{
		Name:    ordService.MspID,
		ID:      ordService.MspID,
		MSPDir:  ordererOrgMspDir,
		MSPType: "bccsp",
		Policies: map[string]*genesisconfig.Policy{
			"Readers": {
				Type: "Signature",
				Rule: fmt.Sprintf("OR('%s.member')", ordService.MspID),
			},
			"Writers": {
				Type: "Signature",
				Rule: fmt.Sprintf("OR('%s.member')", ordService.MspID),
			},
			"Admins": {
				Type: "Signature",
				Rule: fmt.Sprintf("OR('%s.admin')", ordService.MspID),
			},
		},
		AnchorPeers:   nil,
		SkipAsForeign: false,
	})
	log.Printf("Members: %d", len(members))
	for _, member := range members {
		peerOrg, err := memberToOrg(member)
		if err != nil {
			return nil, err
		}
		organizations = append(organizations, peerOrg)
	}
	profileConfig := &genesisconfig.Profile{
		Consortium: consortiumName,
		Application: &genesisconfig.Application{
			Organizations: organizations,
			Capabilities:  ordererCapabilities(),
			Policies: map[string]*genesisconfig.Policy{
				"Admins": {
					Type: "Signature",
					Rule: adminPolicy,
				},
				"Endorsement": {
					Type: "ImplicitMeta",
					Rule: "MAJORITY Endorsement",
				},
				"LifecycleEndorsement": {
					Type: "ImplicitMeta",
					Rule: "MAJORITY Endorsement",
				},
				"Readers": {
					Type: "ImplicitMeta",
					Rule: "ANY Readers",
				},
				"Writers": {
					Type: "ImplicitMeta",
					Rule: "ANY Writers",
				},
			},
			ACLs: nil,
		},
		Orderer: &genesisconfig.Orderer{
			OrdererType: "etcdraft",
			EtcdRaft: &etcdraft.ConfigMetadata{
				Consenters: consenters,
				Options: &etcdraft.Options{
					SnapshotIntervalSize: 19,
					TickInterval:         "500ms",
					ElectionTick:         10,
					HeartbeatTick:        1,
					MaxInflightBlocks:    5,
				},
			},
			Addresses:    ordererAddresses,
			BatchTimeout: 2 * time.Second,
			BatchSize: genesisconfig.BatchSize{
				MaxMessageCount:   500,
				AbsoluteMaxBytes:  10 * 1024 * 1024,
				PreferredMaxBytes: 2 * 1024 * 1024,
			},
			Organizations: ordererOrganizations,
			Policies: map[string]*genesisconfig.Policy{
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
					Rule: "ANY Admins",
				},
				"BlockValidation": {
					Type: "ImplicitMeta",
					Rule: "ANY Writers",
				},
			},
			Capabilities: ordererCapabilities(),
		},
		Capabilities: ordererCapabilities(),
		Policies: map[string]*genesisconfig.Policy{
			"Admins": {
				Type: "ImplicitMeta",
				Rule: "MAJORITY Admins",
			},
			"Readers": {
				Type: "ImplicitMeta",
				Rule: "ANY Readers",
			},
			"Writers": {
				Type: "ImplicitMeta",
				Rule: "ANY Writers",
			},
		},
	}
	return profileConfig, nil
}
