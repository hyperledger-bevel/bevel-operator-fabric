package helpers

import (
	"context"
	"fmt"
	"strings"

	"github.com/kfsoftware/hlf-operator/controllers/utils"
	"k8s.io/client-go/kubernetes"

	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	operatorv1 "github.com/kfsoftware/hlf-operator/pkg/client/clientset/versioned"
	"github.com/pkg/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type OrganizationType = string

const (
	PeerType    = "PEER"
	OrdererType = "ORDERER"
)

type Organization struct {
	Type         OrganizationType
	MspID        string
	OrdererNodes []*ClusterOrdererNode
	Peers        []*ClusterPeer
	Users        []OrgUser
}
type OrgUser struct {
	Name string
	Cert string
	Key  string
}

type ClusterCA struct {
	Object     hlfv1alpha1.FabricCA
	Spec       hlfv1alpha1.FabricCASpec
	Status     hlfv1alpha1.FabricCAStatus
	Name       string
	PublicURL  string
	PrivateURL string
	EnrollID   string
	EnrollPWD  string
	Item       hlfv1alpha1.FabricCA
	Namespace  string
}

func (c ClusterCA) GetFullName() string {
	return fmt.Sprintf("%s.%s", c.Object.Name, c.Object.Namespace)
}

type ClusterOrderingService struct {
	MSPID    string
	Name     string
	Object   hlfv1alpha1.FabricOrderingService
	Spec     hlfv1alpha1.FabricOrderingServiceSpec
	Status   hlfv1alpha1.FabricOrderingServiceStatus
	Orderers []*ClusterOrdererNode
}

type ClusterOrdererNode struct {
	ObjectMeta v1.ObjectMeta
	Name       string
	PublicURL  string
	PrivateURL string
	AdminURL   string
	Spec       hlfv1alpha1.FabricOrdererNodeSpec
	Status     hlfv1alpha1.FabricOrdererNodeStatus
	Item       hlfv1alpha1.FabricOrdererNode
	Namespace  string
}

type ClusterPeer struct {
	Name       string
	Object     hlfv1alpha1.FabricPeer
	Spec       hlfv1alpha1.FabricPeerSpec
	Status     hlfv1alpha1.FabricPeerStatus
	PublicURL  string
	PrivateURL string
	TLSCACert  string
	RootCert   string
	Identity   Identity
	MSPID      string
	ObjectMeta v1.ObjectMeta
	Namespace  string
}
type Identity struct {
	Key  string
	Cert string
}

func MapClusterCA(clientSet *kubernetes.Clientset, certAuth hlfv1alpha1.FabricCA) (*ClusterCA, error) {
	certauthName := fmt.Sprintf("%s.%s", certAuth.Name, certAuth.Namespace)
	privateURL := GetCAPrivateURL(certAuth)
	publicURL, err := GetCAPublicURL(clientSet, certAuth)
	if err != nil {
		return nil, err
	}
	certAuthIdentities := certAuth.Spec.CA.Registry.Identities
	var enrollId string
	var enrollPwd string
	if len(certAuthIdentities) > 0 {
		enrollId = certAuthIdentities[0].Name
		enrollPwd = certAuthIdentities[0].Pass
	}
	return &ClusterCA{
		Object:     certAuth,
		Spec:       certAuth.Spec,
		Status:     certAuth.Status,
		Name:       certauthName,
		Namespace:  certAuth.Namespace,
		PublicURL:  publicURL,
		PrivateURL: privateURL,
		EnrollID:   enrollId,
		EnrollPWD:  enrollPwd,
		Item:       certAuth,
	}, nil
}

func MapClusterPeer(clientSet *kubernetes.Clientset, peer hlfv1alpha1.FabricPeer) (*ClusterPeer, error) {
	publicURL, err := GetPeerPublicURL(clientSet, peer)
	if err != nil {
		return nil, err
	}
	privateURL := GetPeerPrivateURL(peer)
	return &ClusterPeer{
		Name:       peer.FullName(),
		ObjectMeta: peer.ObjectMeta,
		Namespace:  peer.Namespace,
		Object:     peer,
		Spec:       peer.Spec,
		Status:     peer.Status,
		Identity:   Identity{},
		PublicURL:  publicURL,
		PrivateURL: privateURL,
		MSPID:      peer.Spec.MspID,
	}, nil
}

func MapClusterOrdererNode(clientSet *kubernetes.Clientset, ordNode hlfv1alpha1.FabricOrdererNode) (*ClusterOrdererNode, error) {
	publicURL, err := GetOrdererPublicURL(clientSet, ordNode)
	if err != nil {
		return nil, err
	}
	adminPublicURL, err := GetAdminOrdererPublicURL(clientSet, ordNode)
	if err != nil {
		return nil, err
	}
	privateURL := GetOrdererPrivateURL(ordNode)
	return &ClusterOrdererNode{
		Name:       ordNode.FullName(),
		AdminURL:   adminPublicURL,
		Namespace:  ordNode.Namespace,
		ObjectMeta: ordNode.ObjectMeta,
		Spec:       ordNode.Spec,
		Status:     ordNode.Status,
		PublicURL:  publicURL,
		PrivateURL: privateURL,
		Item:       ordNode,
	}, nil
}
func GetClusterCAs(clientSet *kubernetes.Clientset, oclient *operatorv1.Clientset, ns string) ([]*ClusterCA, error) {
	ctx := context.Background()
	certAuthsRes, err := oclient.HlfV1alpha1().FabricCAs(ns).List(ctx, v1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var certAuths []*ClusterCA
	for _, certAuth := range certAuthsRes.Items {
		clusterCA, err := MapClusterCA(clientSet, certAuth)
		if err != nil {
			return nil, err
		}
		certAuths = append(certAuths, clusterCA)
	}
	return certAuths, nil
}

func GetClusterOrderers(
	clientSet *kubernetes.Clientset,
	oclient *operatorv1.Clientset,
	ns string,
) ([]*Organization, []*ClusterOrderingService, error) {
	ctx := context.Background()
	ordererNodes, err := oclient.HlfV1alpha1().FabricOrdererNodes(ns).List(ctx, v1.ListOptions{})
	if err != nil {
		return nil, nil, err
	}
	orderingServices, err := oclient.HlfV1alpha1().FabricOrderingServices(ns).List(ctx, v1.ListOptions{})
	if err != nil {
		return nil, nil, err
	}
	var orderers []*ClusterOrderingService
	if len(ordererNodes.Items) > 0 {
		orderingService := &ClusterOrderingService{
			Name:     ordererNodes.Items[0].FullName(),
			MSPID:    ordererNodes.Items[0].Spec.MspID,
			Orderers: []*ClusterOrdererNode{},
		}
		orderers = append(orderers, orderingService)
		for _, ordNode := range ordererNodes.Items {
			publicURL, err := GetOrdererPublicURL(clientSet, ordNode)
			if err != nil {
				return nil, nil, err
			}
			privateURL := GetOrdererPrivateURL(ordNode)
			adminPublicURL, err := GetAdminOrdererPublicURL(clientSet, ordNode)
			if err != nil {
				return nil, nil, err
			}
			orderingService.Orderers = append(
				orderingService.Orderers,
				&ClusterOrdererNode{
					AdminURL:   adminPublicURL,
					Name:       ordNode.FullName(),
					ObjectMeta: ordNode.ObjectMeta,
					Spec:       ordNode.Spec,
					Status:     ordNode.Status,
					PublicURL:  publicURL,
					PrivateURL: privateURL,
					Item:       ordNode,
				},
			)
		}
	}
	for _, ordService := range orderingServices.Items {
		ordNodesRes, err := oclient.HlfV1alpha1().FabricOrdererNodes(ns).List(
			ctx,
			v1.ListOptions{
				LabelSelector: fmt.Sprintf("release=%s", ordService.Name),
			},
		)
		if err != nil {
			return nil, nil, err
		}
		orderingService := &ClusterOrderingService{
			Name:     ordService.FullName(),
			Object:   ordService,
			MSPID:    ordService.Spec.MspID,
			Spec:     ordService.Spec,
			Status:   ordService.Status,
			Orderers: []*ClusterOrdererNode{},
		}
		orderers = append(orderers, orderingService)
		for _, ordNode := range ordNodesRes.Items {
			orderingService.Orderers = append(
				orderingService.Orderers,
				&ClusterOrdererNode{
					Name:   ordNode.FullName(),
					Spec:   ordNode.Spec,
					Status: ordNode.Status,
				},
			)
		}
	}
	if len(orderers) == 0 {
		return nil, nil, nil
	}
	var organizations []*Organization
	for _, ord := range orderers {
		org := &Organization{
			Type:         OrdererType,
			MspID:        ord.MSPID,
			OrdererNodes: []*ClusterOrdererNode{},
			Peers:        []*ClusterPeer{},
		}
		organizations = append(organizations, org)
	}
	return organizations, orderers, nil
}

func GetClusterOrdererNodes(
	clientSet *kubernetes.Clientset,
	oclient *operatorv1.Clientset,
	ns string,
) ([]*ClusterOrdererNode, error) {
	ctx := context.Background()
	ordererNodeList, err := oclient.HlfV1alpha1().FabricOrdererNodes(ns).List(ctx, v1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var ordererNodes []*ClusterOrdererNode

	for _, ordNode := range ordererNodeList.Items {
		publicURL, err := GetOrdererPublicURL(clientSet, ordNode)
		if err != nil {
			return nil, err
		}
		privateURL := GetOrdererPrivateURL(ordNode)
		adminPublicURL, err := GetAdminOrdererPublicURL(clientSet, ordNode)
		if err != nil {
			return nil, err
		}
		ordererNodes = append(
			ordererNodes,
			&ClusterOrdererNode{
				Name:       ordNode.FullName(),
				AdminURL:   adminPublicURL,
				Namespace:  ordNode.Namespace,
				PublicURL:  publicURL,
				PrivateURL: privateURL,
				Spec:       ordNode.Spec,
				Status:     ordNode.Status,
				Item:       ordNode,
			},
		)
	}
	return ordererNodes, nil
}
func GetCertAuthByURL(clientSet *kubernetes.Clientset, oclient *operatorv1.Clientset, host string, port int) (*ClusterCA, error) {
	cahost := host
	ns := ""
	if strings.Contains(cahost, ".") && len(strings.Split(cahost, ".")) == 2 {
		chunks := strings.Split(cahost, ".")
		cahost = chunks[0]
		ns = chunks[1]
	}
	certAuths, err := GetClusterCAs(clientSet, oclient, ns)
	if err != nil {
		return nil, err
	}
	for _, certAuth := range certAuths {
		if // if host and port is specified by kubernetes DNS
		utils.Contains(certAuth.Spec.Hosts, host) || certAuth.Item.Name == cahost || (certAuth.Status.NodePort != 7054 && certAuth.Status.NodePort == port) {
			return certAuth, nil
		}

	}
	return nil, errors.Errorf("CA with host=%s port=%d not found", host, port)
}
func GetURLForCA(certAuth *ClusterCA) (string, error) {
	var host string
	var port int
	if certAuth.Spec.Istio != nil && len(certAuth.Spec.Istio.Hosts) > 0 {
		host = certAuth.Spec.Istio.Hosts[0]
		port = certAuth.Spec.Istio.Port
	} else if certAuth.Spec.GatewayApi != nil && len(certAuth.Spec.GatewayApi.Hosts) > 0 {
		host = certAuth.Spec.GatewayApi.Hosts[0]
		port = certAuth.Spec.GatewayApi.Port
	} else if certAuth.Spec.Traefik != nil && len(certAuth.Spec.Traefik.Hosts) > 0 {
		host = certAuth.Spec.Traefik.Hosts[0]
		port = 443
	} else if certAuth.Status.NodePort == 0 {
		// not exposed through a NodePort (e.g. ClusterIP service), use the in-cluster address
		host = fmt.Sprintf("%s.%s", certAuth.Item.Name, certAuth.Item.Namespace)
		port = 7054
	} else {
		client, err := GetKubeClient()
		if err != nil {
			return "", err
		}
		host, err = utils.GetPublicIPKubernetes(client)
		if err != nil {
			return "", err
		}
		port = certAuth.Status.NodePort
	}
	return fmt.Sprintf("https://%s:%d", host, port), nil
}
func GetCertAuthByName(clientSet *kubernetes.Clientset, oclient *operatorv1.Clientset, name string, ns string) (*ClusterCA, error) {
	certAuths, err := GetClusterCAs(clientSet, oclient, "")
	if err != nil {
		return nil, err
	}
	for _, certAuth := range certAuths {
		if certAuth.Object.Name == name && certAuth.Object.Namespace == ns {
			return certAuth, nil
		}

	}
	return nil, errors.Errorf("CA with name=%s not found", name)
}

func GetOrderingServiceByFullName(clientSet *kubernetes.Clientset, oclient *operatorv1.Clientset, name string) (*ClusterOrderingService, error) {
	_, ordServices, err := GetClusterOrderers(clientSet, oclient, "")
	if err != nil {
		return nil, err
	}
	for _, ordService := range ordServices {
		if ordService.Name == name {
			return ordService, nil
		}

	}
	return nil, errors.Errorf("Ordering Service with name=%s not found", name)
}
func GetPeerByFullName(clientSet *kubernetes.Clientset, oclient *operatorv1.Clientset, name string) (*ClusterPeer, error) {
	_, peers, err := GetClusterPeers(clientSet, oclient, "")
	if err != nil {
		return nil, err
	}
	for _, peer := range peers {
		if peer.Name == name {
			return peer, nil
		}

	}
	return nil, errors.Errorf("Peer with name=%s not found", name)
}

type HostPort struct {
	Host string
	Port int
}

func GetOrdererPublicURL(clientset *kubernetes.Clientset, node hlfv1alpha1.FabricOrdererNode) (string, error) {
	hostPort, err := GetOrdererHostPort(clientset, node)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%d", hostPort.Host, hostPort.Port), nil
}
func GetAdminOrdererPublicURL(clientset *kubernetes.Clientset, node hlfv1alpha1.FabricOrdererNode) (string, error) {
	host, port, err := GetOrdererAdminHostAndPort(clientset, node)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("https://%s:%d", host, port), nil
}
func GetOrdererHostAndPort(clientset *kubernetes.Clientset, node hlfv1alpha1.FabricOrdererNode) (string, int, error) {
	nodeSpec, nodeStatus := node.Spec, node.Status
	var hostName string
	var err error
	var ordererPort int
	if nodeSpec.Istio != nil && len(nodeSpec.Istio.Hosts) > 0 {
		hostName = nodeSpec.Istio.Hosts[0]
		ordererPort = nodeSpec.Istio.Port
	} else if nodeSpec.Traefik != nil && len(nodeSpec.Traefik.Hosts) > 0 {
		hostName = nodeSpec.Traefik.Hosts[0]
		ordererPort = 443
	} else if nodeStatus.NodePort == 0 {
		// not exposed through a NodePort (e.g. ClusterIP service), use the in-cluster address
		hostName = fmt.Sprintf("%s.%s", node.Name, node.Namespace)
		ordererPort = 7050
	} else {
		hostName, err = utils.GetPublicIPKubernetes(clientset)
		if err != nil {
			return "", 0, err
		}
		ordererPort = nodeStatus.NodePort
	}
	return hostName, ordererPort, nil
}
func GetPeerHostAndPort(clientset *kubernetes.Clientset, node hlfv1alpha1.FabricPeer) (string, int, error) {
	nodeSpec, nodeStatus := node.Spec, node.Status
	if nodeSpec.Istio != nil && len(nodeSpec.Istio.Hosts) > 0 {
		return nodeSpec.Istio.Hosts[0], nodeSpec.Istio.Port, nil
	}
	if nodeStatus.NodePort == 0 {
		// not exposed through a NodePort (e.g. ClusterIP service), use the in-cluster address
		return fmt.Sprintf("%s.%s", node.Name, node.Namespace), 7051, nil
	}
	hostName, err := utils.GetPublicIPKubernetes(clientset)
	if err != nil {
		return "", 0, err
	}
	return hostName, nodeStatus.NodePort, nil
}
func GetOrdererAdminHostAndPort(clientset *kubernetes.Clientset, node hlfv1alpha1.FabricOrdererNode) (string, int, error) {
	nodeSpec, nodeStatus := node.Spec, node.Status
	var hostName string
	var err error
	var ordererPort int
	if nodeSpec.AdminIstio != nil && len(nodeSpec.AdminIstio.Hosts) > 0 {
		hostName = nodeSpec.AdminIstio.Hosts[0]
		ordererPort = nodeSpec.AdminIstio.Port
	} else if nodeSpec.AdminTraefik != nil && len(nodeSpec.AdminTraefik.Hosts) > 0 {
		hostName = nodeSpec.AdminTraefik.Hosts[0]
		ordererPort = 443
	} else if nodeStatus.AdminPort == 0 {
		// not exposed through a NodePort (e.g. ClusterIP service), use the in-cluster address
		hostName = fmt.Sprintf("%s.%s", node.Name, node.Namespace)
		ordererPort = 7053
	} else {
		hostName, err = utils.GetPublicIPKubernetes(clientset)
		if err != nil {
			return "", 0, err
		}
		ordererPort = nodeStatus.AdminPort
	}
	return hostName, ordererPort, nil
}
func GetOrdererPrivateURL(node hlfv1alpha1.FabricOrdererNode) string {
	return fmt.Sprintf("%s.%s:%s", node.Name, node.Namespace, "7050")
}

func GetCAPublicURL(clientset *kubernetes.Clientset, node hlfv1alpha1.FabricCA) (string, error) {
	hostPort, err := GetCAHostPort(clientset, node)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%d", hostPort.Host, hostPort.Port), nil
}
func GetCAPrivateURL(node hlfv1alpha1.FabricCA) string {
	return fmt.Sprintf("%s.%s:%s", node.Name, node.Namespace, "7054")
}

func GetPeerPublicURL(clientset *kubernetes.Clientset, node hlfv1alpha1.FabricPeer) (string, error) {
	hostPort, err := GetPeerHostPort(clientset, node)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%d", hostPort.Host, hostPort.Port), nil
}
func GetPeerHostPort(clientset *kubernetes.Clientset, node hlfv1alpha1.FabricPeer) (*HostPort, error) {

	if node.Spec.Istio != nil && len(node.Spec.Istio.Hosts) > 0 {
		return &HostPort{
			Host: node.Spec.Istio.Hosts[0],
			Port: node.Spec.Istio.Port,
		}, nil
	}
	if node.Spec.Traefik != nil && len(node.Spec.Traefik.Hosts) > 0 {
		return &HostPort{
			Host: node.Spec.Traefik.Hosts[0],
			Port: 443,
		}, nil
	}
	if node.Spec.GatewayApi != nil && len(node.Spec.GatewayApi.Hosts) > 0 {
		return &HostPort{
			Host: node.Spec.GatewayApi.Hosts[0],
			Port: node.Spec.GatewayApi.Port,
		}, nil
	}
	if node.Status.NodePort == 0 {
		// not exposed through a NodePort (e.g. ClusterIP service), use the in-cluster address
		return &HostPort{
			Host: fmt.Sprintf("%s.%s", node.Name, node.Namespace),
			Port: 7051,
		}, nil
	}
	k8sIP, err := utils.GetPublicIPKubernetes(clientset)
	if err != nil {
		return nil, err
	}
	return &HostPort{
		Host: k8sIP,
		Port: node.Status.NodePort,
	}, nil
}
func GetPeerPrivateURL(node hlfv1alpha1.FabricPeer) string {
	return fmt.Sprintf("%s.%s:%s", node.Name, node.Namespace, "7051")
}
func GetOrdererHostPort(clientset *kubernetes.Clientset, node hlfv1alpha1.FabricOrdererNode) (*HostPort, error) {

	if node.Spec.Istio != nil && len(node.Spec.Istio.Hosts) > 0 {
		return &HostPort{
			Host: node.Spec.Istio.Hosts[0],
			Port: node.Spec.Istio.Port,
		}, nil
	}
	if node.Spec.Traefik != nil && len(node.Spec.Traefik.Hosts) > 0 {
		return &HostPort{
			Host: node.Spec.Traefik.Hosts[0],
			Port: 443,
		}, nil
	}
	if node.Spec.GatewayApi != nil && len(node.Spec.GatewayApi.Hosts) > 0 {
		return &HostPort{
			Host: node.Spec.GatewayApi.Hosts[0],
			Port: node.Spec.GatewayApi.Port,
		}, nil
	}
	if node.Status.NodePort == 0 {
		// not exposed through a NodePort (e.g. ClusterIP service), use the in-cluster address
		return &HostPort{
			Host: fmt.Sprintf("%s.%s", node.Name, node.Namespace),
			Port: 7050,
		}, nil
	}
	k8sIP, err := utils.GetPublicIPKubernetes(clientset)
	if err != nil {
		return nil, err
	}
	return &HostPort{
		Host: k8sIP,
		Port: node.Status.NodePort,
	}, nil
}

func GetCAHostPort(clientset *kubernetes.Clientset, node hlfv1alpha1.FabricCA) (*HostPort, error) {
	if node.Spec.Istio != nil && len(node.Spec.Istio.Hosts) > 0 {
		return &HostPort{
			Host: node.Spec.Istio.Hosts[0],
			Port: node.Spec.Istio.Port,
		}, nil
	}
	if node.Spec.GatewayApi != nil && len(node.Spec.GatewayApi.Hosts) > 0 {
		return &HostPort{
			Host: node.Spec.GatewayApi.Hosts[0],
			Port: node.Spec.GatewayApi.Port,
		}, nil
	}
	if node.Spec.Traefik != nil && len(node.Spec.Traefik.Hosts) > 0 {
		return &HostPort{
			Host: node.Spec.Traefik.Hosts[0],
			Port: 443,
		}, nil
	}
	if node.Status.NodePort == 0 {
		// not exposed through a NodePort (e.g. ClusterIP service), use the in-cluster address
		return &HostPort{
			Host: fmt.Sprintf("%s.%s", node.Name, node.Namespace),
			Port: 7054,
		}, nil
	}
	k8sIP, err := utils.GetPublicIPKubernetes(clientset)
	if err != nil {
		return nil, err
	}
	return &HostPort{
		Host: k8sIP,
		Port: node.Status.NodePort,
	}, nil
}
func GetOrdererNodeByFullName(clientSet *kubernetes.Clientset, oclient *operatorv1.Clientset, name string) (*ClusterOrdererNode, error) {
	ordererNodes, err := GetClusterOrdererNodes(clientSet, oclient, "")
	if err != nil {
		return nil, err
	}
	for _, ordNode := range ordererNodes {
		if ordNode.Name == name {
			return ordNode, nil
		}
	}
	return nil, errors.Errorf("Orderer Node with name=%s not found", name)
}
func GetCertAuthByFullName(clientSet *kubernetes.Clientset, oclient *operatorv1.Clientset, name string) (*ClusterCA, error) {
	certAuths, err := GetClusterCAs(clientSet, oclient, "")
	if err != nil {
		return nil, err
	}
	for _, certAuth := range certAuths {
		if certAuth.Name == name {
			return certAuth, nil
		}

	}
	return nil, errors.Errorf("CA with name=%s not found", name)
}
func GetClusterPeers(
	clientSet *kubernetes.Clientset,
	oclient *operatorv1.Clientset, ns string) ([]*Organization, []*ClusterPeer, error) {
	ctx := context.Background()

	peerResponse, err := oclient.HlfV1alpha1().FabricPeers(ns).List(ctx, v1.ListOptions{})
	if err != nil {
		return nil, nil, err
	}
	var peers []*ClusterPeer
	for _, peer := range peerResponse.Items {
		clusterPeer, err := MapClusterPeer(clientSet, peer)
		if err != nil {
			return nil, nil, err
		}
		peers = append(
			peers,
			clusterPeer,
		)
	}
	orgMap := map[string]*Organization{}
	for _, peer := range peers {
		mspID := peer.Spec.MspID
		org, ok := orgMap[mspID]
		if !ok {
			orgMap[mspID] = &Organization{
				Type:         PeerType,
				MspID:        mspID,
				OrdererNodes: []*ClusterOrdererNode{},
				Peers:        []*ClusterPeer{},
			}
			org = orgMap[mspID]
		}
		org.Peers = append(org.Peers, peer)
	}
	var organizations []*Organization
	for _, org := range orgMap {
		organizations = append(organizations, org)
	}
	return organizations, peers, nil
}
