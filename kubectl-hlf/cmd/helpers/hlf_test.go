package helpers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// newNodeClientset returns a clientset backed by a test API server that lists
// a single node with the given internal IP.
func newNodeClientset(t *testing.T, internalIP string) *kubernetes.Clientset {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/nodes" {
			http.NotFound(w, r)
			return
		}
		nodes := corev1.NodeList{
			TypeMeta: metav1.TypeMeta{Kind: "NodeList", APIVersion: "v1"},
			Items: []corev1.Node{{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: internalIP}},
				},
			}},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(nodes)
	}))
	t.Cleanup(srv.Close)
	clientset, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL})
	require.NoError(t, err)
	return clientset
}

func TestGetPeerHostPort(t *testing.T) {
	clientset := newNodeClientset(t, "10.0.0.1")
	tests := []struct {
		name     string
		peer     hlfv1alpha1.FabricPeer
		expected HostPort
	}{
		{
			name: "Istio host",
			peer: hlfv1alpha1.FabricPeer{
				ObjectMeta: metav1.ObjectMeta{Name: "org1-peer0", Namespace: "fabric"},
				Spec: hlfv1alpha1.FabricPeerSpec{
					Istio: &hlfv1alpha1.FabricIstio{Hosts: []string{"peer0.example.com"}, Port: 443},
				},
			},
			expected: HostPort{Host: "peer0.example.com", Port: 443},
		},
		{
			name: "NodePort service",
			peer: hlfv1alpha1.FabricPeer{
				ObjectMeta: metav1.ObjectMeta{Name: "org1-peer0", Namespace: "fabric"},
				Status:     hlfv1alpha1.FabricPeerStatus{NodePort: 30751},
			},
			expected: HostPort{Host: "10.0.0.1", Port: 30751},
		},
		{
			name: "ClusterIP service without NodePort",
			peer: hlfv1alpha1.FabricPeer{
				ObjectMeta: metav1.ObjectMeta{Name: "org1-peer0", Namespace: "fabric"},
			},
			expected: HostPort{Host: "org1-peer0.fabric", Port: 7051},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hostPort, err := GetPeerHostPort(clientset, tt.peer)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, *hostPort)
		})
	}
}

func TestGetOrdererHostPort(t *testing.T) {
	clientset := newNodeClientset(t, "10.0.0.1")
	tests := []struct {
		name     string
		orderer  hlfv1alpha1.FabricOrdererNode
		expected HostPort
	}{
		{
			name: "Istio host",
			orderer: hlfv1alpha1.FabricOrdererNode{
				ObjectMeta: metav1.ObjectMeta{Name: "ord-node1", Namespace: "fabric"},
				Spec: hlfv1alpha1.FabricOrdererNodeSpec{
					Istio: &hlfv1alpha1.FabricIstio{Hosts: []string{"orderer0.example.com"}, Port: 443},
				},
			},
			expected: HostPort{Host: "orderer0.example.com", Port: 443},
		},
		{
			name: "NodePort service",
			orderer: hlfv1alpha1.FabricOrdererNode{
				ObjectMeta: metav1.ObjectMeta{Name: "ord-node1", Namespace: "fabric"},
				Status:     hlfv1alpha1.FabricOrdererNodeStatus{NodePort: 30750},
			},
			expected: HostPort{Host: "10.0.0.1", Port: 30750},
		},
		{
			name: "ClusterIP service without NodePort",
			orderer: hlfv1alpha1.FabricOrdererNode{
				ObjectMeta: metav1.ObjectMeta{Name: "ord-node1", Namespace: "fabric"},
			},
			expected: HostPort{Host: "ord-node1.fabric", Port: 7050},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hostPort, err := GetOrdererHostPort(clientset, tt.orderer)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, *hostPort)
		})
	}
}

func TestGetOrdererHostAndPort(t *testing.T) {
	clientset := newNodeClientset(t, "10.0.0.1")
	meta := metav1.ObjectMeta{Name: "ord-node1", Namespace: "fabric"}
	tests := []struct {
		name         string
		orderer      hlfv1alpha1.FabricOrdererNode
		expectedHost string
		expectedPort int
	}{
		{
			name:         "NodePort service",
			orderer:      hlfv1alpha1.FabricOrdererNode{ObjectMeta: meta, Status: hlfv1alpha1.FabricOrdererNodeStatus{NodePort: 30750}},
			expectedHost: "10.0.0.1",
			expectedPort: 30750,
		},
		{
			name:         "ClusterIP service without NodePort",
			orderer:      hlfv1alpha1.FabricOrdererNode{ObjectMeta: meta},
			expectedHost: "ord-node1.fabric",
			expectedPort: 7050,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := GetOrdererHostAndPort(clientset, tt.orderer)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedHost, host)
			assert.Equal(t, tt.expectedPort, port)
		})
	}
}

func TestGetOrdererAdminHostAndPort(t *testing.T) {
	clientset := newNodeClientset(t, "10.0.0.1")
	meta := metav1.ObjectMeta{Name: "ord-node1", Namespace: "fabric"}
	tests := []struct {
		name         string
		orderer      hlfv1alpha1.FabricOrdererNode
		expectedHost string
		expectedPort int
	}{
		{
			name: "Admin Istio host",
			orderer: hlfv1alpha1.FabricOrdererNode{ObjectMeta: meta, Spec: hlfv1alpha1.FabricOrdererNodeSpec{
				AdminIstio: &hlfv1alpha1.FabricIstio{Hosts: []string{"admin-ord.example.com"}, Port: 443},
			}},
			expectedHost: "admin-ord.example.com",
			expectedPort: 443,
		},
		{
			name:         "NodePort service",
			orderer:      hlfv1alpha1.FabricOrdererNode{ObjectMeta: meta, Status: hlfv1alpha1.FabricOrdererNodeStatus{AdminPort: 30753}},
			expectedHost: "10.0.0.1",
			expectedPort: 30753,
		},
		{
			name:         "ClusterIP service without NodePort",
			orderer:      hlfv1alpha1.FabricOrdererNode{ObjectMeta: meta},
			expectedHost: "ord-node1.fabric",
			expectedPort: 7053,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := GetOrdererAdminHostAndPort(clientset, tt.orderer)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedHost, host)
			assert.Equal(t, tt.expectedPort, port)
		})
	}
}

func TestGetPeerHostAndPort(t *testing.T) {
	clientset := newNodeClientset(t, "10.0.0.1")
	meta := metav1.ObjectMeta{Name: "org1-peer0", Namespace: "fabric"}
	tests := []struct {
		name         string
		peer         hlfv1alpha1.FabricPeer
		expectedHost string
		expectedPort int
	}{
		{
			name: "Istio host",
			peer: hlfv1alpha1.FabricPeer{ObjectMeta: meta, Spec: hlfv1alpha1.FabricPeerSpec{
				Istio: &hlfv1alpha1.FabricIstio{Hosts: []string{"peer0.example.com"}, Port: 443},
			}},
			expectedHost: "peer0.example.com",
			expectedPort: 443,
		},
		{
			name:         "NodePort service without Istio",
			peer:         hlfv1alpha1.FabricPeer{ObjectMeta: meta, Status: hlfv1alpha1.FabricPeerStatus{NodePort: 30751}},
			expectedHost: "10.0.0.1",
			expectedPort: 30751,
		},
		{
			name:         "ClusterIP service without NodePort",
			peer:         hlfv1alpha1.FabricPeer{ObjectMeta: meta},
			expectedHost: "org1-peer0.fabric",
			expectedPort: 7051,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := GetPeerHostAndPort(clientset, tt.peer)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedHost, host)
			assert.Equal(t, tt.expectedPort, port)
		})
	}
}

func TestGetCAHostPort(t *testing.T) {
	clientset := newNodeClientset(t, "10.0.0.1")
	meta := metav1.ObjectMeta{Name: "org1-ca", Namespace: "fabric"}

	hostPort, err := GetCAHostPort(clientset, hlfv1alpha1.FabricCA{ObjectMeta: meta, Status: hlfv1alpha1.FabricCAStatus{NodePort: 30754}})
	require.NoError(t, err)
	assert.Equal(t, HostPort{Host: "10.0.0.1", Port: 30754}, *hostPort)

	hostPort, err = GetCAHostPort(clientset, hlfv1alpha1.FabricCA{ObjectMeta: meta})
	require.NoError(t, err)
	assert.Equal(t, HostPort{Host: "org1-ca.fabric", Port: 7054}, *hostPort)
}

func TestGetURLForCAWithoutNodePort(t *testing.T) {
	ca := hlfv1alpha1.FabricCA{ObjectMeta: metav1.ObjectMeta{Name: "org1-ca", Namespace: "fabric"}}
	url, err := GetURLForCA(&ClusterCA{Item: ca, Spec: ca.Spec, Status: ca.Status})
	require.NoError(t, err)
	assert.Equal(t, "https://org1-ca.fabric:7054", url)
}
