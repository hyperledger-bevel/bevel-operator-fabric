package peer_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kfsoftware/hlf-operator/controllers/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func TestGetDefaultExternalEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/nodes" {
			http.NotFound(w, r)
			return
		}
		nodes := corev1.NodeList{
			TypeMeta: metav1.TypeMeta{Kind: "NodeList", APIVersion: "v1"},
			Items: []corev1.Node{{Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.0.1"}},
			}}},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(nodes)
	}))
	defer srv.Close()
	clientset, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL})
	require.NoError(t, err)

	svc := func(nodePort int32) *corev1.Service {
		return &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "org1-peer0", Namespace: "fabric"},
			Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{
				{Name: peer.PeerPortName, Port: 7051, NodePort: nodePort},
			}},
		}
	}

	endpoint, err := peer.GetDefaultExternalEndpoint(clientset, svc(30751))
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.1:30751", endpoint)

	endpoint, err = peer.GetDefaultExternalEndpoint(clientset, svc(0))
	require.NoError(t, err)
	assert.Equal(t, "org1-peer0.fabric:7051", endpoint)
}
