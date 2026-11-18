package utils

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func chartLabels(app, release string) map[string]string {
	return map[string]string{
		"app":      app,
		"release":  release,
		"heritage": "Helm",
		"chart":    app + "-1.0.0",
	}
}

func TestHelmChartObjectDeleted(t *testing.T) {
	p := HelmChartObjectDeleted("hlf-peer")
	peerDeployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Name: "org1-peer0", Namespace: "fabric", Labels: chartLabels("hlf-peer", "org1-peer0"),
	}}

	tests := []struct {
		name     string
		obj      client.Object
		expected bool
	}{
		{name: "Peer chart Deployment", obj: peerDeployment, expected: true},
		{
			name: "Peer chart PVC",
			obj: &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
				Name: "org1-peer0", Namespace: "fabric", Labels: chartLabels("hlf-peer", "org1-peer0"),
			}},
			expected: true,
		},
		{
			name: "Other chart",
			obj: &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
				Name: "org1-ca", Namespace: "fabric", Labels: chartLabels("hlf-ca", "org1-ca"),
			}},
			expected: false,
		},
		{
			name: "Not managed by Helm",
			obj: &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
				Name: "org1-peer0", Namespace: "fabric", Labels: map[string]string{"app": "hlf-peer", "release": "org1-peer0"},
			}},
			expected: false,
		},
		{
			name:     "No labels",
			obj:      &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "fabric"}},
			expected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, p.Delete(event.DeleteEvent{Object: tt.obj}))
		})
	}

	// only deletions trigger a reconcile, status updates of the Deployment must not
	assert.False(t, p.Create(event.CreateEvent{Object: peerDeployment}))
	assert.False(t, p.Update(event.UpdateEvent{ObjectOld: peerDeployment, ObjectNew: peerDeployment}))
	assert.False(t, p.Generic(event.GenericEvent{Object: peerDeployment}))
}

func TestEnqueueHelmReleaseOwner(t *testing.T) {
	h := EnqueueHelmReleaseOwner()
	q := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	defer q.ShutDown()

	h.Delete(context.Background(), event.DeleteEvent{Object: &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Name: "org1-peer0", Namespace: "fabric", Labels: chartLabels("hlf-peer", "org1-peer0"),
	}}}, q)
	h.Delete(context.Background(), event.DeleteEvent{Object: &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Name: "no-release", Namespace: "fabric",
	}}}, q)

	assert.Equal(t, 1, q.Len())
	item, _ := q.Get()
	assert.Equal(t, reconcile.Request{NamespacedName: types.NamespacedName{Name: "org1-peer0", Namespace: "fabric"}}, item)
}
