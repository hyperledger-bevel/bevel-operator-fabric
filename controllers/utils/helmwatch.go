package utils

import (
	"context"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// Objects rendered by the hlf-* charts carry the standard labels
// (app, release, heritage) but no owner references, so Owns() never maps
// them back to the custom resource that created the release.

// EnqueueHelmReleaseOwner enqueues the custom resource named after the Helm
// release (the "release" label) in the object's namespace.
func EnqueueHelmReleaseOwner() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(_ context.Context, obj client.Object) []reconcile.Request {
		release := obj.GetLabels()["release"]
		if release == "" {
			return nil
		}
		return []reconcile.Request{{
			NamespacedName: types.NamespacedName{Name: release, Namespace: obj.GetNamespace()},
		}}
	})
}

// HelmChartObjectDeleted only accepts delete events for objects rendered by
// the given chart, so that out-of-band deletions trigger a reconcile (and a
// Helm upgrade that recreates them) without reacting to status updates.
func HelmChartObjectDeleted(chartName string) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc:  func(event.CreateEvent) bool { return false },
		UpdateFunc:  func(event.UpdateEvent) bool { return false },
		GenericFunc: func(event.GenericEvent) bool { return false },
		DeleteFunc: func(e event.DeleteEvent) bool {
			labels := e.Object.GetLabels()
			return labels["heritage"] == "Helm" && labels["app"] == chartName && labels["release"] != ""
		},
	}
}
