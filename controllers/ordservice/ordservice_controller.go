package ordservice

import (
	"context"

	"github.com/go-logr/logr"
	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/kfsoftware/hlf-operator/pkg/status"
	"github.com/pkg/errors"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// FabricOrderingServiceReconciler reconciles a FabricOrderingService object
type FabricOrderingServiceReconciler struct {
	client.Client
	ChartPath string
	Log       logr.Logger
	Scheme    *runtime.Scheme
	Config    *rest.Config
}

const ordererFinalizer = "finalizer.orderer.hlf.kungfusoftware.es"

var (
	ErrNotSupported = errors.New("orderingServiceNotSupported")
)

func (r *FabricOrderingServiceReconciler) finalizeOrderer(reqLogger logr.Logger, m *hlfv1alpha1.FabricOrderingService) error {
	ns := m.Namespace
	if ns == "" {
		ns = "default"
	}

	reqLogger.Info("Finalizing ordering service",
		"orderingService", m.Name,
		"namespace", ns,
	)

	reqLogger.Info("Successfully finalized ordering service",
		"orderingService", m.Name,
		"namespace", ns,
	)
	return nil
}

func (r *FabricOrderingServiceReconciler) addFinalizer(reqLogger logr.Logger, m *hlfv1alpha1.FabricOrderingService) error {
	reqLogger.Info("Adding finalizer for ordering service",
		"orderingService", m.Name,
		"namespace", m.Namespace,
		"finalizer", ordererFinalizer,
	)

	controllerutil.AddFinalizer(m, ordererFinalizer)

	if err := r.Update(context.TODO(), m); err != nil {
		reqLogger.Error(err, "Failed to update ordering service with finalizer",
			"orderingService", m.Name,
			"namespace", m.Namespace,
		)
		return errors.Wrap(err, "failed to add finalizer to ordering service")
	}

	reqLogger.Info("Successfully added finalizer to ordering service",
		"orderingService", m.Name,
		"namespace", m.Namespace,
	)
	return nil
}

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricorderingservices,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricorderingservices/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricorderingservices/finalizers,verbs=get;update;patch
func (r *FabricOrderingServiceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	reqLogger := r.Log.WithValues("hlf", req.NamespacedName)

	reqLogger.Info("Starting ordering service reconciliation",
		"orderingService", req.Name,
		"namespace", req.Namespace,
	)

	fabricOrderer := &hlfv1alpha1.FabricOrderingService{}

	// Note: This controller currently marks ordering services as not supported
	// This is a placeholder implementation
	reqLogger.Info("Ordering service functionality not yet implemented",
		"orderingService", req.Name,
		"namespace", req.Namespace,
	)

	fabricOrderer.Status.Status = hlfv1alpha1.PendingStatus
	fabricOrderer.Status.Conditions.SetCondition(status.Condition{
		Type:   "NOT_SUPPORTED",
		Status: "True",
	})

	if err := r.Status().Update(ctx, fabricOrderer); err != nil {
		reqLogger.Error(err, "Failed to update ordering service status")
		return ctrl.Result{}, errors.Wrap(err, "failed to update ordering service status")
	}

	return ctrl.Result{}, nil
}

func (r *FabricOrderingServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&hlfv1alpha1.FabricOrderingService{}).
		Owns(&appsv1.Deployment{}).
		Complete(r)
}
