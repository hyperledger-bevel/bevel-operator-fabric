package console

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/kfsoftware/hlf-operator/pkg/status"
	"github.com/pkg/errors"

	"helm.sh/helm/v3/pkg/cli"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/go-logr/logr"
	"github.com/kfsoftware/hlf-operator/controllers/utils"
	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/storage/driver"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// FabricOperationsConsoleReconciler reconciles a FabricOperationsConsole object
type FabricOperationsConsoleReconciler struct {
	client.Client
	ChartPath string
	Log       logr.Logger
	Scheme    *runtime.Scheme
	Config    *rest.Config
}

var (
	ErrInvalidConfig = errors.New("invalidConfigurationError")
	ErrHelmOperation = errors.New("helmOperationError")
)

func (r *FabricOperationsConsoleReconciler) addFinalizer(reqLogger logr.Logger, m *hlfv1alpha1.FabricOperationsConsole) error {
	if len(m.GetFinalizers()) < 1 && m.GetDeletionTimestamp() == nil {
		reqLogger.Info("Adding finalizer for fabric console",
			"console", m.Name,
			"namespace", m.Namespace,
			"finalizer", consoleFinalizer,
		)

		m.SetFinalizers([]string{consoleFinalizer})

		if err := r.Client.Update(context.TODO(), m); err != nil {
			reqLogger.Error(err, "Failed to update console with finalizer",
				"console", m.Name,
				"namespace", m.Namespace,
			)
			return errors.Wrap(err, "failed to add finalizer to console")
		}

		reqLogger.Info("Successfully added finalizer to console",
			"console", m.Name,
			"namespace", m.Namespace,
		)
	}
	return nil
}

type Status struct {
	Status   hlfv1alpha1.DeploymentStatus
	TLSCert  string
	NodePort int
}

func GetConsoleState(conf *action.Configuration, config *rest.Config, releaseName string, ns string) (*hlfv1alpha1.FabricOperationsConsoleStatus, error) {
	ctx := context.Background()
	cmd := action.NewGet(conf)
	rel, err := cmd.Run(releaseName)
	if err != nil {
		return nil, err
	}
	clientSet, err := utils.GetClientKubeWithConf(config)
	if err != nil {
		return nil, err
	}
	if ns == "" {
		ns = "default"
	}
	r := &hlfv1alpha1.FabricOperationsConsoleStatus{
		Status: hlfv1alpha1.PendingStatus,
	}
	objects := utils.ParseK8sYaml([]byte(rel.Manifest))
	for _, object := range objects {
		kind := object.GetObjectKind().GroupVersionKind().Kind
		if kind == "Deployment" {
			depSpec := object.(*appsv1.Deployment)
			dep, err := clientSet.AppsV1().Deployments(ns).Get(ctx, depSpec.Name, v1.GetOptions{})
			if err != nil {
				return nil, err
			}
			pods, err := clientSet.CoreV1().Pods(ns).List(ctx, v1.ListOptions{
				LabelSelector: fmt.Sprintf("release=%s", releaseName),
			})
			if err != nil {
				return nil, err
			}
			if len(pods.Items) > 0 {
				for _, item := range pods.Items {
					if utils.IsPodReadyConditionTrue(item.Status) {
						r.Status = hlfv1alpha1.RunningStatus
					} else {
						switch item.Status.Phase {
						case corev1.PodPending:
							r.Status = hlfv1alpha1.PendingStatus
						case corev1.PodSucceeded:
						case corev1.PodRunning:
							r.Status = hlfv1alpha1.RunningStatus
						case corev1.PodFailed:
							r.Status = hlfv1alpha1.FailedStatus
						case corev1.PodUnknown:
							r.Status = hlfv1alpha1.UnknownStatus
						}
					}
				}
			} else {
				if dep.Status.ReadyReplicas == *depSpec.Spec.Replicas {
					r.Status = hlfv1alpha1.RunningStatus
				} else {
					r.Status = hlfv1alpha1.PendingStatus
				}
			}
		}
	}

	return r, nil
}

const consoleFinalizer = "finalizer.console.hlf.kungfusoftware.es"

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricchaincodeinstalls,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricchaincodeinstalls/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricchaincodeinstalls/finalizers,verbs=get;update;patch

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricchaincodecommits,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricchaincodecommits/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricchaincodecommits/finalizers,verbs=get;update;patch

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricchaincodeapproves,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricchaincodeapproves/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricchaincodeapproves/finalizers,verbs=get;update;patch

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricpeers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricpeers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricpeers/finalizers,verbs=get;update;patch

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=console,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=console/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=console/finalizers,verbs=get;update;patch

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricorderernodes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricorderernodes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricorderernodes/finalizers,verbs=get;update;patch

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricorderingservices,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricorderingservices/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricorderingservices/finalizers,verbs=get;update;patch

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabriccas,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabriccas/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabriccas/finalizers,verbs=get;update;patch

// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=monitoring.coreos.com,resources=servicemonitors,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=monitoring.coreos.com,resources=podmonitors,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=extensions,resources=deployments,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=apps,resources=replicasets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=replicasets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=extensions,resources=replicasets,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=apps,resources=persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=extensions,resources=persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=apps,resources=pods,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=extensions,resources=pods,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=apps,resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=extensions,resources=services,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=apps,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=extensions,resources=secrets,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=apps,resources=pods/log,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods/log,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=extensions,resources=pods/log,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=apps,resources=pods/status,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods/status,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=extensions,resources=pods/status,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=apps,resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=extensions,resources=configmaps,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=networking.istio.io,resources=gateways,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.istio.io,resources=virtualservices,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricchaincodes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricchaincodes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricchaincodes/finalizers,verbs=get;update;patch

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricoperationsconsoles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricoperationsconsoles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricoperationsconsoles/finalizers,verbs=get;update;patch

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricidentities,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricidentities/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricidentities/finalizers,verbs=get;update;patch

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricoperatorapis,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricoperatorapis/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricoperatorapis/finalizers,verbs=get;update;patch

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricoperatoruis,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricoperatoruis/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricoperatoruis/finalizers,verbs=get;update;patch

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricchaincodetemplates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricchaincodetemplates/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricchaincodetemplates/finalizers,verbs=get;update;patch

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricfollowerchannels,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricfollowerchannels/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricfollowerchannels/finalizers,verbs=get;update;patch

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricmainchannels,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricmainchannels/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricmainchannels/finalizers,verbs=get;update;patch

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricchaincodeinstalls,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricchaincodeinstalls/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricchaincodeinstalls/finalizers,verbs=get;update;patch

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricchaincodeapproves,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricchaincodeapproves/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricchaincodeapproves/finalizers,verbs=get;update;patch

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricchaincodecommits,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricchaincodecommits/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricchaincodecommits/finalizers,verbs=get;update;patch

//

func (r *FabricOperationsConsoleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	reqLogger := r.Log.WithValues("hlf", req.NamespacedName)
	fabricOpConsole := &hlfv1alpha1.FabricOperationsConsole{}
	releaseName := req.Name
	ns := req.Namespace

	reqLogger.Info("Starting console reconciliation",
		"console", req.Name,
		"namespace", req.Namespace,
		"releaseName", releaseName,
	)

	cfg, err := newActionCfg(r.Log, r.Config, ns)
	if err != nil {
		reqLogger.Error(err, "Failed to create Helm action configuration")
		r.setConditionStatus(ctx, fabricOpConsole, hlfv1alpha1.FailedStatus, false,
			errors.Wrap(err, "failed to create Helm action configuration"), false)
		return r.updateCRStatusOrFailReconcile(ctx, reqLogger, fabricOpConsole)
	}

	err = r.Get(ctx, req.NamespacedName, fabricOpConsole)
	if err != nil {
		if apierrors.IsNotFound(err) {
			reqLogger.Info("Console resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		reqLogger.Error(err, "Failed to get console resource",
			"console", req.Name,
			"namespace", req.Namespace,
		)
		r.setConditionStatus(ctx, fabricOpConsole, hlfv1alpha1.FailedStatus, false,
			errors.Wrap(err, "failed to get console resource"), false)
		return r.updateCRStatusOrFailReconcile(ctx, reqLogger, fabricOpConsole)
	}

	// Validate configuration
	if err := r.validateConsoleConfig(fabricOpConsole); err != nil {
		reqLogger.Error(err, "Invalid console configuration",
			"console", fabricOpConsole.Name,
			"namespace", fabricOpConsole.Namespace,
		)
		r.setConditionStatus(ctx, fabricOpConsole, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, reqLogger, fabricOpConsole)
	}

	isPeerMarkedToDelete := fabricOpConsole.GetDeletionTimestamp() != nil
	if isPeerMarkedToDelete {
		if utils.Contains(fabricOpConsole.GetFinalizers(), consoleFinalizer) {
			if err := r.finalizePeer(reqLogger, fabricOpConsole); err != nil {
				r.setConditionStatus(ctx, fabricOpConsole, hlfv1alpha1.FailedStatus, false, err, false)
				return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricOpConsole)
			}
			controllerutil.RemoveFinalizer(fabricOpConsole, consoleFinalizer)
			err := r.Update(ctx, fabricOpConsole)
			if err != nil {
				r.setConditionStatus(ctx, fabricOpConsole, hlfv1alpha1.FailedStatus, false, err, false)
				return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricOpConsole)
			}
		}
		return ctrl.Result{}, nil
	}
	if !utils.Contains(fabricOpConsole.GetFinalizers(), consoleFinalizer) {
		if err := r.addFinalizer(reqLogger, fabricOpConsole); err != nil {
			r.setConditionStatus(ctx, fabricOpConsole, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricOpConsole)
		}
	}

	cmdStatus := action.NewStatus(cfg)
	exists := true
	_, err = cmdStatus.Run(releaseName)
	if err != nil {
		if errors.Is(err, driver.ErrReleaseNotFound) {
			exists = false
		} else {
			// it doesnt exist
			r.setConditionStatus(ctx, fabricOpConsole, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricOpConsole)
		}
	}
	reqLogger.Info("Checked Helm release existence",
		"releaseName", releaseName,
		"exists", exists,
	)
	if exists {
		// update
		c, err := GetConfig(fabricOpConsole)
		if err != nil {
			r.setConditionStatus(ctx, fabricOpConsole, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricOpConsole)
		}

		err = r.upgradeChart(cfg, err, ns, releaseName, c)
		if err != nil {
			r.setConditionStatus(ctx, fabricOpConsole, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricOpConsole)
		}
		s, err := GetConsoleState(cfg, r.Config, releaseName, ns)
		if err != nil {
			r.setConditionStatus(ctx, fabricOpConsole, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricOpConsole)
		}

		fPeer := fabricOpConsole.DeepCopy()
		fPeer.Status.Status = s.Status
		fPeer.Status.Conditions.SetCondition(status.Condition{
			Type:   status.ConditionType(s.Status),
			Status: "True",
		})
		if !reflect.DeepEqual(fPeer.Status, fabricOpConsole.Status) {
			if err := r.Status().Update(ctx, fPeer); err != nil {
				reqLogger.Error(err, "Failed to update console status")
				r.setConditionStatus(ctx, fabricOpConsole, hlfv1alpha1.FailedStatus, false, err, false)
				return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricOpConsole)
			}
		}
		reqLogger.Info("Console status updated",
			"console", fPeer.Name,
			"status", string(s.Status),
		)
		switch s.Status {
		case hlfv1alpha1.PendingStatus:
			reqLogger.Info("Console in pending status, requeuing",
				"console", fPeer.Name,
			)
			return ctrl.Result{
				RequeueAfter: 10 * time.Second,
			}, nil
		case hlfv1alpha1.FailedStatus:
			reqLogger.Info("Console in failed status, requeuing",
				"console", fPeer.Name,
			)
			return ctrl.Result{
				RequeueAfter: 10 * time.Second,
			}, nil
		case hlfv1alpha1.RunningStatus:
			return ctrl.Result{}, nil
		default:
			return ctrl.Result{
				RequeueAfter: 2 * time.Second,
			}, nil
		}
	} else {
		cmd := action.NewInstall(cfg)
		name, chart, err := cmd.NameAndChart([]string{releaseName, r.ChartPath})
		if err != nil {
			r.setConditionStatus(ctx, fabricOpConsole, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricOpConsole)
		}

		cmd.ReleaseName = name
		ch, err := loader.Load(chart)
		if err != nil {
			r.setConditionStatus(ctx, fabricOpConsole, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricOpConsole)
		}
		c, err := GetConfig(fabricOpConsole)
		if err != nil {
			r.setConditionStatus(ctx, fabricOpConsole, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricOpConsole)
		}
		var inInterface map[string]interface{}
		inrec, err := json.Marshal(c)
		if err != nil {
			r.setConditionStatus(ctx, fabricOpConsole, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricOpConsole)
		}
		err = json.Unmarshal(inrec, &inInterface)
		if err != nil {
			r.setConditionStatus(ctx, fabricOpConsole, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricOpConsole)
		}
		release, err := cmd.Run(ch, inInterface)
		if err != nil {
			reqLogger.Error(err, "Failed to install chart")
			r.setConditionStatus(ctx, fabricOpConsole, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricOpConsole)
		}
		reqLogger.Info("Successfully installed Helm chart",
			"releaseName", release.Name,
		)
		fabricOpConsole.Status.Status = hlfv1alpha1.PendingStatus
		fabricOpConsole.Status.Conditions.SetCondition(status.Condition{
			Type:               "DEPLOYED",
			Status:             "True",
			LastTransitionTime: v1.Time{},
		})
		if err := r.Status().Update(ctx, fabricOpConsole); err != nil {
			r.setConditionStatus(ctx, fabricOpConsole, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricOpConsole)
		}
		return ctrl.Result{
			Requeue:      false,
			RequeueAfter: 10 * time.Second,
		}, nil
	}
}

func (r *FabricOperationsConsoleReconciler) upgradeChart(
	cfg *action.Configuration,
	err error,
	ns string,
	releaseName string,
	c *FabricOperationsConsoleChart,
) error {
	inrec, err := json.Marshal(c)
	if err != nil {
		return err
	}
	var inInterface map[string]interface{}
	err = json.Unmarshal(inrec, &inInterface)
	if err != nil {
		return err
	}
	cmd := action.NewUpgrade(cfg)
	cmd.MaxHistory = 5
	err = os.Setenv("HELM_NAMESPACE", ns)
	if err != nil {
		return err
	}
	settings := cli.New()
	chartPath, err := cmd.LocateChart(r.ChartPath, settings)
	ch, err := loader.Load(chartPath)
	if err != nil {
		return err
	}
	cmd.Wait = false
	cmd.Timeout = time.Minute * 5
	release, err := cmd.Run(releaseName, ch, inInterface)
	if err != nil {
		return err
	}
	r.Log.Info("Successfully upgraded Helm chart",
		"releaseName", release.Name,
	)
	return nil
}

func (r *FabricOperationsConsoleReconciler) validateConsoleConfig(console *hlfv1alpha1.FabricOperationsConsole) error {
	if console.Spec.Image == "" {
		return errors.Wrap(ErrInvalidConfig, "console image cannot be empty")
	}

	if console.Spec.Tag == "" {
		return errors.Wrap(ErrInvalidConfig, "console image tag cannot be empty")
	}

	// Basic validation - console should have required fields
	if console.Name == "" {
		return errors.Wrap(ErrInvalidConfig, "console name cannot be empty")
	}

	return nil
}

func (r *FabricOperationsConsoleReconciler) setConditionStatus(ctx context.Context, p *hlfv1alpha1.FabricOperationsConsole, conditionType hlfv1alpha1.DeploymentStatus, statusFlag bool, err error, statusUnknown bool) (update bool) {
	statusStr := func() corev1.ConditionStatus {
		if statusUnknown {
			return corev1.ConditionUnknown
		}
		if statusFlag {
			return corev1.ConditionTrue
		} else {
			return corev1.ConditionFalse
		}
	}
	if p.Status.Status != conditionType {
		depCopy := client.MergeFrom(p.DeepCopy())
		p.Status.Status = conditionType
		err = r.Status().Patch(ctx, p, depCopy)
		if err != nil {
			r.Log.Error(err, "Failed to patch console status",
				"targetStatus", conditionType,
			)
		}
	}
	if err != nil {
		p.Status.Message = err.Error()
	}
	condition := func() status.Condition {
		if err != nil {
			return status.Condition{
				Type:    status.ConditionType(conditionType),
				Status:  statusStr(),
				Reason:  status.ConditionReason(err.Error()),
				Message: err.Error(),
			}
		}
		return status.Condition{
			Type:   status.ConditionType(conditionType),
			Status: statusStr(),
		}
	}
	return p.Status.Conditions.SetCondition(condition())
}

func (r *FabricOperationsConsoleReconciler) updateCRStatusOrFailReconcile(ctx context.Context, log logr.Logger, p *hlfv1alpha1.FabricOperationsConsole) (reconcile.Result, error) {
	if err := r.Status().Update(ctx, p); err != nil {
		log.Error(err, "Failed to update console status",
			"console", p.Name,
			"namespace", p.Namespace,
		)
		return reconcile.Result{}, errors.Wrap(err, "failed to update console status")
	}
	return reconcile.Result{}, nil
}

func GetConfig(conf *hlfv1alpha1.FabricOperationsConsole) (*FabricOperationsConsoleChart, error) {
	spec := conf.Spec
	ingress := Ingress{}
	if spec.Ingress.Enabled {
		hosts := []IngressHost{}
		for _, host := range spec.Ingress.Hosts {
			paths := []IngressPath{}
			for _, path := range host.Paths {
				paths = append(paths, IngressPath{
					Path:     path.Path,
					PathType: path.PathType,
				})
			}
			hosts = append(hosts, IngressHost{
				Host:  host.Host,
				Paths: paths,
			})
		}
		ingress = Ingress{
			Enabled:     spec.Ingress.Enabled,
			ClassName:   spec.Ingress.ClassName,
			Annotations: spec.Ingress.Annotations,
			TLS:         spec.Ingress.TLS,
			Hosts:       hosts,
		}
	}
	var c = FabricOperationsConsoleChart{
		Replicas: spec.Replicas,
		Image: Image{
			Repository: spec.Image,
			Tag:        spec.Tag,
			PullPolicy: spec.ImagePullPolicy,
		},
		ImagePullSecrets: spec.ImagePullSecrets,
		PodAnnotations:   map[string]string{},
		Ingress:          ingress,
		Resources:        spec.Resources,
		Tolerations:      spec.Tolerations,
		Affinity:         spec.Affinity,
		Port:             spec.Port,
		HostUrl:          spec.HostURL,
		Auth: Auth{
			Scheme:   spec.Auth.Scheme,
			Username: spec.Auth.Username,
			Password: spec.Auth.Password,
		},
		CouchDB: CouchDB{
			External: CouchDBExternal{
				Enabled: false,
				Host:    "",
				Port:    0,
			},
			Image:      spec.CouchDB.Image,
			Tag:        spec.CouchDB.Tag,
			PullPolicy: spec.CouchDB.ImagePullPolicy,
			Username:   spec.CouchDB.Username,
			Password:   spec.CouchDB.Password,
			Persistence: Persistence{
				Enabled:      true,
				Annotations:  map[string]string{},
				StorageClass: spec.CouchDB.Storage.StorageClass,
				AccessMode:   spec.CouchDB.Storage.AccessMode,
				Size:         spec.CouchDB.Storage.Size,
			},
			Resources: spec.CouchDB.Resources,
		},
	}
	return &c, nil
}

func (r *FabricOperationsConsoleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&hlfv1alpha1.FabricOperationsConsole{}).
		Owns(&appsv1.Deployment{}).
		Complete(r)
}
func getServiceName(console *hlfv1alpha1.FabricOperationsConsole) string {
	return console.Name
}
func (r *FabricOperationsConsoleReconciler) finalizePeer(reqLogger logr.Logger, console *hlfv1alpha1.FabricOperationsConsole) error {
	ns := console.Namespace
	if ns == "" {
		ns = "default"
	}
	svcName := getServiceName(console)
	clientSet, err := utils.GetClientKubeWithConf(r.Config)
	if err != nil {
		return err
	}
	ctx := context.Background()
	err = clientSet.CoreV1().Services(ns).Delete(ctx, svcName, v1.DeleteOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			reqLogger.Info(fmt.Sprintf("Service %s couldn't be found", svcName))
		} else {
			reqLogger.Info(fmt.Sprintf("Service %s couldn't be deleted: %v", svcName, err))
		}
	}
	cfg, err := newActionCfg(r.Log, r.Config, ns)
	if err != nil {
		return err
	}
	releaseName := console.Name
	reqLogger.Info("Successfully finalized console")
	cmd := action.NewUninstall(cfg)
	resp, err := cmd.Run(releaseName)
	if err != nil {
		if strings.Compare("Release not loaded", err.Error()) != 0 {
			return nil
		}
		r.Log.Error(err, "Failed to uninstall Helm release",
			"releaseName", releaseName,
		)
		return err
	}
	r.Log.Info("Successfully deleted Helm release",
		"releaseName", releaseName,
		"info", resp.Info,
	)
	return nil
}

func newActionCfg(log logr.Logger, clusterCfg *rest.Config, namespace string) (*action.Configuration, error) {
	err := os.Setenv("HELM_NAMESPACE", namespace)
	if err != nil {
		return nil, err
	}
	cfg := new(action.Configuration)
	ns := namespace
	err = cfg.Init(&genericclioptions.ConfigFlags{
		Namespace:   &ns,
		APIServer:   &clusterCfg.Host,
		CAFile:      &clusterCfg.CAFile,
		BearerToken: &clusterCfg.BearerToken,
	}, ns, "secret", actionLogger(log))
	return cfg, err
}

func actionLogger(logger logr.Logger) func(format string, v ...interface{}) {
	return func(format string, v ...interface{}) {
		logger.Info(fmt.Sprintf(format, v...))
	}
}
