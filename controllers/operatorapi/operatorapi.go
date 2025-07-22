package operatorapi

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
	log "github.com/sirupsen/logrus"
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

// FabricOperatorAPIReconciler reconciles a FabricOperatorAPI object
type FabricOperatorAPIReconciler struct {
	client.Client
	ChartPath string
	Log       logr.Logger
	Scheme    *runtime.Scheme
	Config    *rest.Config
}

func (r *FabricOperatorAPIReconciler) addFinalizer(reqLogger logr.Logger, m *hlfv1alpha1.FabricOperatorAPI) error {
	if len(m.GetFinalizers()) < 1 && m.GetDeletionTimestamp() == nil {
		reqLogger.Info("Adding Finalizer for the Fabric Console")
		m.SetFinalizers([]string{consoleFinalizer})
		// Update CR
		err := r.Client.Update(context.TODO(), m)
		if err != nil {
			reqLogger.Error(err, "Failed to update Peer with finalizer")
			return err
		}
		reqLogger.Info(fmt.Sprintf("Finalizer for console %s added", m.Name))
	}
	return nil
}

type Status struct {
	Status   hlfv1alpha1.DeploymentStatus
	TLSCert  string
	NodePort int
}

func GetConsoleState(conf *action.Configuration, config *rest.Config, releaseName string, ns string) (*hlfv1alpha1.FabricOperatorAPIStatus, error) {
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
	r := &hlfv1alpha1.FabricOperatorAPIStatus{
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

const consoleFinalizer = "finalizer.operatorapi.hlf.kungfusoftware.es"

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

func (r *FabricOperatorAPIReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	reqLogger := r.Log.WithValues("hlf", req.NamespacedName)
	fabricOpConsole := &hlfv1alpha1.FabricOperatorAPI{}
	releaseName := req.Name
	ns := req.Namespace
	if ns == "" {
		ns = "default"
	}
	cfg, err := newActionCfg(r.Log, r.Config, ns)
	if err != nil {
		r.setConditionStatus(ctx, fabricOpConsole, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricOpConsole)
	}
	err = r.Get(ctx, req.NamespacedName, fabricOpConsole)
	if err != nil {
		log.Debugf("Error getting the object %s error=%v", req.NamespacedName, err)
		if apierrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			reqLogger.Info("Peer resource not found. Ignoring since object must be deleted.")

			return ctrl.Result{}, nil
		}
		reqLogger.Error(err, "Failed to get Peer.")
		r.setConditionStatus(ctx, fabricOpConsole, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricOpConsole)
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
	log.Debugf("Release %s exists=%v", releaseName, exists)
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
				log.Errorf("Error updating the status: %v", err)
				r.setConditionStatus(ctx, fabricOpConsole, hlfv1alpha1.FailedStatus, false, err, false)
				return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricOpConsole)
			}
		}
		log.Infof("Peer %s in %s status", fPeer.Name, string(s.Status))
		switch s.Status {
		case hlfv1alpha1.PendingStatus:
			log.Infof("Peer %s in %s status", fPeer.Name, string(s.Status))
			return ctrl.Result{
				RequeueAfter: 10 * time.Second,
			}, nil
		case hlfv1alpha1.FailedStatus:
			log.Infof("Peer %s in %s status", fPeer.Name, string(s.Status))
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
		cmd.Namespace = ns
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
		log.Infof("Chart installed %s", release.Name)
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
			RequeueAfter: 120 * time.Minute,
		}, nil
	}
}

func (r *FabricOperatorAPIReconciler) upgradeChart(
	cfg *action.Configuration,
	err error,
	ns string,
	releaseName string,
	c *HLFOperatorAPIChart,
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
	cmd.Namespace = ns
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
	log.Infof("Chart upgraded %s", release.Name)
	return nil
}

func (r *FabricOperatorAPIReconciler) setConditionStatus(ctx context.Context, p *hlfv1alpha1.FabricOperatorAPI, conditionType hlfv1alpha1.DeploymentStatus, statusFlag bool, err error, statusUnknown bool) (update bool) {
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
			log.Warnf("Failed to update status to %s: %v", conditionType, err)
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

var (
	ErrClientK8s = errors.New("k8sAPIClientError")
)

func (r *FabricOperatorAPIReconciler) updateCRStatusOrFailReconcile(ctx context.Context, log logr.Logger, p *hlfv1alpha1.FabricOperatorAPI) (
	reconcile.Result, error) {
	if err := r.Status().Update(ctx, p); err != nil {
		log.Error(err, fmt.Sprintf("%v failed to update the application status", ErrClientK8s))
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}

func GetConfig(conf *hlfv1alpha1.FabricOperatorAPI) (*HLFOperatorAPIChart, error) {
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
	auth := Auth{}
	if spec.Auth != nil {
		auth.OIDCJWKS = spec.Auth.OIDCJWKS
		auth.OIDCIssuer = spec.Auth.OIDCIssuer
		auth.OIDCAuthority = spec.Auth.OIDCAuthority
		auth.OIDCClientId = spec.Auth.OIDCClientId
		auth.OIDCScope = spec.Auth.OIDCScope
	}
	var c = HLFOperatorAPIChart{
		PodLabels:    spec.PodLabels,
		ReplicaCount: spec.Replicas,
		LogoURL:      spec.LogoURL,
		Image: Image{
			Repository: spec.Image,
			Tag:        spec.Tag,
			PullPolicy: spec.ImagePullPolicy,
		},
		Hlf: HLFConfig{
			MspID: spec.HLFConfig.MSPID,
			User:  spec.HLFConfig.User,
			NetworkConfig: HLFNetworkConfig{
				SecretName: spec.HLFConfig.NetworkConfig.SecretName,
				Key:        spec.HLFConfig.NetworkConfig.Key,
			},
		},
		ImagePullSecrets: spec.ImagePullSecrets,
		ServiceAccount:   ServiceAccount{},
		PodAnnotations:   map[string]string{},
		Service: Service{
			Type: "ClusterIP",
			Port: 80,
		},
		Ingress:   ingress,
		Resources: spec.Resources,
		Autoscaling: Autoscaling{
			Enabled:                        false,
			MinReplicas:                    1,
			MaxReplicas:                    1,
			TargetCPUUtilizationPercentage: 90,
		},
		Tolerations: spec.Tolerations,
		Affinity:    spec.Affinity,
		Auth:        auth,
	}
	return &c, nil
}

func (r *FabricOperatorAPIReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&hlfv1alpha1.FabricOperatorAPI{}).
		Owns(&appsv1.Deployment{}).
		Complete(r)
}
func getServiceName(console *hlfv1alpha1.FabricOperatorAPI) string {
	return console.Name
}
func (r *FabricOperatorAPIReconciler) finalizePeer(reqLogger logr.Logger, console *hlfv1alpha1.FabricOperatorAPI) error {
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
		log.Errorf("Failed to uninstall release %s %v", releaseName, err)
		return err
	}
	log.Infof("Release %s deleted=%s", releaseName, resp.Info)
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
