package ordnode

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"helm.sh/helm/v3/pkg/release"

	"github.com/go-logr/logr"
	"github.com/kfsoftware/hlf-operator/controllers/certs"
	"github.com/kfsoftware/hlf-operator/controllers/certs_vault"
	"github.com/kfsoftware/hlf-operator/controllers/hlfmetrics"
	"github.com/kfsoftware/hlf-operator/controllers/utils"
	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	operatorv1 "github.com/kfsoftware/hlf-operator/pkg/client/clientset/versioned"
	"github.com/kfsoftware/hlf-operator/pkg/status"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/storage/driver"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// FabricOrdererNodeReconciler reconciles a FabricOrdererNode object
type FabricOrdererNodeReconciler struct {
	client.Client
	ChartPath                  string
	Log                        logr.Logger
	Scheme                     *runtime.Scheme
	Config                     *rest.Config
	AutoRenewCertificates      bool
	AutoRenewCertificatesDelta time.Duration
	Wait                       bool
	Timeout                    time.Duration
	MaxHistory                 int
}

const ordererNodeFinalizer = "finalizer.orderernode.hlf.kungfusoftware.es"

func (r *FabricOrdererNodeReconciler) finalizeOrderer(reqLogger logr.Logger, m *hlfv1alpha1.FabricOrdererNode) error {
	ns := m.Namespace
	if ns == "" {
		ns = "default"
	}
	cfg, err := newActionCfg(r.Log, r.Config, ns)
	if err != nil {
		return err
	}
	releaseName := m.Name
	reqLogger.Info("Successfully finalized orderer")
	cmd := action.NewUninstall(cfg)
	cmd.Wait = r.Wait
	cmd.Timeout = r.Timeout
	resp, err := cmd.Run(releaseName)
	if err != nil {
		if strings.Compare("Release not loaded", err.Error()) != 0 {
			return nil
		}
		return err
	}
	log.Printf("Release %s deleted=%s", releaseName, resp.Info)
	return nil
}

func (r *FabricOrdererNodeReconciler) addFinalizer(reqLogger logr.Logger, m *hlfv1alpha1.FabricOrdererNode) error {
	reqLogger.Info("Adding Finalizer for the Orderer")
	controllerutil.AddFinalizer(m, ordererNodeFinalizer)

	// Update CR
	err := r.Update(context.TODO(), m)
	if err != nil {
		reqLogger.Error(err, "Failed to update Orderer with finalizer")
		return err
	}
	return nil
}

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricorderernodes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricorderernodes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricorderernodes/finalizers,verbs=get;update;patch
func (r *FabricOrdererNodeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log.Infof("Reconciling Orderer %s/%s", req.Namespace, req.Name)
	defer func() {
		log.Infof("Reconciling Orderer %s/%s done", req.Namespace, req.Name)
	}()
	reqLogger := r.Log.WithValues("hlf", req.NamespacedName)
	fabricOrdererNode := &hlfv1alpha1.FabricOrdererNode{}
	releaseName := req.Name
	ns := req.Namespace
	cfg, err := newActionCfg(r.Log, r.Config, ns)
	if err != nil {
		return ctrl.Result{}, err
	}
	err = r.Get(ctx, req.NamespacedName, fabricOrdererNode)
	if err != nil {
		log.Printf("Error getting the object %s error=%v", req.NamespacedName, err)
		if apierrors.IsNotFound(err) {
			reqLogger.Info("Orderer resource not found. Ignoring since object must be deleted.")
			return ctrl.Result{}, nil
		}
		reqLogger.Error(err, "Failed to get Orderer.")
		return ctrl.Result{}, err
	}
	isMemcachedMarkedToBeDeleted := fabricOrdererNode.GetDeletionTimestamp() != nil
	if isMemcachedMarkedToBeDeleted {
		if utils.Contains(fabricOrdererNode.GetFinalizers(), ordererNodeFinalizer) {
			if err := r.finalizeOrderer(reqLogger, fabricOrdererNode); err != nil {
				return ctrl.Result{}, err
			}
			controllerutil.RemoveFinalizer(fabricOrdererNode, ordererNodeFinalizer)
			err := r.Update(ctx, fabricOrdererNode)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}
	if !utils.Contains(fabricOrdererNode.GetFinalizers(), ordererNodeFinalizer) {
		if err := r.addFinalizer(reqLogger, fabricOrdererNode); err != nil {
			return ctrl.Result{}, err
		}
	}
	if fabricOrdererNode.Spec.CredentialStore == "" {
		fabricOrdererNode.Spec.CredentialStore = "kubernetes"
	}
	cmdStatus := action.NewStatus(cfg)
	exists := true
	helmStatus, err := cmdStatus.Run(releaseName)
	if err != nil {
		if errors.Is(err, driver.ErrReleaseNotFound) {
			// it doesn't exists
			exists = false
		} else {
			// it doesn't exist
			return ctrl.Result{}, err
		}
	}
	if exists && helmStatus.Info.Status == release.StatusPendingUpgrade {
		rollbackStatus := action.NewRollback(cfg)
		rollbackStatus.Version = helmStatus.Version - 1
		err = rollbackStatus.Run(releaseName)
		if err != nil {
			// it doesn't exist
			return ctrl.Result{}, err
		}
	} else if exists && helmStatus.Info.Status == release.StatusPendingRollback {
		historyAction := action.NewHistory(cfg)
		history, err := historyAction.Run(releaseName)
		if err != nil {
			return ctrl.Result{}, err
		}
		if len(history) > 0 {
			// find the last deployed revision
			// and rollback to it
			// sort history by revision number descending using raw go
			sort.Slice(history, func(i, j int) bool {
				return history[i].Version > history[j].Version
			})
			for _, historyItem := range history {
				if historyItem.Info.Status == release.StatusDeployed {
					rollbackStatus := action.NewRollback(cfg)
					rollbackStatus.Version = historyItem.Version
					err = rollbackStatus.Run(releaseName)
					if err != nil {
						// it doesn't exist
						return ctrl.Result{}, err
					}
					break
				}
			}
		}
	}
	log.Printf("Release %s exists=%v", releaseName, exists)
	clientSet, err := utils.GetClientKubeWithConf(r.Config)
	if err != nil {
		return ctrl.Result{}, err
	}
	if exists {
		// update
		hlfClientSet, err := operatorv1.NewForConfig(r.Config)
		if err != nil {
			r.setConditionStatus(ctx, fabricOrdererNode, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricOrdererNode)
		}
		ordNode, err := hlfClientSet.HlfV1alpha1().FabricOrdererNodes(ns).Get(ctx, fabricOrdererNode.Name, v1.GetOptions{})
		if err != nil {
			r.setConditionStatus(ctx, fabricOrdererNode, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricOrdererNode)
		}

		lastTimeCertsRenewed := ordNode.Status.LastCertificateUpdate
		certificatesNeedToBeRenewed := false
		if ordNode.Status.LastCertificateUpdate != nil && fabricOrdererNode.Spec.UpdateCertificateTime != nil && fabricOrdererNode.Spec.UpdateCertificateTime.Time.After(ordNode.Status.LastCertificateUpdate.Time) {
			certificatesNeedToBeRenewed = true
		}
		if lastTimeCertsRenewed == nil && fabricOrdererNode.Spec.UpdateCertificateTime != nil {
			certificatesNeedToBeRenewed = true
		}
		// renew certificate 15 days before
		tlsCert, _, _, err := getExistingTLSCrypto(clientSet, releaseName, ns)
		if err != nil {
			return ctrl.Result{}, err
		}
		if r.AutoRenewCertificates && tlsCert.NotAfter.Before(time.Now().Add(r.AutoRenewCertificatesDelta)) {
			certificatesNeedToBeRenewed = true
		}
		requeueAfter := time.Second * 10
		log.Infof("Last time certs were updated: %v, they need to be renewed: %v", lastTimeCertsRenewed, certificatesNeedToBeRenewed)

		// --- RELEASE LEASE IF HELD AND STATUS IS RUNNING ---
		if fabricOrdererNode.Status.CertRenewalLeaseHeld && fabricOrdererNode.Status.Status == hlfv1alpha1.RunningStatus {
			leaseName := "orderernode-cert-renewal-global-lock"
			holderIdentity := os.Getenv("POD_NAME")
			if holderIdentity == "" {
				holderIdentity = fmt.Sprintf("orderernode-%s-lock", fabricOrdererNode.Name)
			}
			err := utils.ReleaseLease(ctx, clientSet, leaseName, ns, holderIdentity)
			if err != nil {
				log.Warnf("Error releasing lease: %v", err)
			} else {
				log.Infof("Released cert renewal lease for %s", fabricOrdererNode.Name)
			}
			fabricOrdererNode.Status.CertRenewalLeaseHeld = false
			if err := r.Status().Update(ctx, fabricOrdererNode); err != nil {
				log.Errorf("Error updating status after releasing lease: %v", err)
			}
		}

		if certificatesNeedToBeRenewed {
			// Lease-based lock for cert renewal (global lock)
			leaseName := "orderernode-cert-renewal-global-lock"
			holderIdentity := os.Getenv("POD_NAME")
			if holderIdentity == "" {
				holderIdentity = fmt.Sprintf("orderernode-%s-lock", fabricOrdererNode.Name)
			}
			leaseTTL := int32(120)
			acquired := false
			for i := 0; i < 5; i++ { // try for ~5 seconds
				ok, err := utils.AcquireLease(ctx, clientSet, leaseName, ns, holderIdentity, leaseTTL)
				if err != nil {
					log.Warnf("Error acquiring lease: %v", err)
				}
				if ok {
					acquired = true
					break
				}
				time.Sleep(time.Second)
			}
			if !acquired {
				log.Warnf("Could not acquire cert renewal lock for %s, skipping renewal", fabricOrdererNode.Name)
				return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
			}
			// Set lease held flag
			fabricOrdererNode.Status.CertRenewalLeaseHeld = true
			if err := r.Status().Update(ctx, fabricOrdererNode); err != nil {
				log.Errorf("Error updating status after acquiring lease: %v", err)
			}
			// must update the certificates and block until it's done
			log.Infof("Trying to upgrade certs (lease acquired)")
			r.setConditionStatus(ctx, fabricOrdererNode, hlfv1alpha1.UpdatingCertificates, false, nil, false)
			err := r.updateCerts(req, fabricOrdererNode, clientSet, releaseName, ctx, cfg, ns)
			if err != nil {
				log.Errorf("Error renewing certs: %v", err)
				r.setConditionStatus(ctx, fabricOrdererNode, hlfv1alpha1.FailedStatus, false, err, false)
				return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricOrdererNode)
			}
			newTime := v1.NewTime(time.Now().Add(time.Minute * 5)) // to avoid duplicate updates
			lastTimeCertsRenewed = &newTime
			log.Infof("Certs updated, last time updated: %v", lastTimeCertsRenewed)
			requeueAfter = time.Minute * 1
		} else if helmStatus.Info.Status != release.StatusPendingUpgrade {
			c, err := getConfig(fabricOrdererNode, clientSet, releaseName, req.Namespace, false)
			if err != nil {
				return ctrl.Result{}, err
			}
			err = r.upgradeChartWithWait(cfg, err, ns, releaseName, c, false, 5*time.Minute)
			if err != nil {
				r.setConditionStatus(ctx, fabricOrdererNode, hlfv1alpha1.FailedStatus, false, err, false)
				return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricOrdererNode)
			}
			requeueAfter = time.Minute * 60
		}
		s, err := GetOrdererState(cfg, r.Config, releaseName, ns, fabricOrdererNode)
		if err != nil {
			log.Printf("Failed to get orderer state=%v", err)
			return ctrl.Result{}, err
		}
		fOrderer := fabricOrdererNode.DeepCopy()
		fOrderer.Status.Status = s.Status
		fOrderer.Status.Message = ""
		fOrderer.Status.NodePort = s.NodePort
		fOrderer.Status.TlsCert = s.TlsCert
		fOrderer.Status.SignCert = s.SignCert
		fOrderer.Status.SignCACert = s.SignCACert
		fOrderer.Status.TlsCACert = s.TlsCACert
		fOrderer.Status.TlsAdminCert = s.TlsAdminCert
		fOrderer.Status.AdminPort = s.AdminPort
		fOrderer.Status.OperationsPort = s.OperationsPort
		fOrderer.Status.LastCertificateUpdate = lastTimeCertsRenewed
		fOrderer.Status.Conditions.SetCondition(status.Condition{
			Type:   status.ConditionType(s.Status),
			Status: "True",
		})
		if !reflect.DeepEqual(fOrderer.Status, fabricOrdererNode.Status) {
			if err := r.Status().Update(ctx, fOrderer); err != nil {
				log.Errorf("Error updating the status: %v", err)
				r.setConditionStatus(ctx, fabricOrdererNode, hlfv1alpha1.FailedStatus, false, err, false)
				return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricOrdererNode)
			}
		}
		reqLogger.Info(fmt.Sprintf("Peer status %s  requeueAfter %v", string(s.Status), requeueAfter))
		switch s.Status {
		case hlfv1alpha1.PendingStatus:
			log.Infof("Orderer %s in pending status", fabricOrdererNode.Name)
			return ctrl.Result{
				RequeueAfter: 10 * time.Second,
			}, nil
		case hlfv1alpha1.RunningStatus:
			return ctrl.Result{
				RequeueAfter: requeueAfter,
			}, nil
		case hlfv1alpha1.UpdatingCertificates:
			return ctrl.Result{
				RequeueAfter: requeueAfter,
			}, nil
		case hlfv1alpha1.FailedStatus:
			log.Infof("Orderer %s in failed status", fabricOrdererNode.Name)
			return ctrl.Result{
				RequeueAfter: 10 * time.Second,
			}, nil
		default:
			log.Infof("Orderer %s in unknown status, requeuing in 2 seconds", fabricOrdererNode.Name)
			return ctrl.Result{
				RequeueAfter: 2 * time.Second,
			}, nil
		}
	} else {
		cmd := action.NewInstall(cfg)
		cmd.Wait = r.Wait
		cmd.Timeout = r.Timeout
		cmd.ReleaseName = releaseName
		name, chart, err := cmd.NameAndChart([]string{releaseName, r.ChartPath})
		if err != nil {
			return ctrl.Result{}, err
		}

		cmd.ReleaseName = name
		ch, err := loader.Load(chart)
		if err != nil {
			return ctrl.Result{}, err
		}
		c, err := getConfig(fabricOrdererNode, clientSet, releaseName, req.Namespace, false)
		if err != nil {
			reqLogger.Error(err, fmt.Sprintf("Failed to get config for orderer %s/%s", req.Namespace, req.Name))
			return ctrl.Result{}, err
		}
		var inInterface map[string]interface{}
		inrec, err := json.Marshal(c)
		if err != nil {
			return ctrl.Result{}, err
		}
		err = json.Unmarshal(inrec, &inInterface)
		if err != nil {
			log.Printf("Failed to unmarshall JSON %v", err)
			return ctrl.Result{}, err
		}
		if fabricOrdererNode.Spec.Genesis == "" && fabricOrdererNode.Spec.BootstrapMethod != "none" {
			waitForGenesis := 2 * time.Second
			log.Printf("Waiting %v since bootstrapMethod is %s", waitForGenesis, fabricOrdererNode.Spec.BootstrapMethod)
			return ctrl.Result{
				RequeueAfter: waitForGenesis,
			}, err
		}
		release, err := cmd.Run(ch, inInterface)
		if err != nil {
			r.setConditionStatus(ctx, fabricOrdererNode, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricOrdererNode)
		}
		log.Printf("Chart installed %s", release.Name)
		fabricOrdererNode.Status.Status = hlfv1alpha1.PendingStatus
		fabricOrdererNode.Status.Message = ""
		fabricOrdererNode.Status.Conditions.SetCondition(status.Condition{
			Type:               "DEPLOYED",
			Status:             "True",
			LastTransitionTime: v1.Time{},
		})
		err = r.Get(ctx, req.NamespacedName, fabricOrdererNode)
		if err != nil {
			reqLogger.Error(err, "Failed to get Orderer before updating it.")
			return ctrl.Result{}, err
		}
		if err := r.Status().Update(ctx, fabricOrdererNode); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{
			Requeue:      false,
			RequeueAfter: 10 * time.Second,
		}, nil
	}
}

var (
	ErrClientK8s = errors.New("k8sAPIClientError")
)

func (r *FabricOrdererNodeReconciler) updateCRStatusOrFailReconcile(ctx context.Context, log logr.Logger, p *hlfv1alpha1.FabricOrdererNode) (
	ctrl.Result, error) {
	if err := r.Status().Update(ctx, p); err != nil {
		log.Error(err, fmt.Sprintf("%v failed to update the application status", ErrClientK8s))
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}
func (r *FabricOrdererNodeReconciler) setConditionStatus(
	ctx context.Context,
	p *hlfv1alpha1.FabricOrdererNode,
	conditionType hlfv1alpha1.DeploymentStatus,
	statusFlag bool,
	err error,
	statusUnknown bool,
) (update bool) {
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

func (r *FabricOrdererNodeReconciler) SetupWithManager(mgr ctrl.Manager, maxReconciles int) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&hlfv1alpha1.FabricOrdererNode{}).
		Owns(&appsv1.Deployment{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: maxReconciles,
		}).
		Complete(r)
}

func (r *FabricOrdererNodeReconciler) updateCerts(req ctrl.Request, node *hlfv1alpha1.FabricOrdererNode, clientSet *kubernetes.Clientset, releaseName string, ctx context.Context, cfg *action.Configuration, ns string) error {
	log.Infof("Trying to upgrade certs")
	r.setConditionStatus(ctx, node, hlfv1alpha1.UpdatingCertificates, false, nil, false)
	config, err := getConfig(node, clientSet, releaseName, req.Namespace, true)
	if err != nil {
		log.Errorf("Error getting the config: %v", err)
		return errors.Wrapf(err, "Error getting the config: %v", err)
	}
	// Force Wait=true and Timeout=5m for cert renewal
	wait := true
	timeout := 5 * time.Minute
	err = r.upgradeChartWithWait(cfg, err, ns, releaseName, config, wait, timeout)
	if err != nil {
		return errors.Wrapf(err, "Error upgrading the chart: %v", err)
	}
	return nil
}

// upgradeChartWithWait is like upgradeChart but allows overriding Wait/Timeout
func (r *FabricOrdererNodeReconciler) upgradeChartWithWait(
	cfg *action.Configuration,
	err error,
	ns string,
	releaseName string,
	c *fabricOrdChart,
	wait bool,
	timeout time.Duration,
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
	err = os.Setenv("HELM_NAMESPACE", ns)
	if err != nil {
		return err
	}
	settings := cli.New()
	chartPath, err := cmd.LocateChart(r.ChartPath, settings)
	if err != nil {
		return err
	}
	ch, err := loader.Load(chartPath)
	if err != nil {
		return err
	}
	cmd.Wait = wait
	cmd.Timeout = timeout
	cmd.MaxHistory = r.MaxHistory

	release, err := cmd.Run(releaseName, ch, inInterface)
	if err != nil {
		return err
	}
	log.Infof("Chart upgraded %s", release.Name)
	return nil
}
func GetOrdererDeployment(conf *action.Configuration, config *rest.Config, releaseName string, ns string) (*appsv1.Deployment, error) {
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
	objects := utils.ParseK8sYaml([]byte(rel.Manifest))
	for _, object := range objects {
		kind := object.GetObjectKind().GroupVersionKind().Kind
		if kind == "Deployment" {
			depSpec := object.(*appsv1.Deployment)
			dep, err := clientSet.AppsV1().Deployments(ns).Get(ctx, depSpec.Name, v1.GetOptions{})
			if err != nil {
				return nil, err
			}
			return dep, nil
		}
	}
	return nil, errors.Errorf("Deployment not found")

}

const (
	deploymentRestartTriggerAnnotation = "es.kungfusoftware.hlf.deployment-restart.timestamp"
)

func restartDeployment(config *rest.Config, deployment *appsv1.Deployment) error {
	clientSet, err := utils.GetClientKubeWithConf(config)
	if err != nil {
		return err
	}

	patchData := map[string]interface{}{}
	patchData["spec"] = map[string]interface{}{
		"template": map[string]interface{}{
			"metadata": map[string]interface{}{
				"annotations": map[string]interface{}{
					deploymentRestartTriggerAnnotation: time.Now().Format(time.Stamp),
				},
			},
		},
	}
	encodedData, err := json.Marshal(patchData)
	if err != nil {
		return err
	}
	_, err = clientSet.AppsV1().Deployments(deployment.Namespace).Patch(context.TODO(), deployment.Name, types.MergePatchType, encodedData, v1.PatchOptions{})
	if err != nil {
		return err
	}
	return nil
}
func getExistingTLSAdminCrypto(client *kubernetes.Clientset, chartName string, namespace string) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, *x509.Certificate, error) {
	secretName := fmt.Sprintf("%s-admin", chartName)
	secret, err := client.CoreV1().Secrets(namespace).Get(context.Background(), secretName, v1.GetOptions{})
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// cacert.pem
	tlsKeyData := secret.Data["tls.key"]
	tlsCrtData := secret.Data["tls.crt"]
	rootTLSCrtData := secret.Data["cacert.crt"]
	clientRootCrtData := secret.Data["clientcacert.crt"]
	key, err := utils.ParseECDSAPrivateKey(tlsKeyData)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	crt, err := utils.ParseX509Certificate(tlsCrtData)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	rootCrt, err := utils.ParseX509Certificate(rootTLSCrtData)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	clientRootCrt, err := utils.ParseX509Certificate(clientRootCrtData)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return crt, key, rootCrt, clientRootCrt, nil
}

func getExistingTLSCrypto(client *kubernetes.Clientset, chartName string, namespace string) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, error) {
	secretName := fmt.Sprintf("%s-tls", chartName)
	tlsRootSecretName := fmt.Sprintf("%s-tlsrootcert", chartName)
	secret, err := client.CoreV1().Secrets(namespace).Get(context.Background(), secretName, v1.GetOptions{})
	if err != nil {
		return nil, nil, nil, err
	}
	rootCertSecret, err := client.CoreV1().Secrets(namespace).Get(context.Background(), tlsRootSecretName, v1.GetOptions{})
	if err != nil {
		return nil, nil, nil, err
	}
	// cacert.pem
	tlsKeyData := secret.Data["tls.key"]
	tlsCrtData := secret.Data["tls.crt"]
	rootTLSCrtData := rootCertSecret.Data["cacert.pem"]
	key, err := utils.ParseECDSAPrivateKey(tlsKeyData)
	if err != nil {
		return nil, nil, nil, err
	}
	crt, err := utils.ParseX509Certificate(tlsCrtData)
	if err != nil {
		return nil, nil, nil, err
	}
	rootCrt, err := utils.ParseX509Certificate(rootTLSCrtData)
	if err != nil {
		return nil, nil, nil, err
	}
	return crt, key, rootCrt, nil
}

func getExistingSignCrypto(client *kubernetes.Clientset, chartName string, namespace string) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, error) {
	secretCrtName := fmt.Sprintf("%s-idcert", chartName)
	secretKeyName := fmt.Sprintf("%s-idkey", chartName)
	secretRootCrtName := fmt.Sprintf("%s-cacert", chartName)
	secretCrt, err := client.CoreV1().Secrets(namespace).Get(context.Background(), secretCrtName, v1.GetOptions{})
	if err != nil {
		return nil, nil, nil, err
	}
	secretKey, err := client.CoreV1().Secrets(namespace).Get(context.Background(), secretKeyName, v1.GetOptions{})
	if err != nil {
		return nil, nil, nil, err
	}
	secretRootCrt, err := client.CoreV1().Secrets(namespace).Get(context.Background(), secretRootCrtName, v1.GetOptions{})
	if err != nil {
		return nil, nil, nil, err
	}
	signCrtData := secretCrt.Data["cert.pem"]
	signKeyData := secretKey.Data["key.pem"]
	signRootCrtData := secretRootCrt.Data["cacert.pem"]
	crt, err := utils.ParseX509Certificate(signCrtData)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "failed to parse certificate for %s", chartName)
	}
	rootCrt, err := utils.ParseX509Certificate(signRootCrtData)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "failed to parse root certificate for %s", chartName)
	}
	key, err := utils.ParseECDSAPrivateKey(signKeyData)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "failed to parse private key for %s", chartName)
	}
	return crt, key, rootCrt, nil
}

func CreateTLSCryptoMaterial(client *kubernetes.Clientset, conf *hlfv1alpha1.FabricOrdererNode, enrollment *hlfv1alpha1.TLSComponent) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, error) {
	if conf.Spec.CredentialStore == hlfv1alpha1.CredentialStoreVault {
		enrollRequest, err := getEnrollRequestForVaultTLS(enrollment, conf, "tls")
		if err != nil {
			return nil, nil, nil, err
		}
		tlsCert, tlsKey, tlsRootCert, err := certs_vault.EnrollUser(
			client,
			&enrollment.Vault.Vault,
			&enrollment.Vault.Request,
			enrollRequest,
		)
		if err != nil {
			return nil, nil, nil, err
		}
		return tlsCert, tlsKey, tlsRootCert, nil
	} else {
		enrollRequest, err := getEnrollRequestForFabricCATLS(client, enrollment, &conf.Spec, "tls")
		if err != nil {
			return nil, nil, nil, err
		}
		tlsCert, tlsKey, tlsRootCert, err := certs.EnrollUser(enrollRequest)
		if err != nil {
			return nil, nil, nil, err
		}
		return tlsCert, tlsKey, tlsRootCert, nil
	}
}

func ReenrollTLSCryptoMaterial(
	client *kubernetes.Clientset,
	conf *hlfv1alpha1.FabricOrdererNode,
	enrollment *hlfv1alpha1.TLSComponent,
	tlsCertPem string,
	tlsKey *ecdsa.PrivateKey,
) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, error) {
	if conf.Spec.CredentialStore == hlfv1alpha1.CredentialStoreVault {
		reenrollRequest, err := getReenrollRequestForVaultTLS(enrollment, conf, "tls")
		if err != nil {
			return nil, nil, nil, err
		}
		tlsCert, tlsRootCert, err := certs_vault.ReenrollUser(
			client,
			&enrollment.Vault.Vault,
			&enrollment.Vault.Request,
			reenrollRequest,
			tlsCertPem,
			tlsKey,
		)
		if err != nil {
			return nil, nil, nil, err
		}
		return tlsCert, tlsKey, tlsRootCert, nil
	} else {
		reenrollRequest, err := getReenrollRequestForFabricCATLS(client, enrollment, &conf.Spec, "tls")
		if err != nil {
			return nil, nil, nil, err
		}
		tlsCert, tlsRootCert, err := certs.ReenrollUser(
			reenrollRequest,
			tlsCertPem,
			tlsKey,
		)
		if err != nil {
			return nil, nil, nil, err
		}
		return tlsCert, tlsKey, tlsRootCert, nil
	}
}

func CreateTLSAdminCryptoMaterial(client *kubernetes.Clientset, conf *hlfv1alpha1.FabricOrdererNode, enrollment *hlfv1alpha1.TLSComponent) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, *x509.Certificate, error) {
	if conf.Spec.CredentialStore == hlfv1alpha1.CredentialStoreVault {
		enrollRequest, err := getEnrollRequestForVaultTLS(enrollment, conf, "tls")
		if err != nil {
			return nil, nil, nil, nil, err
		}
		tlsCert, tlsKey, tlsRootCert, err := certs_vault.EnrollUser(
			client,
			&enrollment.Vault.Vault,
			&enrollment.Vault.Request,
			enrollRequest,
		)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		return tlsCert, tlsKey, tlsRootCert, tlsRootCert, nil
	} else {
		enrollRequest, err := getEnrollRequestForFabricCATLS(client, enrollment, &conf.Spec, "tls")
		if err != nil {
			return nil, nil, nil, nil, err
		}
		tlsCert, tlsKey, tlsRootCert, err := certs.EnrollUser(
			enrollRequest,
		)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		return tlsCert, tlsKey, tlsRootCert, tlsRootCert, nil
	}
}

func ReenrollTLSAdminCryptoMaterial(
	client *kubernetes.Clientset,
	conf *hlfv1alpha1.FabricOrdererNode,
	enrollment *hlfv1alpha1.TLSComponent,
	tlsCertPem string,
	tlsKey *ecdsa.PrivateKey,
) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, *x509.Certificate, error) {
	if conf.Spec.CredentialStore == hlfv1alpha1.CredentialStoreVault {
		reenrollRequest, err := getReenrollRequestForVaultTLS(enrollment, conf, "tls")
		if err != nil {
			return nil, nil, nil, nil, err
		}
		tlsCert, tlsRootCert, err := certs_vault.ReenrollUser(
			client,
			&enrollment.Vault.Vault,
			&enrollment.Vault.Request,
			reenrollRequest,
			tlsCertPem,
			tlsKey,
		)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		return tlsCert, tlsKey, tlsRootCert, tlsRootCert, nil
	}

	reenrollRequest, err := getReenrollRequestForFabricCATLS(client, enrollment, &conf.Spec, "tls")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	tlsCert, tlsRootCert, err := certs.ReenrollUser(
		reenrollRequest,
		tlsCertPem,
		tlsKey,
	)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return tlsCert, tlsKey, tlsRootCert, tlsRootCert, nil
}

func CreateSignCryptoMaterial(client *kubernetes.Clientset, conf *hlfv1alpha1.FabricOrdererNode, enrollment *hlfv1alpha1.Component) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, error) {
	if conf.Spec.CredentialStore == hlfv1alpha1.CredentialStoreVault {
		enrollRequest, err := getEnrollRequestForVault(enrollment, conf, "ca")
		if err != nil {
			return nil, nil, nil, err
		}
		tlsCert, tlsKey, tlsRootCert, err := certs_vault.EnrollUser(
			client,
			&enrollment.Vault.Vault,
			&enrollment.Vault.Request,
			enrollRequest,
		)
		if err != nil {
			return nil, nil, nil, err
		}
		return tlsCert, tlsKey, tlsRootCert, nil
	}
	enrollRequest, err := getEnrollRequestForFabricCA(client, enrollment, &conf.Spec, "ca")
	if err != nil {
		return nil, nil, nil, err
	}
	log.Infof("Enroll request: %+v", enrollRequest)
	tlsCert, tlsKey, tlsRootCert, err := certs.EnrollUser(enrollRequest)
	if err != nil {
		return nil, nil, nil, err
	}
	return tlsCert, tlsKey, tlsRootCert, nil
}

func ReenrollSignCryptoMaterial(
	client *kubernetes.Clientset,
	conf *hlfv1alpha1.FabricOrdererNode,
	enrollment *hlfv1alpha1.Component,
	signCertPem string,
	privateKey *ecdsa.PrivateKey,
) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, error) {
	if conf.Spec.CredentialStore == hlfv1alpha1.CredentialStoreVault {
		reenrollRequest, err := getReenrollRequestForVault(enrollment, conf, "ca")
		if err != nil {
			return nil, nil, nil, err
		}
		signCert, signRootCert, err := certs_vault.ReenrollUser(
			client,
			&enrollment.Vault.Vault,
			&enrollment.Vault.Request,
			reenrollRequest,
			signCertPem,
			privateKey,
		)
		if err != nil {
			return nil, nil, nil, err
		}
		return signCert, privateKey, signRootCert, nil
	}

	reenrollRequest, err := getReenrollRequestForFabricCA(client, enrollment, &conf.Spec, "ca")
	if err != nil {
		return nil, nil, nil, err
	}
	signCert, signRootCert, err := certs.ReenrollUser(
		reenrollRequest,
		signCertPem,
		privateKey,
	)
	if err != nil {
		return nil, nil, nil, err
	}
	return signCert, privateKey, signRootCert, nil
}

func getCertBytesFromCATLS(client *kubernetes.Clientset, caTls *hlfv1alpha1.Catls) ([]byte, error) {
	var signCertBytes []byte
	var err error
	if caTls.Cacert != "" {
		signCertBytes, err = base64.StdEncoding.DecodeString(caTls.Cacert)
		if err != nil {
			return nil, err
		}
	} else if caTls.SecretRef != nil {
		secret, err := client.CoreV1().Secrets(caTls.SecretRef.Namespace).Get(context.Background(), caTls.SecretRef.Name, v1.GetOptions{})
		if err != nil {
			return nil, err
		}
		signCertBytes = secret.Data[caTls.SecretRef.Key]
	} else {
		return nil, errors.New("invalid ca tls")
	}
	return signCertBytes, nil
}
func getConfig(
	conf *hlfv1alpha1.FabricOrdererNode,
	client *kubernetes.Clientset,
	chartName string,
	namespace string,
	refreshCerts bool,
) (*fabricOrdChart, error) {
	log.Infof("getConfig for %s renewingCerts=%v", conf.Name, refreshCerts)
	spec := conf.Spec
	tlsParams := conf.Spec.Secret.Enrollment.TLS
	tlsHosts := []string{}
	ingressHosts := []string{}
	tlsHosts = append(tlsHosts, tlsParams.Csr.Hosts...)
	var tlsCert, tlsRootCert, adminCert, adminRootCert, adminClientRootCert, signCert, signRootCert *x509.Certificate
	var tlsKey, adminKey, signKey *ecdsa.PrivateKey
	var err error
	ctx := context.Background()
	if tlsParams.External != nil {
		secret, err := client.CoreV1().Secrets(tlsParams.External.SecretNamespace).Get(ctx, tlsParams.External.SecretName, v1.GetOptions{})
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get secret %s", tlsParams.External.SecretName)
		}
		tlsCert, err = utils.ParseX509Certificate(secret.Data[tlsParams.External.CertificateKey])
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse tls certificate")
		}
		tlsRootCert, err = utils.ParseX509Certificate(secret.Data[tlsParams.External.RootCertificateKey])
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse tls root certificate")
		}
		tlsKey, err = utils.ParseECDSAPrivateKey(secret.Data[tlsParams.External.PrivateKeyKey])
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse tls private key")
		}
	} else if refreshCerts {
		tlsCert, tlsKey, tlsRootCert, err = getExistingTLSCrypto(client, chartName, namespace)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get existing tls crypto material")
		}
		tlsCert, tlsKey, tlsRootCert, err = ReenrollTLSCryptoMaterial(
			client,
			conf,
			&tlsParams,
			string(utils.EncodeX509Certificate(tlsCert)),
			tlsKey,
		)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to reenroll tls crypto material")
		}
		log.Infof("Successfully reenrolled tls crypto material for %s", chartName)
	} else {
		tlsCert, tlsKey, tlsRootCert, err = getExistingTLSCrypto(client, chartName, namespace)
		if err != nil {
			log.Warnf("Failed to get existing tls crypto material for %s, will create new one", chartName)
			tlsCert, tlsKey, tlsRootCert, err = CreateTLSCryptoMaterial(
				client,
				conf,
				&tlsParams,
			)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to create tls crypto material")
			}
		}
	}
	if refreshCerts {
		adminCert, adminKey, adminRootCert, adminClientRootCert, err = getExistingTLSAdminCrypto(client, chartName, namespace)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get existing tls admin crypto material")
		}
		adminCert, adminKey, adminRootCert, adminClientRootCert, err = ReenrollTLSAdminCryptoMaterial(
			client,
			conf,
			&tlsParams,
			string(utils.EncodeX509Certificate(adminCert)),
			adminKey,
		)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create tls admin crypto material")
		}
	} else {
		adminCert, adminKey, adminRootCert, adminClientRootCert, err = getExistingTLSAdminCrypto(client, chartName, namespace)
		if err != nil {
			log.Warnf("Failed to get existing tls admin crypto material, creating new one")
			adminCert, adminKey, adminRootCert, adminClientRootCert, err = CreateTLSAdminCryptoMaterial(
				client,
				conf,
				&tlsParams,
			)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to create tls admin crypto material")
			}
		}
	}
	signParams := conf.Spec.Secret.Enrollment.Component
	if signParams.External != nil {
		secret, err := client.CoreV1().Secrets(signParams.External.SecretNamespace).Get(ctx, signParams.External.SecretName, v1.GetOptions{})
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get secret %s", signParams.External.SecretName)
		}
		signCert, err = utils.ParseX509Certificate(secret.Data[signParams.External.CertificateKey])
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse sign certificate")
		}
		signRootCert, err = utils.ParseX509Certificate(secret.Data[signParams.External.RootCertificateKey])
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse sign root certificate")
		}
		signKey, err = utils.ParseECDSAPrivateKey(secret.Data[signParams.External.PrivateKeyKey])
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse sign private key")
		}
	} else if refreshCerts {
		signCert, signKey, signRootCert, err = getExistingSignCrypto(client, chartName, namespace)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get existing sign crypto material")
		}
		signCertPem := utils.EncodeX509Certificate(signCert)
		signCert, signKey, signRootCert, err = ReenrollSignCryptoMaterial(
			client,
			conf,
			&signParams,
			string(signCertPem),
			signKey,
		)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to reenroll sign crypto material")
		}
		log.Infof("Reenrolled sign crypto material")
	} else {
		signCert, signKey, signRootCert, err = getExistingSignCrypto(client, chartName, namespace)
		if err != nil {
			log.Warnf("Failed to get existing sign crypto material: %s", err)

			signCert, signKey, signRootCert, err = CreateSignCryptoMaterial(
				client,
				conf,
				&signParams,
			)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to create sign crypto material")
			}
		}
	}
	tlsCRTEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: tlsCert.Raw,
	})
	tlsRootCRTEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: tlsRootCert.Raw,
	})
	tlsEncodedPK, err := utils.EncodePrivateKey(tlsKey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to encode tls private key")
	}

	adminCRTEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: adminCert.Raw,
	})
	adminRootCRTEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: adminRootCert.Raw,
	})
	adminClientRootCRTEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: adminClientRootCert.Raw,
	})
	adminEncodedPK, err := utils.EncodePrivateKey(adminKey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to encode admin private key")
	}

	signCRTEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: signCert.Raw,
	})
	signRootCRTEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: signRootCert.Raw,
	})
	signEncodedPK, err := utils.EncodePrivateKey(signKey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to encode sign private key")
	}
	log.Infof("Successfully created crypto material signEncodedPK=%s tlsEncodedPK=%s", signEncodedPK, tlsEncodedPK)
	var hostAliases []HostAlias
	for _, hostAlias := range spec.HostAliases {
		hostAliases = append(hostAliases, HostAlias{
			IP:        hostAlias.IP,
			Hostnames: hostAlias.Hostnames,
		})
	}
	var istio Istio
	if spec.Istio != nil {
		gateway := spec.Istio.IngressGateway
		if gateway == "" {
			gateway = "ingressgateway"
		}
		istio = Istio{
			Port:           spec.Istio.Port,
			Hosts:          spec.Istio.Hosts,
			IngressGateway: gateway,
		}
	} else {
		istio = Istio{
			Port:           0,
			Hosts:          []string{},
			IngressGateway: "",
		}
	}
	var gatewayApi GatewayApi
	if spec.GatewayApi != nil {
		gatewayApiName := spec.GatewayApi.GatewayName
		gatewayApiNamespace := spec.GatewayApi.GatewayNamespace
		if gatewayApiName == "" {
			gatewayApiName = "hlf-gateway"
		}
		if gatewayApiNamespace == "" {
			gatewayApiName = "default"
		}
		gatewayApi = GatewayApi{
			Port:             spec.GatewayApi.Port,
			Hosts:            spec.GatewayApi.Hosts,
			GatewayName:      gatewayApiName,
			GatewayNamespace: gatewayApiNamespace,
		}
	} else {
		gatewayApi = GatewayApi{
			Port:             443,
			Hosts:            []string{},
			GatewayName:      "",
			GatewayNamespace: "",
		}
	}

	traefik := Traefik{}
	if spec.Traefik != nil {
		var middlewares []TraefikMiddleware
		if spec.Traefik.Middlewares != nil {
			for _, middleware := range spec.Traefik.Middlewares {
				middlewares = append(middlewares, TraefikMiddleware{
					Name:      middleware.Name,
					Namespace: middleware.Namespace,
				})
			}
		}
		traefik = Traefik{
			Entrypoints: spec.Traefik.Entrypoints,
			Middlewares: middlewares,
			Hosts:       spec.Traefik.Hosts,
		}
	}

	adminTraefik := Traefik{}
	if spec.AdminTraefik != nil {
		var middlewares []TraefikMiddleware
		if spec.AdminTraefik.Middlewares != nil {
			for _, middleware := range spec.AdminTraefik.Middlewares {
				middlewares = append(middlewares, TraefikMiddleware{
					Name:      middleware.Name,
					Namespace: middleware.Namespace,
				})
			}
		}
		adminTraefik = Traefik{
			Entrypoints: spec.AdminTraefik.Entrypoints,
			Middlewares: middlewares,
			Hosts:       spec.AdminTraefik.Hosts,
		}
	}

	var adminIstio Istio
	if spec.AdminIstio != nil {
		gateway := spec.AdminIstio.IngressGateway
		if gateway == "" {
			gateway = "ingressgateway"
		}
		adminIstio = Istio{
			Port:           spec.AdminIstio.Port,
			Hosts:          spec.AdminIstio.Hosts,
			IngressGateway: gateway,
		}
	} else {
		adminIstio = Istio{
			Port:           0,
			Hosts:          []string{},
			IngressGateway: "",
		}
	}
	var adminGatewayApi GatewayApi
	if spec.AdminGatewayApi != nil {
		gatewayApiName := spec.AdminGatewayApi.GatewayName
		gatewayApiNamespace := spec.GatewayApi.GatewayNamespace
		if gatewayApiName == "" {
			gatewayApiName = "hlf-gateway"
		}
		if gatewayApiNamespace == "" {
			gatewayApiName = "default"
		}
		adminGatewayApi = GatewayApi{
			Port:             spec.AdminGatewayApi.Port,
			Hosts:            spec.AdminGatewayApi.Hosts,
			GatewayName:      gatewayApiName,
			GatewayNamespace: gatewayApiNamespace,
		}
	} else {
		adminGatewayApi = GatewayApi{
			Port:             443,
			Hosts:            []string{},
			GatewayName:      "",
			GatewayNamespace: "",
		}
	}
	var monitor ServiceMonitor
	if spec.ServiceMonitor != nil && spec.ServiceMonitor.Enabled {
		monitor = ServiceMonitor{
			Enabled:           spec.ServiceMonitor.Enabled,
			Labels:            spec.ServiceMonitor.Labels,
			Interval:          spec.ServiceMonitor.Interval,
			ScrapeTimeout:     spec.ServiceMonitor.ScrapeTimeout,
			Scheme:            "http",
			Relabelings:       []interface{}{},
			TargetLabels:      []interface{}{},
			MetricRelabelings: []interface{}{},
			SampleLimit:       spec.ServiceMonitor.SampleLimit,
		}
	} else {
		monitor = ServiceMonitor{Enabled: false}
	}
	proxy := GRPCProxy{
		Enabled:          false,
		Image:            "",
		Tag:              "",
		PullPolicy:       "",
		ImagePullSecrets: nil,
		Istio:            Istio{},
		Resources:        nil,
	}
	if spec.GRPCProxy != nil && spec.GRPCProxy.Enabled {
		proxy = GRPCProxy{
			Enabled:          spec.GRPCProxy.Enabled,
			Image:            spec.GRPCProxy.Image,
			Tag:              spec.GRPCProxy.Tag,
			PullPolicy:       spec.GRPCProxy.Image,
			ImagePullSecrets: spec.GRPCProxy.ImagePullSecrets,
			Istio: Istio{
				Port:           spec.GRPCProxy.Istio.Port,
				Hosts:          spec.GRPCProxy.Istio.Hosts,
				IngressGateway: spec.GRPCProxy.Istio.IngressGateway,
			},
		}
		proxy.Resources = spec.GRPCProxy.Resources
	}

	fabricOrdChart := fabricOrdChart{
		PodLabels:                   spec.PodLabels,
		PodAnnotations:              spec.PodAnnotations,
		GatewayApi:                  gatewayApi,
		Istio:                       istio,
		Traefik:                     traefik,
		AdminGatewayApi:             adminGatewayApi,
		AdminIstio:                  adminIstio,
		AdminTraefik:                adminTraefik,
		Replicas:                    spec.Replicas,
		Genesis:                     spec.Genesis,
		ChannelParticipationEnabled: spec.ChannelParticipationEnabled,
		BootstrapMethod:             string(spec.BootstrapMethod),
		Admin: admin{
			Cert:          string(adminCRTEncoded),
			Key:           string(adminEncodedPK),
			RootCAs:       string(adminRootCRTEncoded),
			ClientRootCAs: string(adminClientRootCRTEncoded),
		},
		Cacert:       string(signRootCRTEncoded),
		NodeSelector: spec.NodeSelector,
		Tlsrootcert:  string(tlsRootCRTEncoded),
		AdminCert:    "",
		Affinity:     spec.Affinity,
		Cert:         string(signCRTEncoded),
		Key:          string(signEncodedPK),
		TLS: tls{
			Cert: string(tlsCRTEncoded),
			Key:  string(tlsEncodedPK),
		},
		Tolerations:      spec.Tolerations,
		Resources:        spec.Resources,
		FullnameOverride: conf.Name,
		HostAliases:      hostAliases,
		Service: service{
			Type:               string(spec.Service.Type),
			Port:               7050,
			PortOperations:     9443,
			NodePort:           spec.Service.NodePortRequest,
			NodePortOperations: spec.Service.NodePortOperations,
		},
		Image: image{
			Repository: spec.Image,
			Tag:        spec.Tag,
			PullPolicy: string(spec.PullPolicy),
		},
		Persistence: persistence{
			Enabled:      true,
			Annotations:  annotations{},
			StorageClass: spec.Storage.StorageClass,
			AccessMode:   string(spec.Storage.AccessMode),
			Size:         spec.Storage.Size,
		},
		Ord: ord{
			Type:  "etcdraft",
			MspID: spec.MspID,
			TLS: tlsConfiguration{
				Server: ordServer{
					Enabled: true,
				},
				Client: ordClient{
					Enabled: false,
				},
			},
		},
		Clientcerts:      clientcerts{},
		Hosts:            ingressHosts,
		Logging:          Logging{Spec: "info"},
		ServiceMonitor:   monitor,
		EnvVars:          spec.Env,
		ImagePullSecrets: spec.ImagePullSecrets,
		Proxy:            proxy,
	}

	return &fabricOrdChart, nil
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

func GetOrdererState(conf *action.Configuration, config *rest.Config, releaseName string, ns string, ordNode *hlfv1alpha1.FabricOrdererNode) (*hlfv1alpha1.FabricOrdererNodeStatus, error) {
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
	r := &hlfv1alpha1.FabricOrdererNodeStatus{
		Status:  hlfv1alpha1.RunningStatus,
		Message: "",
	}
	tlsCrt, _, rootTlsCrt, err := getExistingTLSCrypto(clientSet, releaseName, ns)
	if err != nil {
		return nil, err
	}
	r.TlsCert = string(utils.EncodeX509Certificate(tlsCrt))
	r.TlsCACert = string(utils.EncodeX509Certificate(rootTlsCrt))
	hlfmetrics.UpdateCertificateExpiry(
		"orderer",
		"tls",
		tlsCrt,
		ordNode.Name,
		ns,
	)
	tlsAdminCrt, _, _, _, err := getExistingTLSAdminCrypto(clientSet, releaseName, ns)
	if err != nil {
		return nil, err
	}
	r.TlsAdminCert = string(utils.EncodeX509Certificate(tlsAdminCrt))
	hlfmetrics.UpdateCertificateExpiry(
		"orderer",
		"tls_admin",
		tlsAdminCrt,
		ordNode.Name,
		ns,
	)
	signCrt, _, rootSignCrt, err := getExistingSignCrypto(clientSet, releaseName, ns)
	if err != nil {
		return nil, err
	}
	r.SignCert = string(utils.EncodeX509Certificate(signCrt))
	r.SignCACert = string(utils.EncodeX509Certificate(rootSignCrt))
	hlfmetrics.UpdateCertificateExpiry(
		"orderer",
		"sign",
		signCrt,
		ordNode.Name,
		ns,
	)
	objects := utils.ParseK8sYaml([]byte(rel.Manifest))
	for _, object := range objects {
		kind := object.GetObjectKind().GroupVersionKind().Kind
		switch kind {
		case "Deployment":
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
		case "Service":
			svcSpec := object.(*corev1.Service)
			svc, err := clientSet.CoreV1().Services(ns).Get(ctx, svcSpec.Name, v1.GetOptions{})
			if err != nil {
				return nil, err
			}
			for _, port := range svc.Spec.Ports {
				switch port.Name {
				case "grpc":
					r.NodePort = int(port.NodePort)
				case "admin":
					r.AdminPort = int(port.NodePort)
				case "operations":
					r.OperationsPort = int(port.NodePort)
				}
			}
		}
	}
	return r, nil
}

func getEnrollRequestForFabricCA(client *kubernetes.Clientset, enrollment *hlfv1alpha1.Component, spec *hlfv1alpha1.FabricOrdererNodeSpec, profile string) (certs.EnrollUserRequest, error) {
	cacert, err := getCertBytesFromCATLS(client, enrollment.Catls)
	if err != nil {
		return certs.EnrollUserRequest{}, err
	}
	tlsCAUrl := fmt.Sprintf("https://%s:%d", enrollment.Cahost, enrollment.Caport)
	return certs.EnrollUserRequest{
		Hosts:   []string{},
		CN:      "",
		User:    enrollment.Enrollid,
		Secret:  enrollment.Enrollsecret,
		URL:     tlsCAUrl,
		Name:    enrollment.Caname,
		MSPID:   spec.MspID,
		TLSCert: string(cacert),
	}, nil
}

func getEnrollRequestForFabricCATLS(client *kubernetes.Clientset, enrollment *hlfv1alpha1.TLSComponent, spec *hlfv1alpha1.FabricOrdererNodeSpec, profile string) (certs.EnrollUserRequest, error) {
	cacert, err := getCertBytesFromCATLS(client, enrollment.Catls)
	if err != nil {
		return certs.EnrollUserRequest{}, err
	}
	tlsCAUrl := fmt.Sprintf("https://%s:%d", enrollment.Cahost, enrollment.Caport)
	var hosts []string
	hosts = append(hosts, enrollment.Csr.Hosts...)
	if spec.Istio != nil {
		hosts = append(hosts, spec.Istio.Hosts...)
	}
	if spec.Traefik != nil {
		hosts = append(hosts, spec.Traefik.Hosts...)
	}
	if spec.AdminIstio != nil {
		hosts = append(hosts, spec.AdminIstio.Hosts...)
	}
	if spec.AdminTraefik != nil {
		hosts = append(hosts, spec.AdminTraefik.Hosts...)
	}
	return certs.EnrollUserRequest{
		Hosts:      hosts,
		CN:         enrollment.Enrollid,
		Attributes: nil,
		User:       enrollment.Enrollid,
		Secret:     enrollment.Enrollsecret,
		URL:        tlsCAUrl,
		Name:       enrollment.Caname,
		MSPID:      spec.MspID,
		TLSCert:    string(cacert),
		Profile:    profile,
	}, nil
}

func getEnrollRequestForVault(component *hlfv1alpha1.Component, conf *hlfv1alpha1.FabricOrdererNode, profile string) (certs_vault.EnrollUserRequest, error) {
	return certs_vault.EnrollUserRequest{
		MSPID:      conf.Spec.MspID,
		User:       component.Enrollid,
		Hosts:      []string{},
		CN:         conf.Name,
		Attributes: nil,
	}, nil
}

func getEnrollRequestForVaultTLS(tls *hlfv1alpha1.TLSComponent, conf *hlfv1alpha1.FabricOrdererNode, profile string) (certs_vault.EnrollUserRequest, error) {
	tlsParams := tls
	var hosts []string
	hosts = append(hosts, tlsParams.Csr.Hosts...)
	if conf.Spec.Istio != nil {
		hosts = append(hosts, conf.Spec.Istio.Hosts...)
	}
	if conf.Spec.Traefik != nil {
		hosts = append(hosts, conf.Spec.Traefik.Hosts...)
	}
	if conf.Spec.AdminIstio != nil {
		hosts = append(hosts, conf.Spec.AdminIstio.Hosts...)
	}
	if conf.Spec.AdminTraefik != nil {
		hosts = append(hosts, conf.Spec.AdminTraefik.Hosts...)
	}
	return certs_vault.EnrollUserRequest{
		MSPID:      conf.Spec.MspID,
		User:       tls.Enrollid,
		Hosts:      hosts,
		CN:         conf.Name,
		Attributes: nil,
	}, nil
}

func getReenrollRequestForFabricCA(client *kubernetes.Clientset, enrollment *hlfv1alpha1.Component, conf *hlfv1alpha1.FabricOrdererNodeSpec, profile string) (certs.ReenrollUserRequest, error) {
	cacert, err := getCertBytesFromCATLS(client, enrollment.Catls)
	if err != nil {
		return certs.ReenrollUserRequest{}, err
	}
	tlsCAUrl := fmt.Sprintf("https://%s:%d", enrollment.Cahost, enrollment.Caport)
	return certs.ReenrollUserRequest{
		TLSCert:  string(cacert),
		Hosts:    []string{},
		CN:       "",
		URL:      tlsCAUrl,
		Name:     enrollment.Caname,
		EnrollID: enrollment.Enrollid,
		MSPID:    conf.MspID,
	}, nil
}

func getReenrollRequestForFabricCATLS(client *kubernetes.Clientset, enrollment *hlfv1alpha1.TLSComponent, conf *hlfv1alpha1.FabricOrdererNodeSpec, profile string) (certs.ReenrollUserRequest, error) {
	cacert, err := getCertBytesFromCATLS(client, enrollment.Catls)
	if err != nil {
		return certs.ReenrollUserRequest{}, err
	}
	tlsParams := enrollment
	var hosts []string
	hosts = append(hosts, tlsParams.Csr.Hosts...)
	if conf.Istio != nil {
		hosts = append(hosts, conf.Istio.Hosts...)
	}
	if conf.Traefik != nil {
		hosts = append(hosts, conf.Traefik.Hosts...)
	}
	if conf.AdminIstio != nil {
		hosts = append(hosts, conf.AdminIstio.Hosts...)
	}
	if conf.AdminTraefik != nil {
		hosts = append(hosts, conf.AdminTraefik.Hosts...)
	}
	tlsCAUrl := fmt.Sprintf("https://%s:%d", enrollment.Cahost, enrollment.Caport)
	return certs.ReenrollUserRequest{
		TLSCert:  string(cacert),
		Hosts:    hosts,
		Profile:  profile,
		CN:       "",
		URL:      tlsCAUrl,
		Name:     enrollment.Caname,
		EnrollID: enrollment.Enrollid,
		MSPID:    conf.MspID,
	}, nil
}

func getReenrollRequestForVault(enrollment *hlfv1alpha1.Component, conf *hlfv1alpha1.FabricOrdererNode, profile string) (certs_vault.ReenrollUserRequest, error) {
	return certs_vault.ReenrollUserRequest{
		MSPID:      conf.Spec.MspID,
		Hosts:      []string{},
		CN:         conf.Name,
		Attributes: nil,
	}, nil
}

func getReenrollRequestForVaultTLS(tls *hlfv1alpha1.TLSComponent, conf *hlfv1alpha1.FabricOrdererNode, profile string) (certs_vault.ReenrollUserRequest, error) {
	tlsParams := tls
	var hosts []string
	hosts = append(hosts, tlsParams.Csr.Hosts...)
	if conf.Spec.Istio != nil {
		hosts = append(hosts, conf.Spec.Istio.Hosts...)
	}
	if conf.Spec.Traefik != nil {
		hosts = append(hosts, conf.Spec.Traefik.Hosts...)
	}
	if conf.Spec.AdminIstio != nil {
		hosts = append(hosts, conf.Spec.AdminIstio.Hosts...)
	}
	if conf.Spec.AdminTraefik != nil {
		hosts = append(hosts, conf.Spec.AdminTraefik.Hosts...)
	}

	return certs_vault.ReenrollUserRequest{
		MSPID:      conf.Spec.MspID,
		Hosts:      hosts,
		CN:         conf.Name,
		Attributes: nil,
	}, nil
}
