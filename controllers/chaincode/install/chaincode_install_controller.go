package install

import (
	"context"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	fab2 "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/cryptosuite"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/cryptosuite/bccsp/sw"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/ccpackager/lifecycle"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	mspimpl "github.com/hyperledger/fabric-sdk-go/pkg/msp"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"k8s.io/client-go/kubernetes"

	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/go-logr/logr"
	"github.com/kfsoftware/hlf-operator/controllers/utils"
	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	operatorv1 "github.com/kfsoftware/hlf-operator/pkg/client/clientset/versioned"
	"github.com/kfsoftware/hlf-operator/pkg/nc"
	"github.com/kfsoftware/hlf-operator/pkg/status"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type ChaincodePackageOptions struct {
	ChaincodeName  string
	ChaincodeLabel string
	Address        string
}

type Metadata struct {
	Type  string `json:"type"`
	Label string `json:"label"`
}

type Connection struct {
	Address     string `json:"address"`
	DialTimeout string `json:"dial_timeout"`
	TLSRequired bool   `json:"tls_required"`
}

func generateChaincodePackage(options ChaincodePackageOptions) (string, error) {
	outputDir, err := os.MkdirTemp("", "chaincode_package")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(outputDir)

	// Create metadata.json
	metadata := Metadata{
		Type:  "ccaas",
		Label: options.ChaincodeLabel,
	}
	metadataPath := filepath.Join(outputDir, "metadata.json")
	if err := writeJSONFile(metadataPath, metadata); err != nil {
		return "", fmt.Errorf("failed to write metadata.json: %w", err)
	}

	// Create connection.json
	connection := Connection{
		Address:     options.Address,
		DialTimeout: "10s",
		TLSRequired: false,
	}
	connectionPath := filepath.Join(outputDir, "connection.json")
	if err := writeJSONFile(connectionPath, connection); err != nil {
		return "", fmt.Errorf("failed to write connection.json: %w", err)
	}

	// Create code.tar.gz
	codeTarPath := filepath.Join(outputDir, "code.tar.gz")
	if err := createTarGz([]string{connectionPath}, codeTarPath); err != nil {
		return "", fmt.Errorf("failed to create code.tar.gz: %w", err)
	}

	// Create chaincode.tgz
	chaincodeTarPath := filepath.Join(outputDir, "chaincode.tgz")
	if err := createTarGz([]string{metadataPath, codeTarPath}, chaincodeTarPath); err != nil {
		return "", fmt.Errorf("failed to create chaincode.tgz: %w", err)
	}

	// Move the chaincode.tgz to a new location outside the temp directory
	finalPath := filepath.Join(os.TempDir(), fmt.Sprintf("chaincode_%d.tgz", time.Now().UnixNano()))
	if err := os.Rename(chaincodeTarPath, finalPath); err != nil {
		return "", fmt.Errorf("failed to move chaincode.tgz: %w", err)
	}

	return finalPath, nil
}

func writeJSONFile(filePath string, data interface{}) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func createTarGz(inputFiles []string, outputFile string) error {
	// Create the output file
	out, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer out.Close()

	// Create gzip writer
	gw := gzip.NewWriter(out)
	defer gw.Close()

	// Create tar writer
	tw := tar.NewWriter(gw)
	defer tw.Close()

	// Add files to the tar archive
	for _, file := range inputFiles {
		if err := addFileToTar(tw, file); err != nil {
			return err
		}
	}

	return nil
}

func addFileToTar(tw *tar.Writer, filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	header, err := tar.FileInfoHeader(info, info.Name())
	if err != nil {
		return err
	}

	header.Name = filepath.Base(filename)
	// Canonicalize everything that comes from the filesystem rather than the
	// package contents. The package ID is label + SHA256 over the raw archive
	// bytes, headers included; the temp files are rewritten on every reconcile,
	// so filesystem-derived header fields (most visibly ModTime, with its
	// 1-second resolution) made the package ID non-deterministic for an
	// identical spec. See #323.
	header.ModTime = time.Unix(0, 0)
	header.AccessTime = time.Time{}
	header.ChangeTime = time.Time{}
	header.Uid = 0
	header.Gid = 0
	header.Uname = ""
	header.Gname = ""
	header.Mode = 0o644

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	_, err = io.Copy(tw, file)
	return err
}

type FabricChaincodeInstallReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
	Config *rest.Config
}

const chaincodeInstallFinalizer = "finalizer.chaincodeInstall.hlf.kungfusoftware.es"

func (r *FabricChaincodeInstallReconciler) finalizeChaincodeInstall(reqLogger logr.Logger, m *hlfv1alpha1.FabricChaincodeInstall) error {
	ns := m.Namespace
	if ns == "" {
		ns = "default"
	}
	reqLogger.Info("Successfully finalized ChaincodeInstall")

	return nil
}

func (r *FabricChaincodeInstallReconciler) addFinalizer(reqLogger logr.Logger, m *hlfv1alpha1.FabricChaincodeInstall) error {
	reqLogger.Info("Adding Finalizer for the ChaincodeInstall")
	controllerutil.AddFinalizer(m, chaincodeInstallFinalizer)

	// Update CR
	err := r.Update(context.TODO(), m)
	if err != nil {
		reqLogger.Error(err, "Failed to update ChaincodeInstall with finalizer")
		return err
	}
	return nil
}

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricchaincodeinstalls,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricchaincodeinstalls/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricchaincodeinstalls/finalizers,verbs=get;update;patch

func (r *FabricChaincodeInstallReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	reqLogger := r.Log.WithValues("hlf", req.NamespacedName)
	fabricChaincodeInstall := &hlfv1alpha1.FabricChaincodeInstall{}

	err := r.Get(ctx, req.NamespacedName, fabricChaincodeInstall)
	if err != nil {
		log.Debugf("Error getting the object %s error=%v", req.NamespacedName, err)
		if apierrors.IsNotFound(err) {
			reqLogger.Info("MainChannel resource not found. Ignoring since object must be deleted.")
			return ctrl.Result{}, nil
		}
		reqLogger.Error(err, "Failed to get MainChannel.")
		return ctrl.Result{}, err
	}
	markedToBeDeleted := fabricChaincodeInstall.GetDeletionTimestamp() != nil
	if markedToBeDeleted {
		if utils.Contains(fabricChaincodeInstall.GetFinalizers(), chaincodeInstallFinalizer) {
			if err := r.finalizeChaincodeInstall(reqLogger, fabricChaincodeInstall); err != nil {
				return ctrl.Result{}, err
			}
			controllerutil.RemoveFinalizer(fabricChaincodeInstall, chaincodeInstallFinalizer)
			err := r.Update(ctx, fabricChaincodeInstall)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}
	if !utils.Contains(fabricChaincodeInstall.GetFinalizers(), chaincodeInstallFinalizer) {
		if err := r.addFinalizer(reqLogger, fabricChaincodeInstall); err != nil {
			return ctrl.Result{}, err
		}
	}
	clientSet, err := utils.GetClientKubeWithConf(r.Config)
	if err != nil {
		r.setConditionStatus(ctx, fabricChaincodeInstall, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricChaincodeInstall)
	}
	hlfClientSet, err := operatorv1.NewForConfig(r.Config)
	if err != nil {
		r.setConditionStatus(ctx, fabricChaincodeInstall, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricChaincodeInstall)
	}
	var networkConfig string
	ncResponse, err := nc.GenerateNetworkConfigForChaincodeInstall(fabricChaincodeInstall, clientSet, hlfClientSet, fabricChaincodeInstall.Spec.MSPID)
	if err != nil {
		r.setConditionStatus(ctx, fabricChaincodeInstall, hlfv1alpha1.FailedStatus, false, errors.Wrapf(err, "failed to generate network config"), false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricChaincodeInstall)
	}
	networkConfig = ncResponse.NetworkConfig
	resClient, sdk, err := getResmgmtBasedOnIdentity(ctx, fabricChaincodeInstall, networkConfig, clientSet, fabricChaincodeInstall.Spec.MSPID)
	if err != nil {
		r.setConditionStatus(ctx, fabricChaincodeInstall, hlfv1alpha1.FailedStatus, false, errors.Wrapf(err, "failed to get resmgmt"), false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricChaincodeInstall)
	}
	defer sdk.Close()
	chaincodePackage, err := generateChaincodePackage(ChaincodePackageOptions{
		ChaincodeName:  fabricChaincodeInstall.Spec.ChaincodePackage.Name,
		ChaincodeLabel: fabricChaincodeInstall.Spec.ChaincodePackage.Name,
		Address:        fabricChaincodeInstall.Spec.ChaincodePackage.Address,
	})
	if err != nil {
		r.setConditionStatus(ctx, fabricChaincodeInstall, hlfv1alpha1.FailedStatus, false, errors.Wrapf(err, "failed to generate chaincode package"), false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricChaincodeInstall)
	}
	log.Infof("Chaincode package %s", chaincodePackage)
	pkg, err := os.ReadFile(chaincodePackage)
	if err != nil {
		r.setConditionStatus(ctx, fabricChaincodeInstall, hlfv1alpha1.FailedStatus, false, errors.Wrapf(err, "failed to read chaincode package"), false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricChaincodeInstall)
	}
	packageID := lifecycle.ComputePackageID(fabricChaincodeInstall.Spec.ChaincodePackage.Name, pkg)
	log.Infof("PackageID %s", packageID)
	chaincodeStatus := &hlfv1alpha1.FabricChaincodeInstallStatus{
		PackageID:      packageID,
		FailedPeers:    []hlfv1alpha1.FailedPeer{},
		InstalledPeers: []hlfv1alpha1.InstalledPeer{},
	}
	for _, peer := range fabricChaincodeInstall.Spec.Peers {
		peerName := fmt.Sprintf("%s.%s", peer.Name, peer.Namespace)
		log.Infof("Installing chaincode on peer %s", peerName)
		_, err := resClient.LifecycleInstallCC(
			resmgmt.LifecycleInstallCCRequest{
				Label:   fabricChaincodeInstall.Spec.ChaincodePackage.Name,
				Package: pkg,
			},
			resmgmt.WithTargetEndpoints(peerName),
			resmgmt.WithTimeout(fab2.ResMgmt, 20*time.Minute),
			resmgmt.WithTimeout(fab2.PeerResponse, 20*time.Minute),
		)
		if err != nil {
			chaincodeStatus.FailedPeers = append(chaincodeStatus.FailedPeers, hlfv1alpha1.FailedPeer{
				Name:   peerName,
				Reason: err.Error(),
			})
		} else {
			chaincodeStatus.InstalledPeers = append(chaincodeStatus.InstalledPeers, hlfv1alpha1.InstalledPeer{
				Name: peerName,
			})
		}
	}
	for _, peer := range fabricChaincodeInstall.Spec.ExternalPeers {
		peerName := peer.URL
		_, err := resClient.LifecycleInstallCC(
			resmgmt.LifecycleInstallCCRequest{
				Label:   fabricChaincodeInstall.Spec.ChaincodePackage.Name,
				Package: pkg,
			},
			resmgmt.WithTargetEndpoints(peerName),
			resmgmt.WithTimeout(fab2.ResMgmt, 20*time.Minute),
			resmgmt.WithTimeout(fab2.PeerResponse, 20*time.Minute),
		)
		if err != nil {
			chaincodeStatus.FailedPeers = append(chaincodeStatus.FailedPeers, hlfv1alpha1.FailedPeer{
				Name:   peerName,
				Reason: err.Error(),
			})
		} else {
			chaincodeStatus.InstalledPeers = append(chaincodeStatus.InstalledPeers, hlfv1alpha1.InstalledPeer{
				Name: peerName,
			})
		}
	}
	fabricChaincodeInstall.Status = *chaincodeStatus
	fabricChaincodeInstall.Status.Status = hlfv1alpha1.RunningStatus
	fabricChaincodeInstall.Status.InstalledPeers = chaincodeStatus.InstalledPeers
	fabricChaincodeInstall.Status.FailedPeers = chaincodeStatus.FailedPeers
	fabricChaincodeInstall.Status.Conditions.SetCondition(status.Condition{
		Type:   status.ConditionType(hlfv1alpha1.RunningStatus),
		Status: corev1.ConditionTrue,
	})
	log.Infof("Chaincode status: %v", chaincodeStatus)
	return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricChaincodeInstall)
}

type identity struct {
	Cert Pem `json:"cert"`
	Key  Pem `json:"key"`
}

type Pem struct {
	Pem string
}

func getResmgmtBasedOnIdentity(ctx context.Context, chInstall *hlfv1alpha1.FabricChaincodeInstall, networkConfig string, clientSet *kubernetes.Clientset, mspID string) (*resmgmt.Client, *fabsdk.FabricSDK, error) {
	configBackend := config.FromRaw([]byte(networkConfig), "yaml")
	sdk, err := fabsdk.New(configBackend)
	if err != nil {
		return nil, nil, err
	}
	idConfig := chInstall.Spec.HLFIdentity
	secret, err := clientSet.CoreV1().Secrets(idConfig.SecretNamespace).Get(ctx, idConfig.SecretName, v1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}
	secretData, ok := secret.Data[idConfig.SecretKey]
	if !ok {

		return nil, nil, err
	}
	id := &identity{}
	err = yaml.Unmarshal(secretData, id)
	if err != nil {
		return nil, nil, err
	}
	sdkConfig, err := sdk.Config()
	if err != nil {
		return nil, nil, err
	}
	cryptoConfig := cryptosuite.ConfigFromBackend(sdkConfig)
	cryptoSuite, err := sw.GetSuiteByConfig(cryptoConfig)
	if err != nil {
		return nil, nil, err
	}
	userStore := mspimpl.NewMemoryUserStore()
	endpointConfig, err := fab.ConfigFromBackend(sdkConfig)
	if err != nil {
		return nil, nil, err
	}
	identityManager, err := mspimpl.NewIdentityManager(mspID, userStore, cryptoSuite, endpointConfig)
	if err != nil {
		return nil, nil, err
	}
	signingIdentity, err := identityManager.CreateSigningIdentity(
		msp.WithPrivateKey([]byte(id.Key.Pem)),
		msp.WithCert([]byte(id.Cert.Pem)),
	)
	if err != nil {
		return nil, nil, err
	}
	sdkContext := sdk.Context(
		fabsdk.WithIdentity(signingIdentity),
		fabsdk.WithOrg(mspID),
	)
	resClient, err := resmgmt.New(sdkContext)
	if err != nil {
		return nil, nil, err
	}
	return resClient, sdk, nil
}

func (r *FabricChaincodeInstallReconciler) setConditionStatus(ctx context.Context, p *hlfv1alpha1.FabricChaincodeInstall, conditionType hlfv1alpha1.DeploymentStatus, statusFlag bool, err error, statusUnknown bool) (update bool) {
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

func (r *FabricChaincodeInstallReconciler) updateCRStatusOrFailReconcile(ctx context.Context, log logr.Logger, p *hlfv1alpha1.FabricChaincodeInstall) (
	reconcile.Result, error) {
	if err := r.Status().Update(ctx, p); err != nil {
		log.Error(err, fmt.Sprintf("%v failed to update the application status", ErrClientK8s))
		return reconcile.Result{
			Requeue:      true,
			RequeueAfter: time.Second * 10,
		}, nil
	}

	// If status is failed, requeue after 1 minute
	if p.Status.Status == hlfv1alpha1.FailedStatus {
		return reconcile.Result{
			RequeueAfter: 1 * time.Minute,
		}, nil
	}

	// If status is running/success, don't requeue
	if p.Status.Status == hlfv1alpha1.RunningStatus {
		return reconcile.Result{}, nil
	}

	// For any other status, requeue after 1 minute
	return reconcile.Result{
		RequeueAfter: 1 * time.Minute,
	}, nil
}

func (r *FabricChaincodeInstallReconciler) SetupWithManager(mgr ctrl.Manager) error {
	managedBy := ctrl.NewControllerManagedBy(mgr)
	return managedBy.
		For(&hlfv1alpha1.FabricChaincodeInstall{}).
		Complete(r)
}
