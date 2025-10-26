package mainchannel

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-config/configtx"
	"github.com/hyperledger/fabric-config/configtx/membership"
	"github.com/hyperledger/fabric-config/configtx/orderer"
	"github.com/hyperledger/fabric-config/protolator"
	cb "github.com/hyperledger/fabric-protos-go/common"
	sb "github.com/hyperledger/fabric-protos-go/orderer/smartbft"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/errors/retry"
	fab2 "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/cryptosuite"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/cryptosuite/bccsp/sw"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/resource"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	mspimpl "github.com/hyperledger/fabric-sdk-go/pkg/msp"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/kfsoftware/hlf-operator/controllers/utils"
	"github.com/kfsoftware/hlf-operator/kubectl-hlf/cmd/helpers"
	"github.com/kfsoftware/hlf-operator/kubectl-hlf/cmd/helpers/osnadmin"
	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	operatorv1 "github.com/kfsoftware/hlf-operator/pkg/client/clientset/versioned"
	"github.com/kfsoftware/hlf-operator/pkg/nc"
	"github.com/kfsoftware/hlf-operator/pkg/status"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// FabricMainChannelReconciler reconciles a FabricMainChannel object
type FabricMainChannelReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
	Config *rest.Config
}

const mainChannelFinalizer = "finalizer.mainChannel.hlf.kungfusoftware.es"

var (
	ErrClientK8s          = errors.New("k8sAPIClientError")
	ErrInvalidConfig      = errors.New("invalidConfigurationError")
	ErrChannelOperation   = errors.New("channelOperationError")
	ErrOrdererConnection  = errors.New("ordererConnectionError")
	ErrIdentityManagement = errors.New("identityManagementError")
)

func (r *FabricMainChannelReconciler) finalizeMainChannel(reqLogger logr.Logger, m *hlfv1alpha1.FabricMainChannel) error {
	ns := m.Namespace
	if ns == "" {
		ns = "default"
	}

	reqLogger.Info("Successfully finalized main channel",
		"channel", m.Name,
		"namespace", ns,
	)
	return nil
}

func (r *FabricMainChannelReconciler) addFinalizer(reqLogger logr.Logger, m *hlfv1alpha1.FabricMainChannel) error {
	reqLogger.Info("Adding finalizer for main channel",
		"channel", m.Name,
		"namespace", m.Namespace,
		"finalizer", mainChannelFinalizer,
	)

	controllerutil.AddFinalizer(m, mainChannelFinalizer)

	if err := r.Update(context.TODO(), m); err != nil {
		reqLogger.Error(err, "Failed to update main channel with finalizer",
			"channel", m.Name,
			"namespace", m.Namespace,
		)
		return errors.Wrap(err, "failed to add finalizer to main channel")
	}

	reqLogger.Info("Successfully added finalizer to main channel",
		"channel", m.Name,
		"namespace", m.Namespace,
	)
	return nil
}

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricmainchannels,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricmainchannels/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricmainchannels/finalizers,verbs=get;update;patch
func (r *FabricMainChannelReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	reqLogger := r.Log.WithValues("hlf", req.NamespacedName)
	fabricMainChannel := &hlfv1alpha1.FabricMainChannel{}

	reqLogger.Info("Starting main channel reconciliation",
		"channel", req.Name,
		"namespace", req.Namespace,
	)

	// Validate configuration and handle initial setup
	if err := r.validateAndSetup(ctx, req, fabricMainChannel, reqLogger); err != nil {
		return r.handleReconcileError(ctx, fabricMainChannel, err)
	}

	// Early return if resource is being deleted or doesn't exist
	if fabricMainChannel.Name == "" {
		return ctrl.Result{}, nil
	}

	// Get Kubernetes clients
	clientSet, hlfClientSet, err := r.getClientSets()
	if err != nil {
		return r.handleReconcileError(ctx, fabricMainChannel,
			errors.Wrap(err, "failed to get kubernetes clients"))
	}

	// Setup Fabric SDK
	sdk, err := r.setupSDK(fabricMainChannel, clientSet, hlfClientSet)
	if err != nil {
		return r.handleReconcileError(ctx, fabricMainChannel,
			errors.Wrap(err, "failed to setup fabric SDK"))
	}
	defer func() {
		sdk.Close()
	}()

	resClient, _, err := r.setupResClient(sdk, fabricMainChannel, clientSet)
	if err != nil {
		return r.handleReconcileError(ctx, fabricMainChannel,
			errors.Wrap(err, "failed to setup resource management client"))
	}

	options, endpoints := r.setupResmgmtOptions(fabricMainChannel)
	if len(endpoints) == 0 {
		return r.handleReconcileError(ctx, fabricMainChannel,
			errors.Wrap(ErrInvalidConfig, "no orderer endpoints configured"))
	}

	reqLogger.Info("Checking if channel exists",
		"channel", fabricMainChannel.Spec.Name,
		"ordererEndpoints", len(endpoints),
	)

	// Try to get existing channel config
	_, err = r.queryConfigBlockFromOrdererWithRoundRobin(resClient, fabricMainChannel.Spec.Name, endpoints, options)
	if err != nil {
		// Channel doesn't exist, create it
		reqLogger.Info("Channel does not exist, creating new channel",
			"channel", fabricMainChannel.Spec.Name,
		)

		if err := r.createAndJoinChannel(ctx, fabricMainChannel, clientSet, hlfClientSet, resClient, endpoints, options); err != nil {
			return r.handleReconcileError(ctx, fabricMainChannel, err)
		}
	} else {
		reqLogger.Info("Channel already exists, proceeding with configuration update",
			"channel", fabricMainChannel.Spec.Name,
		)
	}

	// Update channel configuration if needed
	if err := r.updateChannelConfig(ctx, fabricMainChannel, resClient, options, sdk, clientSet); err != nil {
		return r.handleReconcileError(ctx, fabricMainChannel,
			errors.Wrap(err, "failed to update channel configuration"))
	}

	// Allow time for configuration to propagate
	time.Sleep(3 * time.Second)

	// Save channel configuration to ConfigMap
	if err := r.saveChannelConfig(ctx, fabricMainChannel, resClient); err != nil {
		return r.handleReconcileError(ctx, fabricMainChannel,
			errors.Wrap(err, "failed to save channel configuration"))
	}

	return r.finalizeReconcile(ctx, fabricMainChannel)
}

func (r *FabricMainChannelReconciler) validateAndSetup(ctx context.Context, req ctrl.Request, fabricMainChannel *hlfv1alpha1.FabricMainChannel, reqLogger logr.Logger) error {
	err := r.Get(ctx, req.NamespacedName, fabricMainChannel)
	if err != nil {
		if apierrors.IsNotFound(err) {
			reqLogger.Info("Main channel resource not found, ignoring since object must be deleted")
			return nil
		}
		reqLogger.Error(err, "Failed to get main channel resource",
			"channel", req.Name,
			"namespace", req.Namespace,
		)
		return errors.Wrap(err, "failed to get main channel resource")
	}

	// Validate basic configuration
	if err := r.validateMainChannelConfig(fabricMainChannel); err != nil {
		reqLogger.Error(err, "Invalid main channel configuration",
			"channel", fabricMainChannel.Name,
			"namespace", fabricMainChannel.Namespace,
		)
		return errors.Wrap(err, "invalid main channel configuration")
	}

	// Handle deletion
	if fabricMainChannel.GetDeletionTimestamp() != nil {
		return r.handleDeletion(reqLogger, fabricMainChannel)
	}

	// Add finalizer if not present
	if !utils.Contains(fabricMainChannel.GetFinalizers(), mainChannelFinalizer) {
		return r.addFinalizer(reqLogger, fabricMainChannel)
	}

	return nil
}

func (r *FabricMainChannelReconciler) validateMainChannelConfig(channel *hlfv1alpha1.FabricMainChannel) error {
	if channel.Spec.Name == "" {
		return errors.Wrap(ErrInvalidConfig, "channel name cannot be empty")
	}

	if len(channel.Spec.OrdererOrganizations) == 0 {
		return errors.Wrap(ErrInvalidConfig, "at least one orderer organization must be specified")
	}

	if len(channel.Spec.AdminOrdererOrganizations) == 0 {
		return errors.Wrap(ErrInvalidConfig, "at least one admin orderer organization must be specified")
	}

	// Validate that admin orderer organizations exist in orderer organizations
	for _, adminOrg := range channel.Spec.AdminOrdererOrganizations {
		found := false
		for _, ordOrg := range channel.Spec.OrdererOrganizations {
			if adminOrg.MSPID == ordOrg.MSPID {
				found = true
				break
			}
		}
		if !found {
			return errors.Wrapf(ErrInvalidConfig, "admin orderer organization %s not found in orderer organizations", adminOrg.MSPID)
		}
	}

	// Validate identities exist for admin organizations
	for _, adminOrg := range channel.Spec.AdminOrdererOrganizations {
		identityKey := fmt.Sprintf("%s-sign", adminOrg.MSPID)
		if _, exists := channel.Spec.Identities[identityKey]; !exists {
			// Try without -sign suffix
			if _, exists := channel.Spec.Identities[adminOrg.MSPID]; !exists {
				return errors.Wrapf(ErrInvalidConfig, "identity not found for admin orderer organization %s", adminOrg.MSPID)
			}
		}
	}

	return nil
}

func (r *FabricMainChannelReconciler) createAndJoinChannel(ctx context.Context, fabricMainChannel *hlfv1alpha1.FabricMainChannel, clientSet *kubernetes.Clientset, hlfClientSet *operatorv1.Clientset, resClient *resmgmt.Client, endpoints []string, options []resmgmt.RequestOption) error {
	reqLogger := r.Log.WithValues("channel", fabricMainChannel.Spec.Name)

	// Create new channel
	blockBytes, err := r.createNewChannel(fabricMainChannel)
	if err != nil {
		return errors.Wrap(err, "failed to create new channel")
	}

	reqLogger.Info("Successfully created channel genesis block",
		"channel", fabricMainChannel.Spec.Name,
		"blockSize", len(blockBytes),
	)

	// Join orderers to the channel
	if err := r.joinOrderers(ctx, fabricMainChannel, clientSet, hlfClientSet, blockBytes); err != nil {
		return errors.Wrap(err, "failed to join orderers to channel")
	}

	// Wait for orderers to stabilize
	reqLogger.Info("Waiting for orderers to stabilize after channel creation")
	time.Sleep(5 * time.Second)

	// Verify channel was created successfully
	_, err = r.queryConfigBlockFromOrdererWithRoundRobin(resClient, fabricMainChannel.Spec.Name, endpoints, options)
	if err != nil {
		return errors.Wrap(err, "failed to verify channel creation")
	}

	reqLogger.Info("Successfully created and joined channel",
		"channel", fabricMainChannel.Spec.Name,
	)
	return nil
}

func (r *FabricMainChannelReconciler) getClientSets() (*kubernetes.Clientset, *operatorv1.Clientset, error) {
	clientSet, err := utils.GetClientKubeWithConf(r.Config)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to create kubernetes client")
	}

	hlfClientSet, err := operatorv1.NewForConfig(r.Config)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to create HLF client")
	}

	return clientSet, hlfClientSet, nil
}

func (r *FabricMainChannelReconciler) setupSDK(fabricMainChannel *hlfv1alpha1.FabricMainChannel, clientSet *kubernetes.Clientset, hlfClientSet *operatorv1.Clientset) (*fabsdk.FabricSDK, error) {
	reqLogger := r.Log.WithValues("channel", fabricMainChannel.Spec.Name)

	reqLogger.Info("Generating network configuration for Fabric SDK")
	ncResponse, err := nc.GenerateNetworkConfig(fabricMainChannel, clientSet, hlfClientSet, "")
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate network configuration")
	}

	reqLogger.Info("Initializing Fabric SDK with network configuration")
	configBackend := config.FromRaw([]byte(ncResponse.NetworkConfig), "yaml")
	sdk, err := fabsdk.New(configBackend)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize Fabric SDK")
	}

	reqLogger.Info("Successfully initialized Fabric SDK")
	return sdk, nil
}

func (r *FabricMainChannelReconciler) setupResClient(sdk *fabsdk.FabricSDK, fabricMainChannel *hlfv1alpha1.FabricMainChannel, clientSet *kubernetes.Clientset) (*resmgmt.Client, msp.SigningIdentity, error) {
	reqLogger := r.Log.WithValues("channel", fabricMainChannel.Spec.Name)

	if len(fabricMainChannel.Spec.AdminOrdererOrganizations) == 0 {
		return nil, nil, errors.Wrap(ErrInvalidConfig, "no admin orderer organizations configured")
	}

	firstAdminOrgMSPID := fabricMainChannel.Spec.AdminOrdererOrganizations[0].MSPID
	reqLogger.Info("Setting up resource management client",
		"adminOrgMSPID", firstAdminOrgMSPID,
	)

	// Try to find identity with -sign suffix first, then fallback to raw MSPID
	identityKey := fmt.Sprintf("%s-sign", firstAdminOrgMSPID)
	idConfig, ok := fabricMainChannel.Spec.Identities[identityKey]
	if !ok {
		identityKey = firstAdminOrgMSPID
		idConfig, ok = fabricMainChannel.Spec.Identities[firstAdminOrgMSPID]
		if !ok {
			return nil, nil, errors.Wrapf(ErrIdentityManagement,
				"identity not found for MSPID %s (tried %s-sign and %s)",
				firstAdminOrgMSPID, firstAdminOrgMSPID, firstAdminOrgMSPID)
		}
	}

	reqLogger.Info("Loading identity from secret",
		"identityKey", identityKey,
		"secretName", idConfig.SecretName,
		"secretNamespace", idConfig.SecretNamespace,
	)

	secret, err := clientSet.CoreV1().Secrets(idConfig.SecretNamespace).Get(context.Background(), idConfig.SecretName, v1.GetOptions{})
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to get identity secret %s/%s", idConfig.SecretNamespace, idConfig.SecretName)
	}

	secretData, ok := secret.Data[idConfig.SecretKey]
	if !ok {
		return nil, nil, errors.Wrapf(ErrIdentityManagement, "secret key %s not found in secret", idConfig.SecretKey)
	}

	id := &identity{}
	if err := yaml.Unmarshal(secretData, id); err != nil {
		return nil, nil, errors.Wrap(err, "failed to unmarshal identity data")
	}

	signingIdentity, err := r.createSigningIdentity(sdk, firstAdminOrgMSPID, id)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to create signing identity")
	}

	sdkContext := sdk.Context(
		fabsdk.WithIdentity(signingIdentity),
		fabsdk.WithOrg(firstAdminOrgMSPID),
	)

	resClient, err := resmgmt.New(sdkContext)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to create resource management client")
	}

	reqLogger.Info("Successfully created resource management client",
		"adminOrgMSPID", firstAdminOrgMSPID,
	)
	return resClient, signingIdentity, nil
}

func (r *FabricMainChannelReconciler) handleDeletion(reqLogger logr.Logger, fabricMainChannel *hlfv1alpha1.FabricMainChannel) error {
	if utils.Contains(fabricMainChannel.GetFinalizers(), mainChannelFinalizer) {
		if err := r.finalizeMainChannel(reqLogger, fabricMainChannel); err != nil {
			return err
		}
		controllerutil.RemoveFinalizer(fabricMainChannel, mainChannelFinalizer)
		err := r.Update(context.Background(), fabricMainChannel)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *FabricMainChannelReconciler) createSigningIdentity(sdk *fabsdk.FabricSDK, mspID string, id *identity) (msp.SigningIdentity, error) {
	sdkConfig, err := sdk.Config()
	if err != nil {
		return nil, err
	}
	cryptoConfig := cryptosuite.ConfigFromBackend(sdkConfig)
	cryptoSuite, err := sw.GetSuiteByConfig(cryptoConfig)
	if err != nil {
		return nil, err
	}
	userStore := mspimpl.NewMemoryUserStore()
	endpointConfig, err := fab.ConfigFromBackend(sdkConfig)
	if err != nil {
		return nil, err
	}
	identityManager, err := mspimpl.NewIdentityManager(mspID, userStore, cryptoSuite, endpointConfig)
	if err != nil {
		return nil, err
	}
	return identityManager.CreateSigningIdentity(
		msp.WithPrivateKey([]byte(id.Key.Pem)),
		msp.WithCert([]byte(id.Cert.Pem)),
	)
}

func (r *FabricMainChannelReconciler) getCertPool(ordererOrg hlfv1alpha1.FabricMainChannelOrdererOrganization, clientSet *kubernetes.Clientset, hlfClientSet *operatorv1.Clientset) (*x509.CertPool, error) {
	var tlsCACert string
	if ordererOrg.CAName != "" && ordererOrg.CANamespace != "" {
		certAuth, err := helpers.GetCertAuthByName(
			clientSet,
			hlfClientSet,
			ordererOrg.CAName,
			ordererOrg.CANamespace,
		)
		if err != nil {
			return nil, err
		}
		tlsCACert = certAuth.Status.TLSCACert
	} else if ordererOrg.TLSCACert != "" && ordererOrg.SignCACert != "" {
		tlsCACert = ordererOrg.TLSCACert
	}
	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM([]byte(tlsCACert))
	if !ok {
		return nil, fmt.Errorf("couldn't append certs from org %s", ordererOrg.MSPID)
	}
	return certPool, nil
}

func (r *FabricMainChannelReconciler) getTLSClientCert(ordererOrg hlfv1alpha1.FabricMainChannelOrdererOrganization, fabricMainChannel *hlfv1alpha1.FabricMainChannel, clientSet *kubernetes.Clientset) (tls.Certificate, error) {
	idConfig, ok := fabricMainChannel.Spec.Identities[fmt.Sprintf("%s-tls", ordererOrg.MSPID)]
	if !ok {
		r.Log.Info("TLS identity not found, trying with normal identity",
			"mspID", ordererOrg.MSPID,
			"attemptedKey", fmt.Sprintf("%s-tls", ordererOrg.MSPID),
		)
		idConfig, ok = fabricMainChannel.Spec.Identities[ordererOrg.MSPID]
		if !ok {
			return tls.Certificate{}, fmt.Errorf("identity not found for MSPID %s", ordererOrg.MSPID)
		}
	}
	secret, err := clientSet.CoreV1().Secrets(idConfig.SecretNamespace).Get(context.Background(), idConfig.SecretName, v1.GetOptions{})
	if err != nil {
		return tls.Certificate{}, err
	}
	id := &identity{}
	secretData, ok := secret.Data[idConfig.SecretKey]
	if !ok {
		return tls.Certificate{}, fmt.Errorf("secret key %s not found", idConfig.SecretKey)
	}
	err = yaml.Unmarshal(secretData, id)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(
		[]byte(id.Cert.Pem),
		[]byte(id.Key.Pem),
	)
}

func (r *FabricMainChannelReconciler) joinExternalOrderers(ordererOrg hlfv1alpha1.FabricMainChannelOrdererOrganization, fabricMainChannel *hlfv1alpha1.FabricMainChannel, blockBytes []byte, certPool *x509.CertPool, tlsClientCert tls.Certificate) error {
	reqLogger := r.Log.WithValues("channel", fabricMainChannel.Spec.Name, "orgMSPID", ordererOrg.MSPID)

	for _, cc := range ordererOrg.ExternalOrderersToJoin {
		osnUrl := fmt.Sprintf("https://%s:%d", cc.Host, cc.AdminPort)
		reqLogger.Info("Attempting to join external orderer to channel",
			"ordererURL", osnUrl,
			"host", cc.Host,
			"adminPort", cc.AdminPort,
		)

		// Check if orderer is already joined
		chInfoResponse, err := osnadmin.ListSingleChannel(osnUrl, fabricMainChannel.Spec.Name, certPool, tlsClientCert)
		if err != nil {
			return errors.Wrapf(ErrOrdererConnection, "failed to check channel status on orderer %s: %v", osnUrl, err)
		}
		defer chInfoResponse.Body.Close()

		if chInfoResponse.StatusCode == 200 {
			reqLogger.Info("External orderer already joined to channel",
				"ordererURL", osnUrl,
			)
			continue
		}

		// Join orderer to channel
		chResponse, err := osnadmin.Join(osnUrl, blockBytes, certPool, tlsClientCert)
		if err != nil {
			return errors.Wrapf(ErrOrdererConnection, "failed to join orderer %s to channel: %v", osnUrl, err)
		}
		defer chResponse.Body.Close()

		if chResponse.StatusCode == 405 {
			reqLogger.Info("External orderer already joined to channel (method not allowed response)",
				"ordererURL", osnUrl,
			)
			continue
		}

		responseData, err := ioutil.ReadAll(chResponse.Body)
		if err != nil {
			return errors.Wrapf(err, "failed to read response from orderer %s", osnUrl)
		}

		reqLogger.Info("External orderer join response",
			"ordererURL", osnUrl,
			"statusCode", chResponse.StatusCode,
		)

		if chResponse.StatusCode != 201 {
			return errors.Wrapf(ErrChannelOperation,
				"failed to join orderer %s to channel %s: status=%d, response=%s",
				osnUrl, fabricMainChannel.Spec.Name, chResponse.StatusCode, string(responseData))
		}

		reqLogger.Info("Successfully joined external orderer to channel",
			"ordererURL", osnUrl,
		)
	}
	return nil
}

func (r *FabricMainChannelReconciler) joinInternalOrderers(ctx context.Context, ordererOrg hlfv1alpha1.FabricMainChannelOrdererOrganization, fabricMainChannel *hlfv1alpha1.FabricMainChannel, hlfClientSet *operatorv1.Clientset, blockBytes []byte, certPool *x509.CertPool, tlsClientCert tls.Certificate, clientSet *kubernetes.Clientset) error {
	reqLogger := r.Log.WithValues("channel", fabricMainChannel.Spec.Name, "orgMSPID", ordererOrg.MSPID)

	for _, cc := range ordererOrg.OrderersToJoin {
		reqLogger.Info("Attempting to join internal orderer to channel",
			"ordererName", cc.Name,
			"ordererNamespace", cc.Namespace,
		)

		ordererNode, err := hlfClientSet.HlfV1alpha1().FabricOrdererNodes(cc.Namespace).Get(ctx, cc.Name, v1.GetOptions{})
		if err != nil {
			return errors.Wrapf(err, "failed to get orderer node %s/%s", cc.Namespace, cc.Name)
		}

		adminHost, adminPort, err := helpers.GetOrdererAdminHostAndPort(clientSet, ordererNode.Spec, ordererNode.Status)
		if err != nil {
			return errors.Wrapf(err, "failed to get admin host and port for orderer %s/%s", cc.Namespace, cc.Name)
		}

		osnUrl := fmt.Sprintf("https://%s:%d", adminHost, adminPort)
		reqLogger.Info("Joining internal orderer to channel",
			"ordererName", cc.Name,
			"ordererNamespace", cc.Namespace,
			"ordererURL", osnUrl,
		)

		chResponse, err := osnadmin.Join(osnUrl, blockBytes, certPool, tlsClientCert)
		if err != nil {
			return errors.Wrapf(ErrOrdererConnection, "failed to join orderer %s/%s to channel: %v", cc.Namespace, cc.Name, err)
		}
		defer chResponse.Body.Close()

		if chResponse.StatusCode == 405 {
			reqLogger.Info("Internal orderer already joined to channel",
				"ordererName", cc.Name,
				"ordererNamespace", cc.Namespace,
			)
			continue
		}

		responseData, err := ioutil.ReadAll(chResponse.Body)
		if err != nil {
			return errors.Wrapf(err, "failed to read response from orderer %s/%s", cc.Namespace, cc.Name)
		}

		reqLogger.Info("Internal orderer join response",
			"ordererName", cc.Name,
			"ordererNamespace", cc.Namespace,
			"statusCode", chResponse.StatusCode,
		)

		if chResponse.StatusCode != 201 {
			return errors.Wrapf(ErrChannelOperation,
				"failed to join orderer %s/%s to channel %s: status=%d, response=%s",
				cc.Namespace, cc.Name, fabricMainChannel.Spec.Name, chResponse.StatusCode, string(responseData))
		}

		reqLogger.Info("Successfully joined internal orderer to channel",
			"ordererName", cc.Name,
			"ordererNamespace", cc.Namespace,
		)
	}
	return nil
}

func (r *FabricMainChannelReconciler) queryConfigBlockFromOrdererWithRoundRobin(resClient *resmgmt.Client, channelID string, ordererEndpoints []string, resmgmtOptions []resmgmt.RequestOption) (*cb.Block, error) {
	reqLogger := r.Log.WithValues("channel", channelID)

	if len(ordererEndpoints) == 0 {
		return nil, errors.Wrap(ErrOrdererConnection, "no orderer endpoints available")
	}

	reqLogger.Info("Querying config block from orderers",
		"ordererCount", len(ordererEndpoints),
	)

	// Try each orderer in sequence until one succeeds
	var lastErr error
	for i, endpoint := range ordererEndpoints {
		// Create options for this specific orderer
		ordererOpts := []resmgmt.RequestOption{
			resmgmt.WithOrdererEndpoint(endpoint),
			resmgmt.WithRetry(retry.Opts{
				Attempts:       3,
				InitialBackoff: 1 * time.Second,
				MaxBackoff:     10 * time.Second,
			}),
		}

		// Add any other options that were passed in (except orderer endpoints)
		ordererOpts = append(ordererOpts, resmgmtOptions...)

		reqLogger.Info("Attempting to query config block from orderer",
			"endpoint", endpoint,
			"attempt", i+1,
			"totalOrderers", len(ordererEndpoints),
		)

		block, err := resClient.QueryConfigBlockFromOrderer(channelID, ordererOpts...)
		if err != nil {
			reqLogger.Info("Failed to query config block from orderer",
				"endpoint", endpoint,
				"error", err.Error(),
			)
			lastErr = err
			continue
		}

		reqLogger.Info("Successfully queried config block from orderer",
			"endpoint", endpoint,
			"blockNumber", block.Header.Number,
		)
		return block, nil
	}

	return nil, errors.Wrapf(ErrOrdererConnection,
		"failed to query config block from all %d orderers, last error: %v",
		len(ordererEndpoints), lastErr)
}

func (r *FabricMainChannelReconciler) fetchOrdererChannelBlock(resClient *resmgmt.Client, fabricMainChannel *hlfv1alpha1.FabricMainChannel) (*cb.Block, error) {
	var ordererChannelBlock *cb.Block
	var err error

	options, endpoints := r.setupResmgmtOptions(fabricMainChannel)
	ordererChannelBlock, err = r.queryConfigBlockFromOrdererWithRoundRobin(resClient, fabricMainChannel.Spec.Name, endpoints, options)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get block from channel %s", fabricMainChannel.Spec.Name)
	}
	return ordererChannelBlock, nil
}

func (r *FabricMainChannelReconciler) collectConfigSignatures(fabricMainChannel *hlfv1alpha1.FabricMainChannel, sdk *fabsdk.FabricSDK, clientSet *kubernetes.Clientset, channelConfigBytes []byte) ([]*cb.ConfigSignature, error) {
	var configSignatures []*cb.ConfigSignature

	// Collect signatures from admin orderer organizations
	for _, adminOrderer := range fabricMainChannel.Spec.AdminOrdererOrganizations {
		signature, err := r.createConfigSignature(sdk, adminOrderer.MSPID, fabricMainChannel, clientSet, channelConfigBytes)
		if err != nil {
			return nil, err
		}
		configSignatures = append(configSignatures, signature)
	}

	// Collect signatures from admin peer organizations
	for _, adminPeer := range fabricMainChannel.Spec.AdminPeerOrganizations {
		signature, err := r.createConfigSignature(sdk, adminPeer.MSPID, fabricMainChannel, clientSet, channelConfigBytes)
		if err != nil {
			return nil, err
		}
		configSignatures = append(configSignatures, signature)
	}

	return configSignatures, nil
}

func (r *FabricMainChannelReconciler) createConfigSignature(sdk *fabsdk.FabricSDK, mspID string, fabricMainChannel *hlfv1alpha1.FabricMainChannel, clientSet *kubernetes.Clientset, channelConfigBytes []byte) (*cb.ConfigSignature, error) {
	identityName := fmt.Sprintf("%s-sign", mspID)
	idConfig, ok := fabricMainChannel.Spec.Identities[identityName]
	if !ok {
		// If -sign identity is not found, try with raw MSPID
		idConfig, ok = fabricMainChannel.Spec.Identities[mspID]
		if !ok {
			return nil, fmt.Errorf("identity not found for MSPID %s or %s-sign", mspID, mspID)
		}
	}
	secret, err := clientSet.CoreV1().Secrets(idConfig.SecretNamespace).Get(context.Background(), idConfig.SecretName, v1.GetOptions{})
	if err != nil {
		return nil, err
	}
	secretData, ok := secret.Data[idConfig.SecretKey]
	if !ok {
		return nil, fmt.Errorf("secret key %s not found", idConfig.SecretKey)
	}
	id := &identity{}
	err = yaml.Unmarshal(secretData, id)
	if err != nil {
		return nil, err
	}
	signingIdentity, err := r.createSigningIdentity(sdk, mspID, id)
	if err != nil {
		return nil, err
	}

	sdkContext := sdk.Context(
		fabsdk.WithIdentity(signingIdentity),
		fabsdk.WithOrg(mspID),
	)
	resClient, err := resmgmt.New(sdkContext)
	if err != nil {
		return nil, err
	}
	return resClient.CreateConfigSignatureFromReader(signingIdentity, bytes.NewReader(channelConfigBytes))
}

func (r *FabricMainChannelReconciler) handleReconcileError(ctx context.Context, fabricMainChannel *hlfv1alpha1.FabricMainChannel, err error) (reconcile.Result, error) {
	reqLogger := r.Log.WithValues("channel", fabricMainChannel.Spec.Name)

	reqLogger.Error(err, "Reconciliation failed",
		"channel", fabricMainChannel.Spec.Name,
		"namespace", fabricMainChannel.Namespace,
	)

	r.setConditionStatus(ctx, fabricMainChannel, hlfv1alpha1.FailedStatus, false, err, false)
	return r.updateCRStatusOrFailReconcile(ctx, reqLogger, fabricMainChannel)
}

func (r *FabricMainChannelReconciler) setupResmgmtOptions(fabricMainChannel *hlfv1alpha1.FabricMainChannel) ([]resmgmt.RequestOption, []string) {
	resmgmtOptions := []resmgmt.RequestOption{
		resmgmt.WithTimeout(fab2.ResMgmt, 30*time.Second),
		resmgmt.WithRetry(retry.Opts{
			Attempts:       3,
			InitialBackoff: 1 * time.Second,
			MaxBackoff:     10 * time.Second,
		}),
	}

	var ordererEndpoints []string
	for _, ordOrg := range fabricMainChannel.Spec.OrdererOrganizations {
		ordererEndpoints = append(ordererEndpoints, ordOrg.OrdererEndpoints...)
	}

	return resmgmtOptions, ordererEndpoints
}

func (r *FabricMainChannelReconciler) fetchConfigBlock(resClient *resmgmt.Client, fabricMainChannel *hlfv1alpha1.FabricMainChannel) ([]byte, error) {
	options, endpoints := r.setupResmgmtOptions(fabricMainChannel)
	channelBlock, err := r.queryConfigBlockFromOrdererWithRoundRobin(resClient, fabricMainChannel.Spec.Name, endpoints, options)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get block from channel %s", fabricMainChannel.Spec.Name)
	}
	return proto.Marshal(channelBlock)
}

func (r *FabricMainChannelReconciler) createNewChannel(fabricMainChannel *hlfv1alpha1.FabricMainChannel) ([]byte, error) {
	reqLogger := r.Log.WithValues("channel", fabricMainChannel.Spec.Name)

	reqLogger.Info("Creating new channel configuration")
	channelConfig, err := r.mapToConfigTX(fabricMainChannel)
	if err != nil {
		return nil, errors.Wrap(err, "failed to map channel specification to configtx")
	}

	reqLogger.Info("Generating channel genesis block")
	block, err := configtx.NewApplicationChannelGenesisBlock(channelConfig, fabricMainChannel.Spec.Name)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create application channel genesis block")
	}

	blockBytes, err := proto.Marshal(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal genesis block")
	}

	reqLogger.Info("Successfully created channel genesis block",
		"blockSize", len(blockBytes),
		"blockNumber", block.Header.Number,
	)
	return blockBytes, nil
}

func (r *FabricMainChannelReconciler) joinOrderers(ctx context.Context, fabricMainChannel *hlfv1alpha1.FabricMainChannel, clientSet *kubernetes.Clientset, hlfClientSet *operatorv1.Clientset, blockBytes []byte) error {
	reqLogger := r.Log.WithValues("channel", fabricMainChannel.Spec.Name)

	reqLogger.Info("Starting orderer join process",
		"ordererOrganizations", len(fabricMainChannel.Spec.OrdererOrganizations),
	)

	for i, ordererOrg := range fabricMainChannel.Spec.OrdererOrganizations {
		reqLogger.Info("Processing orderer organization",
			"orgMSPID", ordererOrg.MSPID,
			"orgIndex", i+1,
			"totalOrgs", len(fabricMainChannel.Spec.OrdererOrganizations),
			"externalOrderers", len(ordererOrg.ExternalOrderersToJoin),
			"internalOrderers", len(ordererOrg.OrderersToJoin),
		)

		certPool, err := r.getCertPool(ordererOrg, clientSet, hlfClientSet)
		if err != nil {
			return errors.Wrapf(err, "failed to get certificate pool for orderer organization %s", ordererOrg.MSPID)
		}

		tlsClientCert, err := r.getTLSClientCert(ordererOrg, fabricMainChannel, clientSet)
		if err != nil {
			return errors.Wrapf(err, "failed to get TLS client certificate for orderer organization %s", ordererOrg.MSPID)
		}

		// Join external orderers
		if len(ordererOrg.ExternalOrderersToJoin) > 0 {
			if err := r.joinExternalOrderers(ordererOrg, fabricMainChannel, blockBytes, certPool, tlsClientCert); err != nil {
				return errors.Wrapf(err, "failed to join external orderers for organization %s", ordererOrg.MSPID)
			}
		}

		// Join internal orderers
		if len(ordererOrg.OrderersToJoin) > 0 {
			if err := r.joinInternalOrderers(ctx, ordererOrg, fabricMainChannel, hlfClientSet, blockBytes, certPool, tlsClientCert, clientSet); err != nil {
				return errors.Wrapf(err, "failed to join internal orderers for organization %s", ordererOrg.MSPID)
			}
		}

		reqLogger.Info("Successfully processed orderer organization",
			"orgMSPID", ordererOrg.MSPID,
		)
	}

	reqLogger.Info("Successfully completed orderer join process")
	return nil
}

func (r *FabricMainChannelReconciler) updateChannelConfig(ctx context.Context, fabricMainChannel *hlfv1alpha1.FabricMainChannel, resClient *resmgmt.Client, resmgmtOptions []resmgmt.RequestOption, sdk *fabsdk.FabricSDK, clientSet *kubernetes.Clientset) error {
	ordererChannelBlock, err := r.fetchOrdererChannelBlock(resClient, fabricMainChannel)
	if err != nil {
		return err
	}

	cfgBlock, err := resource.ExtractConfigFromBlock(ordererChannelBlock)
	if err != nil {
		return errors.Wrap(err, "failed to extract config from channel block")
	}

	currentConfigTx := configtx.New(cfgBlock)
	ordererConfig, err := currentConfigTx.Orderer().Configuration()
	if err != nil {
		return errors.Wrap(err, "failed to get orderer configuration")
	}
	newConfigTx, err := r.mapToConfigTX(fabricMainChannel)
	if err != nil {
		return errors.Wrap(err, "error mapping channel to configtx channel")
	}
	isMaintenanceMode := ordererConfig.State == orderer.ConsensusStateMaintenance
	switchingToMaintenanceMode := !isMaintenanceMode && newConfigTx.Orderer.State == orderer.ConsensusStateMaintenance

	if !isMaintenanceMode && !switchingToMaintenanceMode {
		if err := updateApplicationChannelConfigTx(currentConfigTx, newConfigTx); err != nil {
			return errors.Wrap(err, "failed to update application channel config")
		}
	}
	if !switchingToMaintenanceMode {
		if err := updateChannelConfigTx(currentConfigTx, newConfigTx); err != nil {
			return errors.Wrap(err, "failed to update channel config")
		}
	}

	if err := updateOrdererChannelConfigTx(currentConfigTx, newConfigTx); err != nil {
		return errors.Wrap(err, "failed to update orderer channel config")
	}

	configUpdate, err := resmgmt.CalculateConfigUpdate(fabricMainChannel.Spec.Name, cfgBlock, currentConfigTx.UpdatedConfig())
	if err != nil {
		if !strings.Contains(err.Error(), "no differences detected between original and updated config") {
			return errors.Wrap(err, "error calculating config update")
		}
		r.Log.Info("No differences detected between original and updated config")
		return nil
	}

	channelConfigBytes, err := CreateConfigUpdateEnvelope(fabricMainChannel.Spec.Name, configUpdate)
	if err != nil {
		return errors.Wrap(err, "error creating config update envelope")
	}
	// convert channelConfigBytes to json using protolator
	var buf bytes.Buffer
	err = protolator.DeepMarshalJSON(&buf, configUpdate)
	if err != nil {
		return errors.Wrap(err, "error unmarshalling channel config bytes to json")
	}
	r.Log.Info("Channel config", "config", buf.String())

	configSignatures, err := r.collectConfigSignatures(fabricMainChannel, sdk, clientSet, channelConfigBytes)
	if err != nil {
		return err
	}

	saveChannelOpts := append([]resmgmt.RequestOption{
		resmgmt.WithConfigSignatures(configSignatures...),
	}, resmgmtOptions...)

	saveChannelResponse, err := resClient.SaveChannel(
		resmgmt.SaveChannelRequest{
			ChannelID:         fabricMainChannel.Spec.Name,
			ChannelConfig:     bytes.NewReader(channelConfigBytes),
			SigningIdentities: []msp.SigningIdentity{},
		},
		saveChannelOpts...,
	)
	if err != nil {
		return errors.Wrap(err, "error saving channel configuration")
	}

	r.Log.Info("Channel configuration updated successfully",
		"transactionID", saveChannelResponse.TransactionID,
	)
	return nil
}

func (r *FabricMainChannelReconciler) saveChannelConfig(ctx context.Context, fabricMainChannel *hlfv1alpha1.FabricMainChannel, resClient *resmgmt.Client) error {
	reqLogger := r.Log.WithValues("channel", fabricMainChannel.Spec.Name)

	reqLogger.Info("Fetching current channel configuration for storage")
	ordererChannelBlock, err := r.fetchOrdererChannelBlock(resClient, fabricMainChannel)
	if err != nil {
		return errors.Wrap(err, "failed to fetch orderer channel block")
	}

	cmnConfig, err := resource.ExtractConfigFromBlock(ordererChannelBlock)
	if err != nil {
		return errors.Wrap(err, "failed to extract configuration from block")
	}

	var buf bytes.Buffer
	if err := protolator.DeepMarshalJSON(&buf, cmnConfig); err != nil {
		return errors.Wrap(err, "failed to convert configuration to JSON")
	}

	configMapName := fmt.Sprintf("%s-config", fabricMainChannel.ObjectMeta.Name)
	configMapNamespace := fabricMainChannel.Namespace
	if configMapNamespace == "" {
		configMapNamespace = "default"
	}

	reqLogger.Info("Saving channel configuration to ConfigMap",
		"configMapName", configMapName,
		"configMapNamespace", configMapNamespace,
		"configSize", buf.Len(),
	)

	if err := r.createOrUpdateConfigMap(ctx, configMapName, configMapNamespace, buf.String()); err != nil {
		return errors.Wrap(err, "failed to create or update configuration ConfigMap")
	}

	reqLogger.Info("Successfully saved channel configuration to ConfigMap",
		"configMapName", configMapName,
	)
	return nil
}

func (r *FabricMainChannelReconciler) createOrUpdateConfigMap(ctx context.Context, name, namespace, data string) error {
	reqLogger := r.Log.WithValues("configMap", name, "namespace", namespace)

	clientSet, err := utils.GetClientKubeWithConf(r.Config)
	if err != nil {
		return errors.Wrap(err, "failed to get kubernetes client")
	}

	configMap, err := clientSet.CoreV1().ConfigMaps(namespace).Get(ctx, name, v1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			reqLogger.Info("Creating new ConfigMap for channel configuration")
			_, err = clientSet.CoreV1().ConfigMaps(namespace).Create(ctx, &corev1.ConfigMap{
				ObjectMeta: v1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
				Data: map[string]string{
					"channel.json": data,
				},
			}, v1.CreateOptions{})
			if err != nil {
				return errors.Wrap(err, "failed to create ConfigMap")
			}
			reqLogger.Info("Successfully created ConfigMap")
			return nil
		}
		return errors.Wrap(err, "failed to get ConfigMap")
	}

	reqLogger.Info("Updating existing ConfigMap with new channel configuration")
	if configMap.Data == nil {
		configMap.Data = make(map[string]string)
	}
	configMap.Data["channel.json"] = data

	_, err = clientSet.CoreV1().ConfigMaps(namespace).Update(ctx, configMap, v1.UpdateOptions{})
	if err != nil {
		return errors.Wrap(err, "failed to update ConfigMap")
	}

	reqLogger.Info("Successfully updated ConfigMap")
	return nil
}

func (r *FabricMainChannelReconciler) finalizeReconcile(ctx context.Context, fabricMainChannel *hlfv1alpha1.FabricMainChannel) (reconcile.Result, error) {
	reqLogger := r.Log.WithValues("channel", fabricMainChannel.Spec.Name)

	fabricMainChannel.Status.Status = hlfv1alpha1.RunningStatus
	fabricMainChannel.Status.Message = "Channel setup completed successfully"

	fabricMainChannel.Status.Conditions.SetCondition(status.Condition{
		Type:   status.ConditionType(fabricMainChannel.Status.Status),
		Status: "True",
	})

	if err := r.Status().Update(ctx, fabricMainChannel); err != nil {
		reqLogger.Error(err, "Failed to update status to running")
		return reconcile.Result{}, errors.Wrap(err, "failed to update status")
	}

	reqLogger.Info("Successfully completed main channel reconciliation",
		"channel", fabricMainChannel.Spec.Name,
		"namespace", fabricMainChannel.Namespace,
		"status", fabricMainChannel.Status.Status,
	)

	r.setConditionStatus(ctx, fabricMainChannel, hlfv1alpha1.RunningStatus, true, nil, false)
	return r.updateCRStatusOrFailReconcile(ctx, reqLogger, fabricMainChannel)
}

func (r *FabricMainChannelReconciler) updateCRStatusOrFailReconcile(ctx context.Context, log logr.Logger, p *hlfv1alpha1.FabricMainChannel) (reconcile.Result, error) {
	if err := r.Status().Update(ctx, p); err != nil {
		log.Error(err, "Failed to update main channel status",
			"channel", p.Name,
			"namespace", p.Namespace,
		)
		return reconcile.Result{}, errors.Wrap(err, "failed to update main channel status")
	}

	if p.Status.Status == hlfv1alpha1.FailedStatus {
		log.Info("Main channel in failed status, requeuing",
			"channel", p.Name,
			"requeueAfter", "5m",
		)
		return reconcile.Result{
			RequeueAfter: 5 * time.Minute,
		}, nil
	}
	return reconcile.Result{}, nil
}

func (r *FabricMainChannelReconciler) setConditionStatus(ctx context.Context, p *hlfv1alpha1.FabricMainChannel, conditionType hlfv1alpha1.DeploymentStatus, statusFlag bool, err error, statusUnknown bool) (update bool) {
	reqLogger := r.Log.WithValues("channel", p.Name)

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
		reqLogger.Info("Updating main channel status",
			"previousStatus", p.Status.Status,
			"newStatus", conditionType,
		)

		depCopy := client.MergeFrom(p.DeepCopy())
		p.Status.Status = conditionType
		if patchErr := r.Status().Patch(ctx, p, depCopy); patchErr != nil {
			reqLogger.Error(patchErr, "Failed to patch main channel status",
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

func (r *FabricMainChannelReconciler) SetupWithManager(mgr ctrl.Manager) error {
	managedBy := ctrl.NewControllerManagedBy(mgr)
	return managedBy.
		For(&hlfv1alpha1.FabricMainChannel{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}

func (r *FabricMainChannelReconciler) mapToConfigTX(channel *hlfv1alpha1.FabricMainChannel) (configtx.Channel, error) {
	clientSet, err := utils.GetClientKubeWithConf(r.Config)
	if err != nil {
		return configtx.Channel{}, err
	}
	hlfClientSet, err := operatorv1.NewForConfig(r.Config)
	if err != nil {
		return configtx.Channel{}, err
	}
	ordererOrgs := []configtx.Organization{}
	for _, ordererOrg := range channel.Spec.OrdererOrganizations {
		var tlsCACert *x509.Certificate
		var caCert *x509.Certificate

		if ordererOrg.CAName != "" && ordererOrg.CANamespace != "" {
			certAuth, err := helpers.GetCertAuthByName(
				clientSet,
				hlfClientSet,
				ordererOrg.CAName,
				ordererOrg.CANamespace,
			)
			if err != nil {
				return configtx.Channel{}, err
			}
			tlsCACert, err = utils.ParseX509Certificate([]byte(certAuth.Status.TLSCACert))
			if err != nil {
				return configtx.Channel{}, err
			}
			caCert, err = utils.ParseX509Certificate([]byte(certAuth.Status.CACert))
			if err != nil {
				return configtx.Channel{}, err
			}
		} else if ordererOrg.TLSCACert != "" && ordererOrg.SignCACert != "" {
			tlsCACert, err = utils.ParseX509Certificate([]byte(ordererOrg.TLSCACert))
			if err != nil {
				return configtx.Channel{}, err
			}
			caCert, err = utils.ParseX509Certificate([]byte(ordererOrg.SignCACert))
			if err != nil {
				return configtx.Channel{}, err
			}
		}

		// Parse revocation list if provided
		revocationList := []*pkix.CertificateList{}
		if len(ordererOrg.RevocationList) > 0 {
			for _, revocation := range ordererOrg.RevocationList {
				crl, err := utils.ParseCRL([]byte(revocation))
				if err != nil {
					return configtx.Channel{}, errors.Wrapf(err, "failed to parse revocation list for orderer org %s", ordererOrg.MSPID)
				}
				revocationList = append(revocationList, crl)
			}
		}

		ordererOrgs = append(ordererOrgs, r.mapOrdererOrg(ordererOrg.MSPID, ordererOrg.OrdererEndpoints, caCert, tlsCACert, revocationList))
	}
	for _, ordererOrg := range channel.Spec.ExternalOrdererOrganizations {
		tlsCACert, err := utils.ParseX509Certificate([]byte(ordererOrg.TLSRootCert))
		if err != nil {
			return configtx.Channel{}, err
		}
		caCert, err := utils.ParseX509Certificate([]byte(ordererOrg.SignRootCert))
		if err != nil {
			return configtx.Channel{}, err
		}
		revocationList := []*pkix.CertificateList{}
		for _, revocation := range ordererOrg.RevocationList {
			crl, err := utils.ParseCRL([]byte(revocation))
			if err != nil {
				return configtx.Channel{}, err
			}
			revocationList = append(revocationList, crl)
		}
		ordererOrgs = append(ordererOrgs, r.mapOrdererOrg(ordererOrg.MSPID, ordererOrg.OrdererEndpoints, caCert, tlsCACert, revocationList))
	}
	etcdRaftOptions := orderer.EtcdRaftOptions{
		TickInterval:         "500ms",
		ElectionTick:         10,
		HeartbeatTick:        1,
		MaxInflightBlocks:    5,
		SnapshotIntervalSize: 16 * 1024 * 1024, // 16 MB
	}
	if channel.Spec.ChannelConfig != nil &&
		channel.Spec.ChannelConfig.Orderer != nil &&
		channel.Spec.ChannelConfig.Orderer.EtcdRaft != nil &&
		channel.Spec.ChannelConfig.Orderer.EtcdRaft.Options != nil {
		etcdRaftOptions.TickInterval = channel.Spec.ChannelConfig.Orderer.EtcdRaft.Options.TickInterval
		etcdRaftOptions.ElectionTick = channel.Spec.ChannelConfig.Orderer.EtcdRaft.Options.ElectionTick
		etcdRaftOptions.HeartbeatTick = channel.Spec.ChannelConfig.Orderer.EtcdRaft.Options.HeartbeatTick
		etcdRaftOptions.MaxInflightBlocks = channel.Spec.ChannelConfig.Orderer.EtcdRaft.Options.MaxInflightBlocks
		etcdRaftOptions.SnapshotIntervalSize = channel.Spec.ChannelConfig.Orderer.EtcdRaft.Options.SnapshotIntervalSize
	}
	if channel.Spec.ChannelConfig != nil &&
		channel.Spec.ChannelConfig.Orderer != nil &&
		channel.Spec.ChannelConfig.Orderer.OrdererType == orderer.ConsensusTypeBFT {

	}
	ordererAdminRule := "MAJORITY Admins"
	if channel.Spec.AdminOrdererOrganizations != nil {
		ordererAdminRule = "OR("
		for idx, adminOrg := range channel.Spec.AdminOrdererOrganizations {
			ordererAdminRule += "'" + adminOrg.MSPID + ".admin'"
			if idx < len(channel.Spec.AdminOrdererOrganizations)-1 {
				ordererAdminRule += ","
			}
		}
		ordererAdminRule += ")"
	}
	adminOrdererPolicies := map[string]configtx.Policy{
		"Readers": {
			Type: "ImplicitMeta",
			Rule: "ANY Readers",
		},
		"Writers": {
			Type: "ImplicitMeta",
			Rule: "ANY Writers",
		},
		"Admins": {
			Type: "Signature",
			Rule: ordererAdminRule,
		},
	}
	// if etcdraft, add BlockValidation policy
	adminOrdererPolicies["BlockValidation"] = configtx.Policy{
		Type: "ImplicitMeta",
		Rule: "ANY Writers",
	}

	var state orderer.ConsensusState
	if channel.Spec.ChannelConfig.Orderer.State == hlfv1alpha1.ConsensusStateMaintenance {
		state = orderer.ConsensusStateMaintenance
	} else {
		state = orderer.ConsensusStateNormal
	}
	ordererType := string(channel.Spec.ChannelConfig.Orderer.OrdererType)
	var etcdRaft orderer.EtcdRaft
	consenterMapping := []cb.Consenter{}
	consenters := []orderer.Consenter{}
	var smartBFTOptions *sb.Options
	if channel.Spec.ChannelConfig.Orderer.OrdererType == hlfv1alpha1.OrdererConsensusBFT {
		if len(channel.Spec.ChannelConfig.Orderer.ConsenterMapping) <= 4 {
			return configtx.Channel{}, fmt.Errorf("consenter mapping needs to be at least 4")
		}
		ordererType = string(orderer.ConsensusTypeBFT)
		for _, consenterItem := range channel.Spec.ChannelConfig.Orderer.ConsenterMapping {
			identityCert, err := utils.ParseX509Certificate([]byte(consenterItem.Identity))
			if err != nil {
				return configtx.Channel{}, err
			}
			clientTLSCert, err := utils.ParseX509Certificate([]byte(consenterItem.ClientTlsCert))
			if err != nil {
				return configtx.Channel{}, err
			}
			serverTLSCert, err := utils.ParseX509Certificate([]byte(consenterItem.ServerTlsCert))
			if err != nil {
				return configtx.Channel{}, err
			}
			consenterMapping = append(consenterMapping, cb.Consenter{
				Id:            consenterItem.Id,
				Host:          consenterItem.Host,
				Port:          consenterItem.Port,
				MspId:         consenterItem.MspId,
				Identity:      utils.EncodeX509Certificate(identityCert),
				ClientTlsCert: utils.EncodeX509Certificate(clientTLSCert),
				ServerTlsCert: utils.EncodeX509Certificate(serverTLSCert),
			})
		}

		leader_rotation := sb.Options_ROTATION_ON
		if channel.Spec.ChannelConfig.Orderer.SmartBFT.LeaderRotation == sb.Options_ROTATION_ON {
			leader_rotation = sb.Options_ROTATION_ON
		} else if channel.Spec.ChannelConfig.Orderer.SmartBFT.LeaderRotation == sb.Options_ROTATION_OFF {
			leader_rotation = sb.Options_ROTATION_OFF
		} else {
			leader_rotation = sb.Options_ROTATION_UNSPECIFIED
		}
		smartBFTOptions = &sb.Options{
			RequestBatchMaxCount:      channel.Spec.ChannelConfig.Orderer.SmartBFT.RequestBatchMaxCount,
			RequestBatchMaxBytes:      channel.Spec.ChannelConfig.Orderer.SmartBFT.RequestBatchMaxBytes,
			RequestBatchMaxInterval:   channel.Spec.ChannelConfig.Orderer.SmartBFT.RequestBatchMaxInterval,
			IncomingMessageBufferSize: channel.Spec.ChannelConfig.Orderer.SmartBFT.IncomingMessageBufferSize,
			RequestPoolSize:           channel.Spec.ChannelConfig.Orderer.SmartBFT.RequestPoolSize,
			RequestForwardTimeout:     channel.Spec.ChannelConfig.Orderer.SmartBFT.RequestForwardTimeout,
			RequestComplainTimeout:    channel.Spec.ChannelConfig.Orderer.SmartBFT.RequestComplainTimeout,
			RequestAutoRemoveTimeout:  channel.Spec.ChannelConfig.Orderer.SmartBFT.RequestAutoRemoveTimeout,
			RequestMaxBytes:           channel.Spec.ChannelConfig.Orderer.SmartBFT.RequestMaxBytes,
			ViewChangeResendInterval:  channel.Spec.ChannelConfig.Orderer.SmartBFT.ViewChangeResendInterval,
			ViewChangeTimeout:         channel.Spec.ChannelConfig.Orderer.SmartBFT.ViewChangeTimeout,
			LeaderHeartbeatTimeout:    channel.Spec.ChannelConfig.Orderer.SmartBFT.LeaderHeartbeatTimeout,
			LeaderHeartbeatCount:      channel.Spec.ChannelConfig.Orderer.SmartBFT.LeaderHeartbeatCount,
			CollectTimeout:            channel.Spec.ChannelConfig.Orderer.SmartBFT.CollectTimeout,
			SyncOnStart:               channel.Spec.ChannelConfig.Orderer.SmartBFT.SyncOnStart,
			SpeedUpViewChange:         channel.Spec.ChannelConfig.Orderer.SmartBFT.SpeedUpViewChange,
			LeaderRotation:            leader_rotation,
			DecisionsPerLeader:        channel.Spec.ChannelConfig.Orderer.SmartBFT.DecisionsPerLeader,
		}
	} else if channel.Spec.ChannelConfig.Orderer.OrdererType == hlfv1alpha1.OrdererConsensusEtcdraft {
		ordererType = string(orderer.ConsensusTypeEtcdRaft)
		for _, consenter := range channel.Spec.Consenters {
			tlsCert, err := utils.ParseX509Certificate([]byte(consenter.TLSCert))
			if err != nil {
				return configtx.Channel{}, err
			}
			channelConsenter := orderer.Consenter{
				Address: orderer.EtcdAddress{
					Host: consenter.Host,
					Port: consenter.Port,
				},
				ClientTLSCert: tlsCert,
				ServerTLSCert: tlsCert,
			}
			consenters = append(consenters, channelConsenter)
		}
		etcdRaft = orderer.EtcdRaft{
			Consenters: consenters,
			Options:    etcdRaftOptions,
		}
	} else {
		return configtx.Channel{}, fmt.Errorf("orderer type %s not supported", ordererType)
	}
	r.Log.Info("Configured orderer type", "ordererType", ordererType)
	ordConfigtx := configtx.Orderer{
		OrdererType:      ordererType,
		Organizations:    ordererOrgs,
		ConsenterMapping: consenterMapping,
		SmartBFT:         smartBFTOptions,
		EtcdRaft:         etcdRaft,
		Policies:         adminOrdererPolicies,
		Capabilities:     channel.Spec.ChannelConfig.Orderer.Capabilities,
		State:            state,
		// these are updated with the values from the channel spec later
		BatchSize: orderer.BatchSize{
			MaxMessageCount:   100,
			AbsoluteMaxBytes:  1024 * 1024,
			PreferredMaxBytes: 512 * 1024,
		},
		BatchTimeout: 2 * time.Second,
	}
	if channel.Spec.ChannelConfig != nil {
		if channel.Spec.ChannelConfig.Orderer != nil {
			if channel.Spec.ChannelConfig.Orderer.BatchTimeout != "" {
				batchTimeout, err := time.ParseDuration(channel.Spec.ChannelConfig.Orderer.BatchTimeout)
				if err != nil {
					return configtx.Channel{}, err
				}
				ordConfigtx.BatchTimeout = batchTimeout
			}
			if channel.Spec.ChannelConfig.Orderer.BatchSize != nil {
				ordConfigtx.BatchSize.MaxMessageCount = uint32(channel.Spec.ChannelConfig.Orderer.BatchSize.MaxMessageCount)
				ordConfigtx.BatchSize.AbsoluteMaxBytes = uint32(channel.Spec.ChannelConfig.Orderer.BatchSize.AbsoluteMaxBytes)
				ordConfigtx.BatchSize.PreferredMaxBytes = uint32(channel.Spec.ChannelConfig.Orderer.BatchSize.PreferredMaxBytes)
			}
		}
	}
	peerOrgs := []configtx.Organization{}
	for _, peerOrg := range channel.Spec.PeerOrganizations {
		var tlsCACert *x509.Certificate
		var caCert *x509.Certificate
		if peerOrg.TLSCACert != "" && peerOrg.SignCACert != "" {
			tlsCACert, err = utils.ParseX509Certificate([]byte(peerOrg.TLSCACert))
			if err != nil {
				return configtx.Channel{}, err
			}
			caCert, err = utils.ParseX509Certificate([]byte(peerOrg.SignCACert))
			if err != nil {
				return configtx.Channel{}, err
			}
		} else {
			certAuth, err := helpers.GetCertAuthByName(
				clientSet,
				hlfClientSet,
				peerOrg.CAName,
				peerOrg.CANamespace,
			)
			if err != nil {
				return configtx.Channel{}, err
			}
			tlsCACert, err = utils.ParseX509Certificate([]byte(certAuth.Status.TLSCACert))
			if err != nil {
				return configtx.Channel{}, err
			}
			caCert, err = utils.ParseX509Certificate([]byte(certAuth.Status.CACert))
			if err != nil {
				return configtx.Channel{}, err
			}
		}

		peerOrgs = append(peerOrgs, r.mapPeerOrg(peerOrg.MSPID, caCert, tlsCACert))
	}
	for _, peerOrg := range channel.Spec.ExternalPeerOrganizations {
		tlsCACert, err := utils.ParseX509Certificate([]byte(peerOrg.TLSRootCert))
		if err != nil {
			return configtx.Channel{}, err
		}
		caCert, err := utils.ParseX509Certificate([]byte(peerOrg.SignRootCert))
		if err != nil {
			return configtx.Channel{}, err
		}
		peerOrgs = append(peerOrgs, r.mapPeerOrg(peerOrg.MSPID, caCert, tlsCACert))
	}
	var adminAppPolicy string
	if len(channel.Spec.AdminPeerOrganizations) == 0 {
		adminAppPolicy = "MAJORITY Admins"
	} else {
		adminAppPolicy = "OR("
		for idx, adminPeerOrg := range channel.Spec.AdminPeerOrganizations {
			adminAppPolicy += "'" + adminPeerOrg.MSPID + ".admin'"
			if idx < len(channel.Spec.AdminPeerOrganizations)-1 {
				adminAppPolicy += ","
			}
		}
		adminAppPolicy += ")"
	}
	applicationPolicies := map[string]configtx.Policy{
		"Readers": {
			Type: "ImplicitMeta",
			Rule: "ANY Readers",
		},
		"Writers": {
			Type: "ImplicitMeta",
			Rule: "ANY Writers",
		},
		"Admins": {
			Type: "Signature",
			Rule: adminAppPolicy,
		},
		"Endorsement": {
			Type: "ImplicitMeta",
			Rule: "MAJORITY Endorsement",
		},
		"LifecycleEndorsement": {
			Type: "ImplicitMeta",
			Rule: "MAJORITY Endorsement",
		},
	}
	application := configtx.Application{
		Organizations: peerOrgs,
		Capabilities:  channel.Spec.ChannelConfig.Application.Capabilities,
		Policies:      applicationPolicies,
		ACLs:          defaultApplicationACLs(),
	}

	if channel.Spec.ChannelConfig.Application != nil && channel.Spec.ChannelConfig.Application.Policies != nil {
		application.Policies = r.mapPolicy(*channel.Spec.ChannelConfig.Application.Policies)
	}
	if channel.Spec.ChannelConfig.Application != nil && channel.Spec.ChannelConfig.Application.ACLs != nil {
		application.ACLs = *channel.Spec.ChannelConfig.Application.ACLs
	}
	channelConfig := configtx.Channel{
		Orderer:      ordConfigtx,
		Application:  application,
		Capabilities: channel.Spec.ChannelConfig.Capabilities,
		Policies: map[string]configtx.Policy{
			"Readers": {
				Type: "ImplicitMeta",
				Rule: "ANY Readers",
			},
			"Writers": {
				Type: "ImplicitMeta",
				Rule: "ANY Writers",
			},
			"Admins": {
				Type: "ImplicitMeta",
				Rule: "MAJORITY Admins",
			},
		},
	}
	return channelConfig, nil
}

func (r *FabricMainChannelReconciler) mapPolicy(
	policies map[string]hlfv1alpha1.FabricMainChannelPoliciesConfig,
) map[string]configtx.Policy {
	policiesMap := map[string]configtx.Policy{}
	for policyName, policyConfig := range policies {
		policiesMap[policyName] = configtx.Policy{
			Type: policyConfig.Type,
			Rule: policyConfig.Rule,
		}
	}
	return policiesMap
}

func (r *FabricMainChannelReconciler) mapOrdererOrg(mspID string, ordererEndpoints []string, caCert *x509.Certificate, tlsCACert *x509.Certificate, revocationList []*pkix.CertificateList) configtx.Organization {
	return configtx.Organization{
		Name: mspID,
		Policies: map[string]configtx.Policy{
			"Admins": {
				Type: "Signature",
				Rule: fmt.Sprintf("OR('%s.admin')", mspID),
			},
			"Readers": {
				Type: "Signature",
				Rule: fmt.Sprintf("OR('%s.member')", mspID),
			},
			"Writers": {
				Type: "Signature",
				Rule: fmt.Sprintf("OR('%s.member')", mspID),
			},
			"Endorsement": {
				Type: "Signature",
				Rule: fmt.Sprintf("OR('%s.member')", mspID),
			},
		},
		MSP: configtx.MSP{
			Name:         mspID,
			RootCerts:    []*x509.Certificate{caCert},
			TLSRootCerts: []*x509.Certificate{tlsCACert},
			NodeOUs: membership.NodeOUs{
				Enable: true,
				ClientOUIdentifier: membership.OUIdentifier{
					Certificate:                  caCert,
					OrganizationalUnitIdentifier: "client",
				},
				PeerOUIdentifier: membership.OUIdentifier{
					Certificate:                  caCert,
					OrganizationalUnitIdentifier: "peer",
				},
				AdminOUIdentifier: membership.OUIdentifier{
					Certificate:                  caCert,
					OrganizationalUnitIdentifier: "admin",
				},
				OrdererOUIdentifier: membership.OUIdentifier{
					Certificate:                  caCert,
					OrganizationalUnitIdentifier: "orderer",
				},
			},
			Admins:                        []*x509.Certificate{},
			IntermediateCerts:             []*x509.Certificate{},
			RevocationList:                revocationList,
			OrganizationalUnitIdentifiers: []membership.OUIdentifier{},
			CryptoConfig:                  membership.CryptoConfig{},
			TLSIntermediateCerts:          []*x509.Certificate{},
		},
		AnchorPeers:      []configtx.Address{},
		OrdererEndpoints: ordererEndpoints,
		ModPolicy:        "",
	}
}

func (r *FabricMainChannelReconciler) mapPeerOrg(mspID string, caCert *x509.Certificate, tlsCACert *x509.Certificate) configtx.Organization {
	return configtx.Organization{
		Name: mspID,
		Policies: map[string]configtx.Policy{
			"Admins": {
				Type: "Signature",
				Rule: fmt.Sprintf("OR('%s.admin')", mspID),
			},
			"Readers": {
				Type: "Signature",
				Rule: fmt.Sprintf("OR('%s.member')", mspID),
			},
			"Writers": {
				Type: "Signature",
				Rule: fmt.Sprintf("OR('%s.member')", mspID),
			},
			"Endorsement": {
				Type: "Signature",
				Rule: fmt.Sprintf("OR('%s.member')", mspID),
			},
		},
		MSP: configtx.MSP{
			Name:         mspID,
			RootCerts:    []*x509.Certificate{caCert},
			TLSRootCerts: []*x509.Certificate{tlsCACert},
			NodeOUs: membership.NodeOUs{
				Enable: true,
				ClientOUIdentifier: membership.OUIdentifier{
					Certificate:                  caCert,
					OrganizationalUnitIdentifier: "client",
				},
				PeerOUIdentifier: membership.OUIdentifier{
					Certificate:                  caCert,
					OrganizationalUnitIdentifier: "peer",
				},
				AdminOUIdentifier: membership.OUIdentifier{
					Certificate:                  caCert,
					OrganizationalUnitIdentifier: "admin",
				},
				OrdererOUIdentifier: membership.OUIdentifier{
					Certificate:                  caCert,
					OrganizationalUnitIdentifier: "orderer",
				},
			},
			Admins:                        []*x509.Certificate{},
			IntermediateCerts:             []*x509.Certificate{},
			RevocationList:                []*pkix.CertificateList{},
			OrganizationalUnitIdentifiers: []membership.OUIdentifier{},
			CryptoConfig:                  membership.CryptoConfig{},
			TLSIntermediateCerts:          []*x509.Certificate{},
		},
		AnchorPeers:      []configtx.Address{},
		OrdererEndpoints: []string{},
		ModPolicy:        "",
	}
}

type identity struct {
	Cert Pem `json:"cert"`
	Key  Pem `json:"key"`
}
type Pem struct {
	Pem string
}

func CreateConfigUpdateEnvelope(channelID string, configUpdate *cb.ConfigUpdate) ([]byte, error) {
	configUpdate.ChannelId = channelID
	configUpdateData, err := proto.Marshal(configUpdate)
	if err != nil {
		return nil, err
	}
	configUpdateEnvelope := &cb.ConfigUpdateEnvelope{}
	configUpdateEnvelope.ConfigUpdate = configUpdateData
	envelope, err := protoutil.CreateSignedEnvelope(cb.HeaderType_CONFIG_UPDATE, channelID, nil, configUpdateEnvelope, 0, 0)
	if err != nil {
		return nil, err
	}
	envelopeData, err := proto.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	return envelopeData, nil
}

func updateApplicationChannelConfigTx(currentConfigTX configtx.ConfigTx, newConfigTx configtx.Channel) error {
	err := currentConfigTX.Application().SetPolicies(
		newConfigTx.Application.Policies,
	)
	if err != nil {
		return errors.Wrapf(err, "failed to set application")
	}
	app, err := currentConfigTX.Application().Configuration()
	if err != nil {
		return errors.Wrapf(err, "failed to get application configuration")
	}
	// Comparing application organizations
	for _, channelPeerOrg := range app.Organizations {
		deleted := true
		for _, organization := range newConfigTx.Application.Organizations {
			if organization.Name == channelPeerOrg.Name {
				deleted = false
				break
			}
		}
		if deleted {
			// Removing organization from application
			currentConfigTX.Application().RemoveOrganization(channelPeerOrg.Name)
		}
	}
	for _, organization := range newConfigTx.Application.Organizations {
		found := false
		for _, channelPeerOrg := range app.Organizations {
			if channelPeerOrg.Name == organization.Name {
				found = true
				break
			}
		}
		if !found {
			// Adding organization to application
			err = currentConfigTX.Application().SetOrganization(organization)
			if err != nil {
				return errors.Wrapf(err, "failed to set organization %s", organization.Name)
			}
		}
	}

	err = currentConfigTX.Application().SetPolicies(
		newConfigTx.Application.Policies,
	)
	if err != nil {
		return errors.Wrap(err, "failed to set application policies")
	}
	if newConfigTx.Application.ACLs != nil {
		// compare current acls with new acls
		_, err := currentConfigTX.Application().ACLs()
		if err != nil {
			return errors.Wrapf(err, "failed to get current ACLs")
		}
		// Updating application ACLs
		// compare them to see if we have to set new ACLs

		var acls []string
		for key := range newConfigTx.Application.ACLs {
			acls = append(acls, key)
		}
		err = currentConfigTX.Application().RemoveACLs(acls)
		if err != nil {
			return errors.Wrapf(err, "failed to remove ACLs")
		}
		err = currentConfigTX.Application().SetACLs(
			newConfigTx.Application.ACLs,
		)
		if err != nil {
			return errors.Wrapf(err, "failed to set ACLs")
		}
	}

	for _, capability := range app.Capabilities {
		err = currentConfigTX.Application().RemoveCapability(capability)
		if err != nil {
			return errors.Wrapf(err, "failed to remove capability %s", capability)
		}
	}

	for _, capability := range newConfigTx.Application.Capabilities {
		err = currentConfigTX.Application().AddCapability(capability)
		if err != nil {
			return errors.Wrapf(err, "failed to add capability %s", capability)
		}
	}
	return nil
}

func updateChannelConfigTx(currentConfigTX configtx.ConfigTx, newConfigTx configtx.Channel) error {
	currentCapabilities, err := currentConfigTX.Channel().Capabilities()
	if err != nil {
		return errors.Wrapf(err, "failed to get application capabilities")
	}
	// Updating channel capabilities
	for _, capability := range currentCapabilities {
		err = currentConfigTX.Channel().RemoveCapability(capability)
		if err != nil {
			return errors.Wrapf(err, "failed to remove capability %s", capability)
		}
	}
	// Adding new channel capabilities
	for _, capability := range newConfigTx.Capabilities {
		err = currentConfigTX.Channel().AddCapability(capability)
		if err != nil {
			return errors.Wrapf(err, "failed to add capability %s", capability)
		}
	}

	return nil
}

func updateOrdererChannelConfigTx(currentConfigTX configtx.ConfigTx, newConfigTx configtx.Channel) error {
	ord, err := currentConfigTX.Orderer().Configuration()
	if err != nil {
		return errors.Wrapf(err, "failed to get application configuration")
	}
	// Updating orderer configuration

	_, err = currentConfigTX.Orderer().Configuration()
	if err != nil {
		return errors.Wrapf(err, "failed to get current orderer configuration")
	}
	// Current orderer configuration loaded
	if newConfigTx.Orderer.OrdererType == orderer.ConsensusTypeEtcdRaft {
		// Updating orderer policies for etcdraft consensus
		err := currentConfigTX.Orderer().SetPolicies(
			newConfigTx.Orderer.Policies,
		)
		if err != nil {
			return errors.Wrapf(err, "failed to set application")
		}
		for _, consenter := range ord.EtcdRaft.Consenters {
			deleted := true
			needsUpdate := false
			var matchingNewConsenter orderer.Consenter

			for _, newConsenter := range newConfigTx.Orderer.EtcdRaft.Consenters {
				if newConsenter.Address.Host == consenter.Address.Host && newConsenter.Address.Port == consenter.Address.Port {
					deleted = false
					matchingNewConsenter = newConsenter
					// Check if TLS certs are different
					if !bytes.Equal(newConsenter.ClientTLSCert.Raw, consenter.ClientTLSCert.Raw) ||
						!bytes.Equal(newConsenter.ServerTLSCert.Raw, consenter.ServerTLSCert.Raw) {
						needsUpdate = true
					}
					break
				}
			}

			if deleted {
				// Removing consenter from etcdraft configuration
				err = currentConfigTX.Orderer().RemoveConsenter(consenter)
				if err != nil {
					return errors.Wrapf(err, "failed to remove consenter %s:%d", consenter.Address.Host, consenter.Address.Port)
				}
			} else if needsUpdate {
				// Updating certificates for consenter
				err = currentConfigTX.Orderer().RemoveConsenter(consenter)
				if err != nil {
					return errors.Wrapf(err, "failed to remove consenter %s:%d for cert update", consenter.Address.Host, consenter.Address.Port)
				}
				err = currentConfigTX.Orderer().AddConsenter(matchingNewConsenter)
				if err != nil {
					return errors.Wrapf(err, "failed to add updated consenter %s:%d", consenter.Address.Host, consenter.Address.Port)
				}
			}
		}

		for _, newConsenter := range newConfigTx.Orderer.EtcdRaft.Consenters {
			found := false
			for _, consenter := range ord.EtcdRaft.Consenters {
				if newConsenter.Address.Host == consenter.Address.Host && newConsenter.Address.Port == consenter.Address.Port {
					found = true
					break
				}
			}
			if !found {
				// Adding new consenter to etcdraft configuration
				err = currentConfigTX.Orderer().AddConsenter(newConsenter)
				if err != nil {
					return errors.Wrapf(err, "failed to add consenter %s:%d", newConsenter.Address.Host, newConsenter.Address.Port)
				}
			}
		}
		err = currentConfigTX.Orderer().EtcdRaftOptions().SetElectionInterval(
			newConfigTx.Orderer.EtcdRaft.Options.ElectionTick,
		)
		if err != nil {
			return errors.Wrapf(err, "failed to set election interval")
		}
		err = currentConfigTX.Orderer().EtcdRaftOptions().SetHeartbeatTick(
			newConfigTx.Orderer.EtcdRaft.Options.HeartbeatTick,
		)
		if err != nil {
			return errors.Wrapf(err, "failed to set heartbeat tick")
		}
		err = currentConfigTX.Orderer().EtcdRaftOptions().SetTickInterval(
			newConfigTx.Orderer.EtcdRaft.Options.TickInterval,
		)
		if err != nil {
			return errors.Wrapf(err, "failed to set tick interval")
		}
		err = currentConfigTX.Orderer().EtcdRaftOptions().SetSnapshotIntervalSize(
			newConfigTx.Orderer.EtcdRaft.Options.SnapshotIntervalSize,
		)
		if err != nil {
			return errors.Wrapf(err, "failed to set snapshot interval size")
		}
		err = currentConfigTX.Orderer().EtcdRaftOptions().SetMaxInflightBlocks(
			newConfigTx.Orderer.EtcdRaft.Options.MaxInflightBlocks,
		)
		if err != nil {
			return errors.Wrapf(err, "failed to set max inflight blocks")
		}
	} else if newConfigTx.Orderer.OrdererType == orderer.ConsensusTypeBFT {
		err = currentConfigTX.Orderer().SetConfiguration(newConfigTx.Orderer)
		if err != nil {
			return errors.Wrapf(err, "failed to set orderer configuration")
		}
		var consenterMapping []*cb.Consenter
		for _, consenter := range newConfigTx.Orderer.ConsenterMapping {
			consenterMapping = append(consenterMapping, &cb.Consenter{
				Host:          consenter.Host,
				Port:          consenter.Port,
				Id:            consenter.Id,
				MspId:         consenter.MspId,
				Identity:      consenter.Identity,
				ClientTlsCert: consenter.ClientTlsCert,
				ServerTlsCert: consenter.ServerTlsCert,
			})
		}
		err = currentConfigTX.Orderer().SetConsenterMapping(consenterMapping)
		if err != nil {
			return errors.Wrapf(err, "failed to set consenter mapping")
		}
	}

	// update
	if ord.OrdererType == orderer.ConsensusTypeBFT {
		err = currentConfigTX.Orderer().SetConfiguration(newConfigTx.Orderer)
		if err != nil {
			return errors.Wrapf(err, "failed to set orderer configuration")
		}
		// Updating BFT orderer configuration
		// update policies but blockValidation
		err = currentConfigTX.Orderer().SetPolicy("Admins", newConfigTx.Orderer.Policies["Admins"])
		if err != nil {
			return errors.Wrapf(err, "failed to set policy admin for orderer")
		}
		err = currentConfigTX.Orderer().SetPolicy("Writers", newConfigTx.Orderer.Policies["Writers"])
		if err != nil {
			return errors.Wrapf(err, "failed to set policy writers for orderer")
		}
		err = currentConfigTX.Orderer().SetPolicy("Readers", newConfigTx.Orderer.Policies["Readers"])
		if err != nil {
			return errors.Wrapf(err, "failed to set policy readers for orderer")
		}

	}
	// update state
	if newConfigTx.Orderer.State != "" {
		state := orderer.ConsensusStateNormal
		switch newConfigTx.Orderer.State {
		case orderer.ConsensusStateNormal:
			state = orderer.ConsensusStateNormal
		case orderer.ConsensusStateMaintenance:
			state = orderer.ConsensusStateMaintenance
		}
		// Setting orderer consensus state
		err := currentConfigTX.Orderer().SetConsensusState(state)
		if err != nil {
			return err
		}
		// Successfully set orderer consensus state
	} else {
		// Consensus state not specified in configuration
	}
	for _, channelOrdOrg := range ord.Organizations {
		deleted := true
		for _, organization := range newConfigTx.Orderer.Organizations {
			if organization.Name == channelOrdOrg.Name {
				deleted = false
				break
			}
		}
		if deleted {
			// Removing organization from orderer configuration
			currentConfigTX.Orderer().RemoveOrganization(channelOrdOrg.Name)
		}
	}
	for _, organization := range newConfigTx.Orderer.Organizations {
		found := false
		for _, channelPeerOrg := range ord.Organizations {
			if channelPeerOrg.Name == organization.Name {
				found = true
				break
			}
		}
		if found {
			ordConfig, err := currentConfigTX.Orderer().Organization(organization.Name).Configuration()
			if err != nil {
				return errors.Wrapf(err, "failed to get orderer organization configuration")
			}
			// remove all previous endpoints
			for _, endpoint := range ordConfig.OrdererEndpoints {
				// extract host and port for endpoint
				host, portStr, err := net.SplitHostPort(endpoint)
				if err != nil {
					return errors.Wrapf(err, "failed to split host and port for endpoint %s", endpoint)
				}
				port, err := strconv.Atoi(portStr)
				if err != nil {
					return errors.Wrapf(err, "failed to convert port %s to int", portStr)
				}
				err = currentConfigTX.Orderer().Organization(organization.Name).RemoveEndpoint(
					configtx.Address{
						Host: host,
						Port: port,
					},
				)
				if err != nil {
					return errors.Wrapf(err, "failed to remove endpoint %s", endpoint)
				}
			}
			// add endpoints
			for _, endpoint := range organization.OrdererEndpoints {
				host, portStr, err := net.SplitHostPort(endpoint)
				if err != nil {
					return errors.Wrapf(err, "failed to split host and port for endpoint %s", endpoint)
				}
				port, err := strconv.Atoi(portStr)
				if err != nil {
					return errors.Wrapf(err, "failed to convert port %s to int", portStr)
				}
				err = currentConfigTX.Orderer().Organization(organization.Name).SetEndpoint(configtx.Address{
					Host: host,
					Port: port,
				})
				if err != nil {
					return errors.Wrapf(err, "failed to add endpoint %s", endpoint)
				}
			}

			ordConfig.MSP.RevocationList = organization.MSP.RevocationList
			err = currentConfigTX.Orderer().Organization(organization.Name).SetMSP(ordConfig.MSP)
			if err != nil {
				return errors.Wrapf(err, "failed to set organization %s", organization.Name)
			}
		} else {
			// Adding organization to orderer configuration
			err = currentConfigTX.Orderer().SetOrganization(organization)
			if err != nil {
				return errors.Wrapf(err, "failed to set organization %s", organization.Name)
			}

		}
	}

	err = currentConfigTX.Orderer().BatchSize().SetMaxMessageCount(
		newConfigTx.Orderer.BatchSize.MaxMessageCount,
	)
	if err != nil {
		return errors.Wrapf(err, "failed to set max message count")
	}
	err = currentConfigTX.Orderer().BatchSize().SetAbsoluteMaxBytes(
		newConfigTx.Orderer.BatchSize.AbsoluteMaxBytes,
	)
	if err != nil {
		return errors.Wrapf(err, "failed to set absolute max bytes")
	}
	err = currentConfigTX.Orderer().BatchSize().SetPreferredMaxBytes(
		newConfigTx.Orderer.BatchSize.PreferredMaxBytes,
	)
	if err != nil {
		return errors.Wrapf(err, "failed to set preferred max bytes")
	}

	err = currentConfigTX.Orderer().SetBatchTimeout(newConfigTx.Orderer.BatchTimeout)
	if err != nil {
		return errors.Wrapf(err, "failed to set batch timeout")
	}

	for _, capability := range newConfigTx.Orderer.Capabilities {
		err = currentConfigTX.Orderer().RemoveCapability(capability)
		if err != nil {
			return errors.Wrapf(err, "failed to remove capability %s", capability)
		}
	}
	for _, capability := range newConfigTx.Orderer.Capabilities {
		err = currentConfigTX.Orderer().AddCapability(capability)
		if err != nil {
			return errors.Wrapf(err, "failed to add capability %s", capability)
		}
	}
	// display configuration
	_, err = currentConfigTX.Orderer().Configuration()
	if err != nil {
		return errors.Wrapf(err, "failed to get orderer configuration")
	}
	// Orderer configuration updated successfully
	// set configuration

	return nil
}

func defaultApplicationACLs() map[string]string {
	return map[string]string{
		"_lifecycle/CheckCommitReadiness": "/Channel/Application/Writers",

		//  ACL policy for _lifecycle's "CommitChaincodeDefinition" function
		"_lifecycle/CommitChaincodeDefinition": "/Channel/Application/Writers",

		//  ACL policy for _lifecycle's "QueryChaincodeDefinition" function
		"_lifecycle/QueryChaincodeDefinition": "/Channel/Application/Writers",

		//  ACL policy for _lifecycle's "QueryChaincodeDefinitions" function
		"_lifecycle/QueryChaincodeDefinitions": "/Channel/Application/Writers",

		// ---Lifecycle System Chaincode (lscc) function to policy mapping for access control---//

		//  ACL policy for lscc's "getid" function
		"lscc/ChaincodeExists": "/Channel/Application/Readers",

		//  ACL policy for lscc's "getdepspec" function
		"lscc/GetDeploymentSpec": "/Channel/Application/Readers",

		//  ACL policy for lscc's "getccdata" function
		"lscc/GetChaincodeData": "/Channel/Application/Readers",

		//  ACL Policy for lscc's "getchaincodes" function
		"lscc/GetInstantiatedChaincodes": "/Channel/Application/Readers",

		// ---Query System Chaincode (qscc) function to policy mapping for access control---//

		//  ACL policy for qscc's "GetChainInfo" function
		"qscc/GetChainInfo": "/Channel/Application/Readers",

		//  ACL policy for qscc's "GetBlockByNumber" function
		"qscc/GetBlockByNumber": "/Channel/Application/Readers",

		//  ACL policy for qscc's  "GetBlockByHash" function
		"qscc/GetBlockByHash": "/Channel/Application/Readers",

		//  ACL policy for qscc's "GetTransactionByID" function
		"qscc/GetTransactionByID": "/Channel/Application/Readers",

		//  ACL policy for qscc's "GetBlockByTxID" function
		"qscc/GetBlockByTxID": "/Channel/Application/Readers",

		// ---Configuration System Chaincode (cscc) function to policy mapping for access control---//

		//  ACL policy for cscc's "GetConfigBlock" function
		"cscc/GetConfigBlock": "/Channel/Application/Readers",

		//  ACL policy for cscc's "GetChannelConfig" function
		"cscc/GetChannelConfig": "/Channel/Application/Readers",

		// ---Miscellaneous peer function to policy mapping for access control---//

		//  ACL policy for invoking chaincodes on peer
		"peer/Propose": "/Channel/Application/Writers",

		//  ACL policy for chaincode to chaincode invocation
		"peer/ChaincodeToChaincode": "/Channel/Application/Writers",

		// ---Events resource to policy mapping for access control// // // ---//

		//  ACL policy for sending block events
		"event/Block": "/Channel/Application/Readers",

		//  ACL policy for sending filtered block events
		"event/FilteredBlock": "/Channel/Application/Readers",
	}
}
