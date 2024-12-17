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
	"github.com/hyperledger/fabric-protos-go/common"
	cb "github.com/hyperledger/fabric-protos-go/common"
	sb "github.com/hyperledger/fabric-protos-go/orderer/smartbft"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
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
	log "github.com/sirupsen/logrus"
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

func (r *FabricMainChannelReconciler) finalizeMainChannel(reqLogger logr.Logger, m *hlfv1alpha1.FabricMainChannel) error {
	ns := m.Namespace
	if ns == "" {
		ns = "default"
	}
	reqLogger.Info("Successfully finalized mainChannel")

	return nil
}

func (r *FabricMainChannelReconciler) addFinalizer(reqLogger logr.Logger, m *hlfv1alpha1.FabricMainChannel) error {
	reqLogger.Info("Adding Finalizer for the MainChannel")
	controllerutil.AddFinalizer(m, mainChannelFinalizer)

	// Update CR
	err := r.Update(context.TODO(), m)
	if err != nil {
		reqLogger.Error(err, "Failed to update MainChannel with finalizer")
		return err
	}
	return nil
}

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricmainchannels,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricmainchannels/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricmainchannels/finalizers,verbs=get;update;patch
func (r *FabricMainChannelReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	reqLogger := r.Log.WithValues("hlf", req.NamespacedName)
	fabricMainChannel := &hlfv1alpha1.FabricMainChannel{}

	if err := r.handleInitialSetup(ctx, req, fabricMainChannel, reqLogger); err != nil {
		return r.handleReconcileError(ctx, fabricMainChannel, err)
	}

	clientSet, hlfClientSet, err := r.getClientSets()
	if err != nil {
		return r.handleReconcileError(ctx, fabricMainChannel, err)
	}

	sdk, err := r.setupSDK(fabricMainChannel, clientSet, hlfClientSet)
	if err != nil {
		return r.handleReconcileError(ctx, fabricMainChannel, err)
	}
	defer sdk.Close()

	resClient, _, err := r.setupResClient(sdk, fabricMainChannel, clientSet)
	if err != nil {
		return r.handleReconcileError(ctx, fabricMainChannel, err)
	}

	resmgmtOptions := r.setupResmgmtOptions(fabricMainChannel)

	blockBytes, err := r.fetchConfigBlock(resClient, fabricMainChannel, resmgmtOptions)
	if err != nil {
		return r.handleReconcileError(ctx, fabricMainChannel, err)
	}

	if err := r.joinOrderers(ctx, fabricMainChannel, clientSet, hlfClientSet, blockBytes); err != nil {
		return r.handleReconcileError(ctx, fabricMainChannel, err)
	}

	if err := r.updateChannelConfig(ctx, fabricMainChannel, resClient, resmgmtOptions, blockBytes, sdk, clientSet); err != nil {
		return r.handleReconcileError(ctx, fabricMainChannel, err)
	}
	time.Sleep(3 * time.Second)
	if err := r.saveChannelConfig(ctx, fabricMainChannel, resClient, resmgmtOptions); err != nil {
		return r.handleReconcileError(ctx, fabricMainChannel, err)
	}

	return r.finalizeReconcile(ctx, fabricMainChannel)
}

func (r *FabricMainChannelReconciler) handleInitialSetup(ctx context.Context, req ctrl.Request, fabricMainChannel *hlfv1alpha1.FabricMainChannel, reqLogger logr.Logger) error {
	err := r.Get(ctx, req.NamespacedName, fabricMainChannel)
	if err != nil {
		if apierrors.IsNotFound(err) {
			reqLogger.Info("MainChannel resource not found. Ignoring since object must be deleted.")
			return nil
		}
		reqLogger.Error(err, "Failed to get MainChannel.")
		return err
	}

	if fabricMainChannel.GetDeletionTimestamp() != nil {
		return r.handleDeletion(reqLogger, fabricMainChannel)
	}

	if !utils.Contains(fabricMainChannel.GetFinalizers(), mainChannelFinalizer) {
		return r.addFinalizer(reqLogger, fabricMainChannel)
	}

	return nil
}

func (r *FabricMainChannelReconciler) getClientSets() (*kubernetes.Clientset, *operatorv1.Clientset, error) {
	clientSet, err := utils.GetClientKubeWithConf(r.Config)
	if err != nil {
		return nil, nil, err
	}

	hlfClientSet, err := operatorv1.NewForConfig(r.Config)
	if err != nil {
		return nil, nil, err
	}

	return clientSet, hlfClientSet, nil
}

func (r *FabricMainChannelReconciler) setupSDK(fabricMainChannel *hlfv1alpha1.FabricMainChannel, clientSet *kubernetes.Clientset, hlfClientSet *operatorv1.Clientset) (*fabsdk.FabricSDK, error) {
	ncResponse, err := nc.GenerateNetworkConfig(fabricMainChannel, clientSet, hlfClientSet, "")
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate network config")
	}

	configBackend := config.FromRaw([]byte(ncResponse.NetworkConfig), "yaml")
	sdk, err := fabsdk.New(configBackend)
	if err != nil {
		return nil, err
	}

	return sdk, nil
}

func (r *FabricMainChannelReconciler) setupResClient(sdk *fabsdk.FabricSDK, fabricMainChannel *hlfv1alpha1.FabricMainChannel, clientSet *kubernetes.Clientset) (*resmgmt.Client, msp.SigningIdentity, error) {
	firstAdminOrgMSPID := fabricMainChannel.Spec.AdminOrdererOrganizations[0].MSPID
	idConfig, ok := fabricMainChannel.Spec.Identities[fmt.Sprintf("%s-sign", firstAdminOrgMSPID)]
	if !ok {
		// If -sign identity is not found, try with raw MSPID
		idConfig, ok = fabricMainChannel.Spec.Identities[firstAdminOrgMSPID]
		if !ok {
			return nil, nil, fmt.Errorf("identity not found for MSPID %s or %s-sign", firstAdminOrgMSPID, firstAdminOrgMSPID)
		}
	}

	secret, err := clientSet.CoreV1().Secrets(idConfig.SecretNamespace).Get(context.Background(), idConfig.SecretName, v1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}

	secretData, ok := secret.Data[idConfig.SecretKey]
	if !ok {
		return nil, nil, fmt.Errorf("secret key %s not found", idConfig.SecretKey)
	}

	id := &identity{}
	err = yaml.Unmarshal(secretData, id)
	if err != nil {
		return nil, nil, err
	}

	signingIdentity, err := r.createSigningIdentity(sdk, firstAdminOrgMSPID, id)
	if err != nil {
		return nil, nil, err
	}

	sdkContext := sdk.Context(
		fabsdk.WithIdentity(signingIdentity),
		fabsdk.WithOrg(firstAdminOrgMSPID),
	)

	resClient, err := resmgmt.New(sdkContext)
	if err != nil {
		return nil, nil, err
	}

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
		log.Infof("Identity for MSPID %s not found, trying with normal identity", fmt.Sprintf("%s-tls", ordererOrg.MSPID))
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
	for _, cc := range ordererOrg.ExternalOrderersToJoin {
		osnUrl := fmt.Sprintf("https://%s:%d", cc.Host, cc.AdminPort)
		log.Infof("Trying to join orderer %s to channel %s", osnUrl, fabricMainChannel.Spec.Name)

		chInfoResponse, err := osnadmin.ListSingleChannel(osnUrl, fabricMainChannel.Spec.Name, certPool, tlsClientCert)
		if err != nil {
			return err
		}
		defer chInfoResponse.Body.Close()
		if chInfoResponse.StatusCode == 200 {
			log.Infof("Orderer %s already joined to channel %s", osnUrl, fabricMainChannel.Spec.Name)
			continue
		}

		chResponse, err := osnadmin.Join(osnUrl, blockBytes, certPool, tlsClientCert)
		if err != nil {
			return err
		}
		defer chResponse.Body.Close()
		if chResponse.StatusCode == 405 {
			log.Infof("Orderer %s already joined to channel %s", osnUrl, fabricMainChannel.Spec.Name)
			continue
		}
		responseData, err := ioutil.ReadAll(chResponse.Body)
		if err != nil {
			return err
		}
		log.Infof("Orderer %s joined Status code=%d", osnUrl, chResponse.StatusCode)

		if chResponse.StatusCode != 201 {
			return fmt.Errorf("response from orderer %s trying to join to the channel %s: %d, response: %s", osnUrl, fabricMainChannel.Spec.Name, chResponse.StatusCode, string(responseData))
		}
	}
	return nil
}

func (r *FabricMainChannelReconciler) joinInternalOrderers(ctx context.Context, ordererOrg hlfv1alpha1.FabricMainChannelOrdererOrganization, fabricMainChannel *hlfv1alpha1.FabricMainChannel, hlfClientSet *operatorv1.Clientset, blockBytes []byte, certPool *x509.CertPool, tlsClientCert tls.Certificate, clientSet *kubernetes.Clientset) error {
	for _, cc := range ordererOrg.OrderersToJoin {
		ordererNode, err := hlfClientSet.HlfV1alpha1().FabricOrdererNodes(cc.Namespace).Get(ctx, cc.Name, v1.GetOptions{})
		if err != nil {
			return err
		}
		adminHost, adminPort, err := helpers.GetOrdererAdminHostAndPort(clientSet, ordererNode.Spec, ordererNode.Status)
		if err != nil {
			return err
		}
		osnUrl := fmt.Sprintf("https://%s:%d", adminHost, adminPort)
		log.Infof("Trying to join orderer %s to channel %s", osnUrl, fabricMainChannel.Spec.Name)
		chResponse, err := osnadmin.Join(osnUrl, blockBytes, certPool, tlsClientCert)
		if err != nil {
			return err
		}
		defer chResponse.Body.Close()
		if chResponse.StatusCode == 405 {
			log.Infof("Orderer %s already joined to channel %s", osnUrl, fabricMainChannel.Spec.Name)
			continue
		}
		responseData, err := ioutil.ReadAll(chResponse.Body)
		if err != nil {
			return err
		}
		log.Infof("Orderer %s.%s joined Status code=%d", cc.Name, cc.Namespace, chResponse.StatusCode)
		if chResponse.StatusCode != 201 {
			return fmt.Errorf("response from orderer %s trying to join to the channel %s: %d, response: %s", osnUrl, fabricMainChannel.Spec.Name, chResponse.StatusCode, string(responseData))
		}
	}
	return nil
}

func (r *FabricMainChannelReconciler) fetchOrdererChannelBlock(resClient *resmgmt.Client, fabricMainChannel *hlfv1alpha1.FabricMainChannel, resmgmtOptions []resmgmt.RequestOption) (*common.Block, error) {
	var ordererChannelBlock *common.Block
	var err error
	attemptsLeft := 5
	for {
		ordererChannelBlock, err = resClient.QueryConfigBlockFromOrderer(fabricMainChannel.Spec.Name, resmgmtOptions...)
		if err == nil || attemptsLeft == 0 {
			break
		}
		if err != nil {
			attemptsLeft--
		}
		log.Infof("Failed to get block %v, attempts left %d", err, attemptsLeft)
		time.Sleep(1500 * time.Millisecond)
	}
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get block from channel %s", fabricMainChannel.Spec.Name)
	}
	return ordererChannelBlock, nil
}

func (r *FabricMainChannelReconciler) collectConfigSignatures(fabricMainChannel *hlfv1alpha1.FabricMainChannel, sdk *fabsdk.FabricSDK, clientSet *kubernetes.Clientset, channelConfigBytes []byte) ([]*common.ConfigSignature, error) {
	var configSignatures []*common.ConfigSignature

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

func (r *FabricMainChannelReconciler) createConfigSignature(sdk *fabsdk.FabricSDK, mspID string, fabricMainChannel *hlfv1alpha1.FabricMainChannel, clientSet *kubernetes.Clientset, channelConfigBytes []byte) (*common.ConfigSignature, error) {
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
	r.setConditionStatus(ctx, fabricMainChannel, hlfv1alpha1.FailedStatus, false, err, false)
	return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricMainChannel)
}

func (r *FabricMainChannelReconciler) setupResmgmtOptions(fabricMainChannel *hlfv1alpha1.FabricMainChannel) []resmgmt.RequestOption {
	resmgmtOptions := []resmgmt.RequestOption{
		resmgmt.WithTimeout(fab2.ResMgmt, 30*time.Second),
	}

	for _, ordOrg := range fabricMainChannel.Spec.OrdererOrganizations {
		for _, endpoint := range ordOrg.OrdererEndpoints {
			resmgmtOptions = append(resmgmtOptions, resmgmt.WithOrdererEndpoint(endpoint))
		}
	}

	return resmgmtOptions
}

func (r *FabricMainChannelReconciler) fetchConfigBlock(resClient *resmgmt.Client, fabricMainChannel *hlfv1alpha1.FabricMainChannel, resmgmtOptions []resmgmt.RequestOption) ([]byte, error) {
	var channelBlock *cb.Block
	var err error

	for i := 0; i < 5; i++ {
		channelBlock, err = resClient.QueryConfigBlockFromOrderer(fabricMainChannel.Spec.Name, resmgmtOptions...)
		if err == nil {
			break
		}
		log.Warnf("Attempt %d failed to query config block from orderer: %v retrying in 1 second", i+1, err)
		time.Sleep(1 * time.Second)
	}

	if err != nil {
		log.Infof("Channel %s does not exist, creating it: %v", fabricMainChannel.Spec.Name, err)
		return r.createNewChannel(fabricMainChannel)
	}

	log.Infof("Channel %s already exists", fabricMainChannel.Spec.Name)
	return proto.Marshal(channelBlock)
}

func (r *FabricMainChannelReconciler) createNewChannel(fabricMainChannel *hlfv1alpha1.FabricMainChannel) ([]byte, error) {
	channelConfig, err := r.mapToConfigTX(fabricMainChannel)
	if err != nil {
		return nil, err
	}

	block, err := configtx.NewApplicationChannelGenesisBlock(channelConfig, fabricMainChannel.Spec.Name)
	if err != nil {
		return nil, err
	}

	return proto.Marshal(block)
}

func (r *FabricMainChannelReconciler) joinOrderers(ctx context.Context, fabricMainChannel *hlfv1alpha1.FabricMainChannel, clientSet *kubernetes.Clientset, hlfClientSet *operatorv1.Clientset, blockBytes []byte) error {
	for _, ordererOrg := range fabricMainChannel.Spec.OrdererOrganizations {
		certPool, err := r.getCertPool(ordererOrg, clientSet, hlfClientSet)
		if err != nil {
			return err
		}

		tlsClientCert, err := r.getTLSClientCert(ordererOrg, fabricMainChannel, clientSet)
		if err != nil {
			return err
		}

		if err := r.joinExternalOrderers(ordererOrg, fabricMainChannel, blockBytes, certPool, tlsClientCert); err != nil {
			return err
		}

		if err := r.joinInternalOrderers(ctx, ordererOrg, fabricMainChannel, hlfClientSet, blockBytes, certPool, tlsClientCert, clientSet); err != nil {
			return err
		}
	}

	return nil
}

func (r *FabricMainChannelReconciler) updateChannelConfig(ctx context.Context, fabricMainChannel *hlfv1alpha1.FabricMainChannel, resClient *resmgmt.Client, resmgmtOptions []resmgmt.RequestOption, blockBytes []byte, sdk *fabsdk.FabricSDK, clientSet *kubernetes.Clientset) error {
	ordererChannelBlock, err := r.fetchOrdererChannelBlock(resClient, fabricMainChannel, resmgmtOptions)
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
		log.Infof("No differences detected between original and updated config")
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

	log.Infof("Channel configuration updated with transaction ID: %s", saveChannelResponse.TransactionID)
	return nil
}

func (r *FabricMainChannelReconciler) saveChannelConfig(ctx context.Context, fabricMainChannel *hlfv1alpha1.FabricMainChannel, resClient *resmgmt.Client, resmgmtOptions []resmgmt.RequestOption) error {
	ordererChannelBlock, err := r.fetchOrdererChannelBlock(resClient, fabricMainChannel, resmgmtOptions)
	if err != nil {
		return err
	}

	cmnConfig, err := resource.ExtractConfigFromBlock(ordererChannelBlock)
	if err != nil {
		return errors.Wrap(err, "error extracting the config from block")
	}

	var buf bytes.Buffer
	err = protolator.DeepMarshalJSON(&buf, cmnConfig)
	if err != nil {
		return errors.Wrap(err, "error converting block to JSON")
	}

	configMapName := fmt.Sprintf("%s-config", fabricMainChannel.ObjectMeta.Name)
	configMapNamespace := "default"
	r.Log.Info("Saving channel config into configmap", "configmap", configMapName)
	return r.createOrUpdateConfigMap(ctx, configMapName, configMapNamespace, buf.String())
}

func (r *FabricMainChannelReconciler) createOrUpdateConfigMap(ctx context.Context, name, namespace, data string) error {
	clientSet, err := utils.GetClientKubeWithConf(r.Config)
	if err != nil {
		return err
	}

	configMap, err := clientSet.CoreV1().ConfigMaps(namespace).Get(ctx, name, v1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			_, err = clientSet.CoreV1().ConfigMaps(namespace).Create(ctx, &corev1.ConfigMap{
				ObjectMeta: v1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
				Data: map[string]string{
					"channel.json": data,
				},
			}, v1.CreateOptions{})
			return err
		}
		return err
	}

	configMap.Data["channel.json"] = data
	_, err = clientSet.CoreV1().ConfigMaps(namespace).Update(ctx, configMap, v1.UpdateOptions{})
	return err
}

func (r *FabricMainChannelReconciler) finalizeReconcile(ctx context.Context, fabricMainChannel *hlfv1alpha1.FabricMainChannel) (reconcile.Result, error) {
	fabricMainChannel.Status.Status = hlfv1alpha1.RunningStatus
	fabricMainChannel.Status.Message = "Channel setup completed"

	fabricMainChannel.Status.Conditions.SetCondition(status.Condition{
		Type:   status.ConditionType(fabricMainChannel.Status.Status),
		Status: "True",
	})

	if err := r.Status().Update(ctx, fabricMainChannel); err != nil {
		return reconcile.Result{}, err
	}

	r.setConditionStatus(ctx, fabricMainChannel, hlfv1alpha1.RunningStatus, true, nil, false)
	return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricMainChannel)
}

var (
	ErrClientK8s = errors.New("k8sAPIClientError")
)

func (r *FabricMainChannelReconciler) updateCRStatusOrFailReconcile(ctx context.Context, log logr.Logger, p *hlfv1alpha1.FabricMainChannel) (
	reconcile.Result, error) {
	if err := r.Status().Update(ctx, p); err != nil {
		log.Error(err, fmt.Sprintf("%v failed to update the application status", ErrClientK8s))
		return reconcile.Result{}, err
	}
	if p.Status.Status == hlfv1alpha1.FailedStatus {
		return reconcile.Result{
			RequeueAfter: 5 * time.Minute,
		}, nil
	}
	return reconcile.Result{}, nil
}

func (r *FabricMainChannelReconciler) setConditionStatus(ctx context.Context, p *hlfv1alpha1.FabricMainChannel, conditionType hlfv1alpha1.DeploymentStatus, statusFlag bool, err error, statusUnknown bool) (update bool) {
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
		ordererOrgs = append(ordererOrgs, r.mapOrdererOrg(ordererOrg.MSPID, ordererOrg.OrdererEndpoints, caCert, tlsCACert))
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
		ordererOrgs = append(ordererOrgs, r.mapOrdererOrg(ordererOrg.MSPID, ordererOrg.OrdererEndpoints, caCert, tlsCACert))
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
	log.Infof("Orderer type: %s", ordererType)
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
		certAuth, err := helpers.GetCertAuthByName(
			clientSet,
			hlfClientSet,
			peerOrg.CAName,
			peerOrg.CANamespace,
		)
		if err != nil {
			return configtx.Channel{}, err
		}
		tlsCACert, err := utils.ParseX509Certificate([]byte(certAuth.Status.TLSCACert))
		if err != nil {
			return configtx.Channel{}, err
		}
		caCert, err := utils.ParseX509Certificate([]byte(certAuth.Status.CACert))
		if err != nil {
			return configtx.Channel{}, err
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
func (r *FabricMainChannelReconciler) mapOrdererOrg(mspID string, ordererEndpoints []string, caCert *x509.Certificate, tlsCACert *x509.Certificate) configtx.Organization {
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

func CreateConfigUpdateEnvelope(channelID string, configUpdate *common.ConfigUpdate) ([]byte, error) {
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
	log.Infof("Current organizations %v", app.Organizations)
	log.Infof("New organizations %v", newConfigTx.Application.Organizations)
	for _, channelPeerOrg := range app.Organizations {
		deleted := true
		for _, organization := range newConfigTx.Application.Organizations {
			if organization.Name == channelPeerOrg.Name {
				deleted = false
				break
			}
		}
		if deleted {
			log.Infof("Removing organization %s", channelPeerOrg.Name)
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
			log.Infof("Adding organization %s", organization.Name)
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
		currentACLs, err := currentConfigTX.Application().ACLs()
		if err != nil {
			return errors.Wrapf(err, "failed to get current ACLs")
		}
		log.Infof("Current ACLs: %v", currentACLs)
		log.Infof("New ACLs: %v", newConfigTx.Application.ACLs)
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
	log.Infof("Current capabilities: %v", currentCapabilities)
	for _, capability := range currentCapabilities {
		err = currentConfigTX.Channel().RemoveCapability(capability)
		if err != nil {
			return errors.Wrapf(err, "failed to remove capability %s", capability)
		}
	}
	log.Infof("New capabilities: %v", newConfigTx.Capabilities)
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
	log.Infof("New config tx: %v", newConfigTx.Orderer)

	currentConfig, err := currentConfigTX.Orderer().Configuration()
	if err != nil {
		return errors.Wrapf(err, "failed to get current orderer configuration")
	}
	log.Infof("Current config before all updates: %v", currentConfig)
	if newConfigTx.Orderer.OrdererType == orderer.ConsensusTypeEtcdRaft {
		log.Infof("updateOrdererChannelConfigTx: Updating policies for etcdraft")
		err := currentConfigTX.Orderer().SetPolicies(
			newConfigTx.Orderer.Policies,
		)
		if err != nil {
			return errors.Wrapf(err, "failed to set application")
		}
		for _, consenter := range ord.EtcdRaft.Consenters {
			deleted := true
			for _, newConsenter := range newConfigTx.Orderer.EtcdRaft.Consenters {
				if newConsenter.Address.Host == consenter.Address.Host && newConsenter.Address.Port == consenter.Address.Port {
					deleted = false
					break
				}
			}
			if deleted {
				log.Infof("Removing consenter %s:%d", consenter.Address.Host, consenter.Address.Port)
				err = currentConfigTX.Orderer().RemoveConsenter(consenter)
				if err != nil {
					return errors.Wrapf(err, "failed to remove consenter %s:%d", consenter.Address.Host, consenter.Address.Port)
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
				log.Infof("Adding consenter %s:%d", newConsenter.Address.Host, newConsenter.Address.Port)
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
		log.Infof("updateOrdererChannelConfigTx: Orderer type: %s", ord.OrdererType)
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
		log.Infof("updateOrdererChannelConfigTx: Setting consensus state to %s", state)
		err := currentConfigTX.Orderer().SetConsensusState(state)
		if err != nil {
			return err
		}
		log.Infof("updateOrdererChannelConfigTx: Consensus state set to %s", state)
	} else {
		log.Infof("updateOrdererChannelConfigTx: Consensus state is not set")
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
			log.Infof("Removing organization %s", channelOrdOrg.Name)
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
		} else {
			log.Infof("Adding organization %s", organization.Name)
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
	ordererConfig, err := currentConfigTX.Orderer().Configuration()
	if err != nil {
		return errors.Wrapf(err, "failed to get orderer configuration")
	}
	log.Infof("updateOrdererChannelConfigTx: Orderer configuration: %v", ordererConfig)
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
