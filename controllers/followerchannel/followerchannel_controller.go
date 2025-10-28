package followerchannel

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-config/configtx"
	"github.com/hyperledger/fabric-config/configtx/orderer"
	"github.com/hyperledger/fabric-config/protolator"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
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
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// FabricFollowerChannelReconciler reconciles a FabricFollowerChannel object
type FabricFollowerChannelReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
	Config *rest.Config
}

const followerChannelFinalizer = "finalizer.followerChannel.hlf.kungfusoftware.es"

var (
	ErrInvalidConfig      = errors.New("invalidConfigurationError")
	ErrChannelOperation   = errors.New("channelOperationError")
	ErrIdentityManagement = errors.New("identityManagementError")
)

func (r *FabricFollowerChannelReconciler) finalizeFollowerChannel(reqLogger logr.Logger, m *hlfv1alpha1.FabricFollowerChannel) error {
	ns := m.Namespace
	if ns == "" {
		ns = "default"
	}

	reqLogger.Info("Finalizing follower channel",
		"channel", m.Name,
		"namespace", ns,
		"mspID", m.Spec.MSPID,
	)

	// Perform any cleanup operations here if needed

	reqLogger.Info("Successfully finalized follower channel",
		"channel", m.Name,
		"namespace", ns,
	)
	return nil
}

func (r *FabricFollowerChannelReconciler) addFinalizer(reqLogger logr.Logger, m *hlfv1alpha1.FabricFollowerChannel) error {
	reqLogger.Info("Adding finalizer for follower channel",
		"channel", m.Name,
		"namespace", m.Namespace,
		"finalizer", followerChannelFinalizer,
	)

	controllerutil.AddFinalizer(m, followerChannelFinalizer)

	if err := r.Update(context.TODO(), m); err != nil {
		reqLogger.Error(err, "Failed to update follower channel with finalizer",
			"channel", m.Name,
			"namespace", m.Namespace,
		)
		return errors.Wrap(err, "failed to add finalizer to follower channel")
	}

	reqLogger.Info("Successfully added finalizer to follower channel",
		"channel", m.Name,
		"namespace", m.Namespace,
	)
	return nil
}

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricfollowerchannels,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricfollowerchannels/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricfollowerchannels/finalizers,verbs=get;update;patch
func (r *FabricFollowerChannelReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	reqLogger := r.Log.WithValues("hlf", req.NamespacedName)
	fabricFollowerChannel := &hlfv1alpha1.FabricFollowerChannel{}

	reqLogger.Info("Starting follower channel reconciliation",
		"channel", req.Name,
		"namespace", req.Namespace,
	)

	err := r.Get(ctx, req.NamespacedName, fabricFollowerChannel)
	if err != nil {
		if apierrors.IsNotFound(err) {
			reqLogger.Info("Follower channel resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		reqLogger.Error(err, "Failed to get follower channel resource",
			"channel", req.Name,
			"namespace", req.Namespace,
		)
		return ctrl.Result{}, errors.Wrap(err, "failed to get follower channel resource")
	}

	// Validate configuration
	if err := r.validateFollowerChannelConfig(fabricFollowerChannel); err != nil {
		reqLogger.Error(err, "Invalid follower channel configuration",
			"channel", fabricFollowerChannel.Name,
			"namespace", fabricFollowerChannel.Namespace,
		)
		r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, reqLogger, fabricFollowerChannel)
	}
	markedToBeDeleted := fabricFollowerChannel.GetDeletionTimestamp() != nil
	if markedToBeDeleted {
		if utils.Contains(fabricFollowerChannel.GetFinalizers(), followerChannelFinalizer) {
			if err := r.finalizeFollowerChannel(reqLogger, fabricFollowerChannel); err != nil {
				return ctrl.Result{}, err
			}
			controllerutil.RemoveFinalizer(fabricFollowerChannel, followerChannelFinalizer)
			err := r.Update(ctx, fabricFollowerChannel)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}
	if !utils.Contains(fabricFollowerChannel.GetFinalizers(), followerChannelFinalizer) {
		if err := r.addFinalizer(reqLogger, fabricFollowerChannel); err != nil {
			return ctrl.Result{}, err
		}
	}
	clientSet, err := utils.GetClientKubeWithConf(r.Config)
	if err != nil {
		reqLogger.Error(err, "Failed to get kubernetes client")
		r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false,
			errors.Wrap(err, "failed to get kubernetes client"), false)
		return r.updateCRStatusOrFailReconcile(ctx, reqLogger, fabricFollowerChannel)
	}
	hlfClientSet, err := operatorv1.NewForConfig(r.Config)
	if err != nil {
		reqLogger.Error(err, "Failed to get HLF client")
		r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false,
			errors.Wrap(err, "failed to get HLF client"), false)
		return r.updateCRStatusOrFailReconcile(ctx, reqLogger, fabricFollowerChannel)
	}

	// join peers
	mspID := fabricFollowerChannel.Spec.MSPID
	reqLogger.Info("Generating network configuration for follower channel",
		"mspID", mspID,
		"channel", fabricFollowerChannel.Spec.Name,
	)

	ncResponse, err := nc.GenerateNetworkConfigForFollower(fabricFollowerChannel, clientSet, hlfClientSet, mspID)
	if err != nil {
		reqLogger.Error(err, "Failed to generate network configuration")
		r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false,
			errors.Wrap(err, "failed to generate network configuration"), false)
		return r.updateCRStatusOrFailReconcile(ctx, reqLogger, fabricFollowerChannel)
	}

	reqLogger.Info("Successfully generated network configuration",
		"configSize", len(ncResponse.NetworkConfig),
	)
	configBackend := config.FromRaw([]byte(ncResponse.NetworkConfig), "yaml")
	sdk, err := fabsdk.New(configBackend)
	if err != nil {
		reqLogger.Error(err, "Failed to initialize Fabric SDK")
		r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false,
			errors.Wrap(err, "failed to initialize Fabric SDK"), false)
		return r.updateCRStatusOrFailReconcile(ctx, reqLogger, fabricFollowerChannel)
	}
	defer sdk.Close()
	idConfig := fabricFollowerChannel.Spec.HLFIdentity
	secret, err := clientSet.CoreV1().Secrets(idConfig.SecretNamespace).Get(ctx, idConfig.SecretName, v1.GetOptions{})
	if err != nil {
		r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
	}
	secretData, ok := secret.Data[idConfig.SecretKey]
	if !ok {
		r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, fmt.Errorf("secret key %s not found", idConfig.SecretKey), false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
	}
	id := &identity{}
	err = yaml.Unmarshal(secretData, id)
	if err != nil {
		r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
	}
	sdkConfig, err := sdk.Config()
	if err != nil {
		r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
	}
	cryptoConfig := cryptosuite.ConfigFromBackend(sdkConfig)
	cryptoSuite, err := sw.GetSuiteByConfig(cryptoConfig)
	if err != nil {
		r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
	}
	userStore := mspimpl.NewMemoryUserStore()
	endpointConfig, err := fab.ConfigFromBackend(sdkConfig)
	if err != nil {
		r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
	}
	identityManager, err := mspimpl.NewIdentityManager(mspID, userStore, cryptoSuite, endpointConfig)
	if err != nil {
		r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
	}
	signingIdentity, err := identityManager.CreateSigningIdentity(
		msp.WithPrivateKey([]byte(id.Key.Pem)),
		msp.WithCert([]byte(id.Cert.Pem)),
	)
	if err != nil {
		r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
	}
	sdkContext := sdk.Context(
		fabsdk.WithIdentity(signingIdentity),
		fabsdk.WithOrg(mspID),
	)
	resClient, err := resmgmt.New(sdkContext)
	if err != nil {
		r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
	}
	for _, peer := range fabricFollowerChannel.Spec.PeersToJoin {
		reqLogger.Info("Joining internal peer to channel",
			"peerName", peer.Name,
			"peerNamespace", peer.Namespace,
			"channel", fabricFollowerChannel.Spec.Name,
		)

		err = resClient.JoinChannel(
			fabricFollowerChannel.Spec.Name,
			resmgmt.WithTargetEndpoints(fmt.Sprintf("%s.%s", peer.Name, peer.Namespace)),
		)
		if err != nil {
			if strings.Contains(err.Error(), "already exists") {
				reqLogger.Info("Internal peer already joined to channel",
					"peerName", peer.Name,
					"peerNamespace", peer.Namespace,
				)
				continue
			}
			reqLogger.Error(err, "Failed to join internal peer to channel",
				"peerName", peer.Name,
				"peerNamespace", peer.Namespace,
			)
			r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false,
				errors.Wrapf(err, "failed to join peer %s/%s to channel", peer.Namespace, peer.Name), false)
			return r.updateCRStatusOrFailReconcile(ctx, reqLogger, fabricFollowerChannel)
		}

		reqLogger.Info("Successfully joined internal peer to channel",
			"peerName", peer.Name,
			"peerNamespace", peer.Namespace,
		)
	}
	for _, peer := range fabricFollowerChannel.Spec.ExternalPeersToJoin {
		reqLogger.Info("Joining external peer to channel",
			"peerURL", peer.URL,
			"channel", fabricFollowerChannel.Spec.Name,
		)

		err = resClient.JoinChannel(
			fabricFollowerChannel.Spec.Name,
			resmgmt.WithTargetEndpoints(peer.URL),
		)
		if err != nil {
			if strings.Contains(err.Error(), "already exists") {
				reqLogger.Info("External peer already joined to channel",
					"peerURL", peer.URL,
				)
				continue
			}
			reqLogger.Error(err, "Failed to join external peer to channel",
				"peerURL", peer.URL,
			)
			r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false,
				errors.Wrapf(err, "failed to join external peer %s to channel", peer.URL), false)
			return r.updateCRStatusOrFailReconcile(ctx, reqLogger, fabricFollowerChannel)
		}

		reqLogger.Info("Successfully joined external peer to channel",
			"peerURL", peer.URL,
		)
	}

	// set anchor peers
	block, err := resClient.QueryConfigBlockFromOrderer(fabricFollowerChannel.Spec.Name)
	if err != nil {
		r.Log.Info(fmt.Sprintf("Failed to get block %v", err))
		r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, errors.Wrapf(err, "failed to get block from channel %s", fabricFollowerChannel.Spec.Name), false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
	}
	cfgBlock, err := resource.ExtractConfigFromBlock(block)
	if err != nil {
		r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
	}

	var buf2 bytes.Buffer
	err = protolator.DeepMarshalJSON(&buf2, cfgBlock)
	if err != nil {
		r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, errors.Wrapf(err, "error converting block to JSON"), false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
	}
	reqLogger.Info("Retrieved channel configuration block",
		"configSize", buf2.Len(),
	)
	cftxGen := configtx.New(cfgBlock)
	ordererConfig, err := cftxGen.Orderer().Configuration()
	if err != nil {
		r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
	}
	if ordererConfig.State == orderer.ConsensusStateMaintenance {
		r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, errors.New("the orderer is in maintenance mode"), false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
	}
	app := cftxGen.Application().Organization(mspID)
	anchorPeers, err := app.AnchorPeers()
	if err != nil {
		r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
	}
	r.Log.Info(fmt.Sprintf("Old anchor peers %v", anchorPeers))

	for _, anchorPeer := range anchorPeers {
		reqLogger.Info(fmt.Sprintf("Removing anchor peer %v", anchorPeer))
		err = app.RemoveAnchorPeer(configtx.Address{
			Host: anchorPeer.Host,
			Port: anchorPeer.Port,
		})
		if err != nil {
			currentAnchorPeers, err := app.AnchorPeers()
			reqLogger.Error(err, fmt.Sprintf("Failed to remove anchor peer %v, current anchor peers: %v", anchorPeer, currentAnchorPeers))
			r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
		}
		reqLogger.Info(fmt.Sprintf("Removed anchor peer %v", anchorPeer))
	}
	r.Log.Info(fmt.Sprintf("New anchor peers %v", anchorPeers))
	for _, anchorPeer := range fabricFollowerChannel.Spec.AnchorPeers {
		err = app.AddAnchorPeer(configtx.Address{
			Host: anchorPeer.Host,
			Port: anchorPeer.Port,
		})
		if err != nil {
			reqLogger.Error(err, fmt.Sprintf("Failed to add anchor peer %v", anchorPeer))
			r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
		}
	}

	r.Log.Info("Setting CRL configuration")
	var revocationList []*pkix.CertificateList
	// Then add the new CRLs
	for _, revocation := range fabricFollowerChannel.Spec.RevocationList {
		crl, err := utils.ParseCRL([]byte(revocation))
		if err != nil {
			r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
		}
		revocationList = append(revocationList, crl)
	}

	org, err := cftxGen.Application().Organization(mspID).Configuration()
	if err != nil {
		r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
	}
	org.MSP.RevocationList = revocationList
	err = cftxGen.Application().SetOrganization(org)
	if err != nil {
		r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
	}

	r.Log.Info("CRL configuration set")
	r.Log.Info("Updating channel configuration")
	updatedConfig := cftxGen.UpdatedConfig()
	// convert to json and print it as log
	var buf3 bytes.Buffer
	err = protolator.DeepMarshalJSON(&buf3, updatedConfig)
	if err != nil {
		r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
	}
	r.Log.Info(fmt.Sprintf("Updated config: %s", buf2.String()))
	configUpdateBytes, err := cftxGen.ComputeMarshaledUpdate(fabricFollowerChannel.Spec.Name)
	if err != nil {
		if !strings.Contains(err.Error(), "no differences detected between original and updated config") {
			r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, errors.Wrapf(err, "error calculating config update"), false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
		}
		r.Log.Info("No differences detected between original and updated config")
	} else {
		configUpdate := &common.ConfigUpdate{}
		err = proto.Unmarshal(configUpdateBytes, configUpdate)
		if err != nil {
			r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
		}
		channelConfigBytes, err := CreateConfigUpdateEnvelope(fabricFollowerChannel.Spec.Name, configUpdate)
		if err != nil {
			r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
		}
		configUpdateReader := bytes.NewReader(channelConfigBytes)
		chResponse, err := resClient.SaveChannel(resmgmt.SaveChannelRequest{
			ChannelID:     fabricFollowerChannel.Spec.Name,
			ChannelConfig: configUpdateReader,
		})
		if err != nil {
			r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
		}
		reqLogger.Info("Successfully updated channel configuration",
			"transactionID", chResponse.TransactionID,
		)
	}

	// update config map with the configuration
	ordererChannelBlock, err := resClient.QueryConfigBlockFromOrderer(fabricFollowerChannel.Spec.Name)
	if err != nil {
		r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, errors.Wrapf(err, "error fetching block from orderer"), false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
	}
	cmnConfig, err := resource.ExtractConfigFromBlock(ordererChannelBlock)
	if err != nil {
		r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, errors.Wrapf(err, "error extracting the config from block"), false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
	}
	var buf bytes.Buffer
	err = protolator.DeepMarshalJSON(&buf, cmnConfig)
	if err != nil {
		r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, errors.Wrapf(err, "error converting block to JSON"), false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
	}
	configMapNamespace := "default"
	configMapName := fmt.Sprintf("%s-follower-config", fabricFollowerChannel.ObjectMeta.Name)
	createConfigMap := false
	configMap, err := clientSet.CoreV1().ConfigMaps(configMapNamespace).Get(ctx, configMapName, v1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			reqLogger.Info(fmt.Sprintf("ConfigMap %s not found, creating it", configMapName))
			createConfigMap = true
		} else {
			r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, errors.Wrapf(err, "error getting configmap"), false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
		}
	}
	if createConfigMap {
		_, err = clientSet.CoreV1().ConfigMaps(configMapNamespace).Create(ctx, &corev1.ConfigMap{
			TypeMeta: v1.TypeMeta{},
			ObjectMeta: v1.ObjectMeta{
				Name:      configMapName,
				Namespace: configMapNamespace,
			},
			Data: map[string]string{
				"channel.json": buf.String(),
			},
		}, v1.CreateOptions{})
		if err != nil {
			r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, errors.Wrapf(err, "error creating config map"), false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
		}
	} else {
		configMap.Data["channel.json"] = buf.String()
		_, err = clientSet.CoreV1().ConfigMaps(configMapNamespace).Update(ctx, configMap, v1.UpdateOptions{})
		if err != nil {
			r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false, errors.Wrapf(err, "error updating config map"), false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricFollowerChannel)
		}
	}

	fabricFollowerChannel.Status.Status = hlfv1alpha1.RunningStatus
	fabricFollowerChannel.Status.Message = "Peers and anchor peers setup completed successfully"
	fabricFollowerChannel.Status.Conditions.SetCondition(status.Condition{
		Type:   status.ConditionType(fabricFollowerChannel.Status.Status),
		Status: "True",
	})

	if err := r.Status().Update(ctx, fabricFollowerChannel); err != nil {
		reqLogger.Error(err, "Failed to update status to running")
		r.setConditionStatus(ctx, fabricFollowerChannel, hlfv1alpha1.FailedStatus, false,
			errors.Wrap(err, "failed to update status"), false)
		return r.updateCRStatusOrFailReconcile(ctx, reqLogger, fabricFollowerChannel)
	}

	reqLogger.Info("Successfully completed follower channel reconciliation",
		"channel", fabricFollowerChannel.Spec.Name,
		"namespace", fabricFollowerChannel.Namespace,
		"mspID", fabricFollowerChannel.Spec.MSPID,
		"status", fabricFollowerChannel.Status.Status,
	)
	return r.updateCRStatusOrFailReconcile(ctx, reqLogger, fabricFollowerChannel)
}

func (r *FabricFollowerChannelReconciler) validateFollowerChannelConfig(channel *hlfv1alpha1.FabricFollowerChannel) error {
	if channel.Spec.Name == "" {
		return errors.Wrap(ErrInvalidConfig, "channel name cannot be empty")
	}

	if channel.Spec.MSPID == "" {
		return errors.Wrap(ErrInvalidConfig, "MSPID cannot be empty")
	}

	if channel.Spec.HLFIdentity.SecretName == "" {
		return errors.Wrap(ErrInvalidConfig, "HLF identity secret name cannot be empty")
	}

	if channel.Spec.HLFIdentity.SecretKey == "" {
		return errors.Wrap(ErrInvalidConfig, "HLF identity secret key cannot be empty")
	}

	if len(channel.Spec.PeersToJoin) == 0 && len(channel.Spec.ExternalPeersToJoin) == 0 {
		return errors.Wrap(ErrInvalidConfig, "at least one peer must be specified to join the channel")
	}

	return nil
}

func (r *FabricFollowerChannelReconciler) updateCRStatusOrFailReconcile(ctx context.Context, log logr.Logger, p *hlfv1alpha1.FabricFollowerChannel) (reconcile.Result, error) {
	if err := r.Status().Update(ctx, p); err != nil {
		log.Error(err, "Failed to update follower channel status",
			"channel", p.Name,
			"namespace", p.Namespace,
		)
		return reconcile.Result{}, errors.Wrap(err, "failed to update follower channel status")
	}

	if p.Status.Status == hlfv1alpha1.FailedStatus {
		log.Info("Follower channel in failed status, requeuing",
			"channel", p.Name,
			"requeueAfter", "5m",
		)
		return reconcile.Result{
			RequeueAfter: 5 * time.Minute,
		}, nil
	}

	return reconcile.Result{
		Requeue: false,
	}, nil
}

func (r *FabricFollowerChannelReconciler) setConditionStatus(ctx context.Context, p *hlfv1alpha1.FabricFollowerChannel, conditionType hlfv1alpha1.DeploymentStatus, statusFlag bool, err error, statusUnknown bool) (update bool) {
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
		reqLogger.Info("Updating follower channel status",
			"previousStatus", p.Status.Status,
			"newStatus", conditionType,
		)

		depCopy := client.MergeFrom(p.DeepCopy())
		p.Status.Status = conditionType
		if patchErr := r.Status().Patch(ctx, p, depCopy); patchErr != nil {
			reqLogger.Error(patchErr, "Failed to patch follower channel status",
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

func (r *FabricFollowerChannelReconciler) SetupWithManager(mgr ctrl.Manager) error {
	managedBy := ctrl.NewControllerManagedBy(mgr)
	return managedBy.
		For(&hlfv1alpha1.FabricFollowerChannel{}).
		Owns(&corev1.Secret{}).
		Complete(r)
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
	configUpdateEnvelope := &common.ConfigUpdateEnvelope{}
	configUpdateEnvelope.ConfigUpdate = configUpdateData
	envelope, err := protoutil.CreateSignedEnvelope(common.HeaderType_CONFIG_UPDATE, channelID, nil, configUpdateEnvelope, 0, 0)
	if err != nil {
		return nil, err
	}
	envelopeData, err := proto.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	return envelopeData, nil
}
