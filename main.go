/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"flag"
	"os"
	"path/filepath"
	"time"

	"github.com/amplitude/analytics-go/amplitude"
	"github.com/kfsoftware/hlf-operator/controllers/chaincode"
	"github.com/kfsoftware/hlf-operator/controllers/console"
	"github.com/kfsoftware/hlf-operator/controllers/followerchannel"
	"github.com/kfsoftware/hlf-operator/controllers/hlfmetrics"
	"github.com/kfsoftware/hlf-operator/controllers/identity"
	"github.com/kfsoftware/hlf-operator/controllers/mainchannel"
	"github.com/kfsoftware/hlf-operator/controllers/networkconfig"
	"github.com/kfsoftware/hlf-operator/controllers/operatorapi"
	"github.com/kfsoftware/hlf-operator/controllers/operatorui"
	"github.com/kfsoftware/hlf-operator/controllers/ordnode"
	"github.com/kfsoftware/hlf-operator/controllers/utils"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/kfsoftware/hlf-operator/controllers/ca"
	"github.com/kfsoftware/hlf-operator/controllers/ordservice"
	"github.com/kfsoftware/hlf-operator/controllers/peer"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/api/hlf.kungfusoftware.es/v1alpha1"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(hlfv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var autoRenewCertificatesPeerEnabled bool
	var autoRenewCertificatesOrdererEnabled bool
	var autoRenewCertificatesIdentityEnabled bool
	var autoRenewOrdererCertificatesDelta time.Duration
	var autoRenewPeerCertificatesDelta time.Duration
	var autoRenewIdentityCertificatesDelta time.Duration
	flag.StringVar(&metricsAddr, "metrics-addr", ":8090", "The address the metric endpoint binds to.")
	flag.DurationVar(&autoRenewOrdererCertificatesDelta, "auto-renew-orderer-certificates-delta", 15*24*time.Hour, "The delta to renew orderer certificates before expiration. Default is 15 days.")
	flag.DurationVar(&autoRenewPeerCertificatesDelta, "auto-renew-peer-certificates-delta", 15*24*time.Hour, "The delta to renew peer certificates before expiration. Default is 15 days.")
	flag.DurationVar(&autoRenewIdentityCertificatesDelta, "auto-renew-identity-certificates-delta", 15*24*time.Hour, "The delta to renew FabricIdentity certificates before expiration. Default is 15 days.")
	flag.BoolVar(&autoRenewCertificatesPeerEnabled, "auto-renew-peer-certificates", false, "Enable auto renew certificates for orderer and peer nodes. Default is false.")
	flag.BoolVar(&autoRenewCertificatesOrdererEnabled, "auto-renew-orderer-certificates", false, "Enable auto renew certificates for orderer and peer nodes. Default is false.")
	flag.BoolVar(&autoRenewCertificatesIdentityEnabled, "auto-renew-identity-certificates", true, "Enable auto renew certificates for FabricIdentity. Default is true.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.Parse()

	log.Infof("Auto renew peer certificates enabled: %t", autoRenewCertificatesPeerEnabled)
	log.Infof("Auto renew orderer certificates enabled: %t", autoRenewCertificatesOrdererEnabled)
	log.Infof("Auto renew peer certificates delta: %s", autoRenewPeerCertificatesDelta)
	log.Infof("Auto renew orderer certificates delta: %s", autoRenewOrdererCertificatesDelta)
	// Pass a Config struct
	// to initialize a Client struct
	// which implements Client interface
	analytics := amplitude.NewClient(
		amplitude.NewConfig("569cfca546698061cf130f97745afca6"),
	)
	// Track events in your application
	analytics.Track(amplitude.Event{
		UserID:          "user-id",
		EventType:       "Start operator",
		EventProperties: map[string]interface{}{"source": "notification"},
	})

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))
	kubeContext, exists := os.LookupEnv("KUBECONTEXT")
	var restConfig *rest.Config
	var err error
	if exists {
		restConfig, err = config.GetConfigWithContext(kubeContext)
		if err != nil {
			log.Fatalf("Failed to get context %s", kubeContext)
		}
	} else {
		restConfig = ctrl.GetConfigOrDie()
	}
	// Register custom metrics with the global prometheus registry
	metrics.Registry.MustRegister(hlfmetrics.CertificateExpiryTimeSeconds)
	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
		Port:               9443,
		LeaderElection:     enableLeaderElection,
		LeaderElectionID:   "a1f969eb.kungfusoftware.es",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}
	peerChartPath, err := filepath.Abs("./charts/hlf-peer")
	if err != nil {
		setupLog.Error(err, "unable to find the peer chart")
		os.Exit(1)
	}
	if err = (&peer.FabricPeerReconciler{
		Client:                     mgr.GetClient(),
		Log:                        ctrl.Log.WithName("controllers").WithName("FabricPeer"),
		Scheme:                     mgr.GetScheme(),
		Config:                     mgr.GetConfig(),
		ChartPath:                  peerChartPath,
		AutoRenewCertificates:      autoRenewCertificatesPeerEnabled,
		AutoRenewCertificatesDelta: autoRenewPeerCertificatesDelta,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "FabricPeer")
		os.Exit(1)
	}
	caChartPath, err := filepath.Abs("./charts/hlf-ca")
	if err != nil {
		setupLog.Error(err, "unable to find the ca chart")
		os.Exit(1)
	}
	clientSet, err := utils.GetClientKubeWithConf(mgr.GetConfig())
	if err != nil {
		setupLog.Error(err, "unable to create client set", "controller", "FabricPeer")
		os.Exit(1)
	}
	if err = (&ca.FabricCAReconciler{
		Client:    mgr.GetClient(),
		Log:       ctrl.Log.WithName("controllers").WithName("FabricCA"),
		Scheme:    mgr.GetScheme(),
		Config:    mgr.GetConfig(),
		ClientSet: clientSet,
		ChartPath: caChartPath,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "FabricCA")
		os.Exit(1)
	}
	ordServiceChartPath, err := filepath.Abs("./charts/hlf-ord")
	if err != nil {
		setupLog.Error(err, "unable to find the orderer chart")
		os.Exit(1)
	}
	if err = (&ordservice.FabricOrderingServiceReconciler{
		Client:    mgr.GetClient(),
		Log:       ctrl.Log.WithName("controllers").WithName("FabricOrderingService"),
		Scheme:    mgr.GetScheme(),
		Config:    mgr.GetConfig(),
		ChartPath: ordServiceChartPath,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "FabricOrderingService")
		os.Exit(1)
	}

	ordNodeChartPath, err := filepath.Abs("./charts/hlf-ordnode")
	if err != nil {
		setupLog.Error(err, "unable to find the orderer node chart")
		os.Exit(1)
	}
	if err = (&ordnode.FabricOrdererNodeReconciler{
		Client:                     mgr.GetClient(),
		Log:                        ctrl.Log.WithName("controllers").WithName("FabricOrdererNode"),
		Scheme:                     mgr.GetScheme(),
		Config:                     mgr.GetConfig(),
		ChartPath:                  ordNodeChartPath,
		AutoRenewCertificates:      autoRenewCertificatesOrdererEnabled,
		AutoRenewCertificatesDelta: autoRenewOrdererCertificatesDelta,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "FabricOrdererNode")
		os.Exit(1)
	}

	fabricConsoleChartPath, err := filepath.Abs("./charts/fabric-operations-console")
	if err != nil {
		setupLog.Error(err, "unable to find the fabric-operations-console chart")
		os.Exit(1)
	}
	if err = (&console.FabricOperationsConsoleReconciler{
		Client:    mgr.GetClient(),
		Log:       ctrl.Log.WithName("controllers").WithName("FabricOperationsConsole"),
		Scheme:    mgr.GetScheme(),
		Config:    mgr.GetConfig(),
		ChartPath: fabricConsoleChartPath,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "FabricOperationsConsole")
		os.Exit(1)
	}

	fabricOperatorAPIChartPath, err := filepath.Abs("./charts/hlf-operator-api")
	if err != nil {
		setupLog.Error(err, "unable to find the fabric-operations-api chart")
		os.Exit(1)
	}
	if err = (&operatorapi.FabricOperatorAPIReconciler{
		Client:    mgr.GetClient(),
		Log:       ctrl.Log.WithName("controllers").WithName("FabricOperatorAPI"),
		Scheme:    mgr.GetScheme(),
		Config:    mgr.GetConfig(),
		ChartPath: fabricOperatorAPIChartPath,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "FabricOperatorAPI")
		os.Exit(1)
	}

	fabricOperatorUIChartPath, err := filepath.Abs("./charts/hlf-operator-ui")
	if err != nil {
		setupLog.Error(err, "unable to find the fabric-operations-ui chart")
		os.Exit(1)
	}
	if err = (&operatorui.FabricOperatorUIReconciler{
		Client:    mgr.GetClient(),
		Log:       ctrl.Log.WithName("controllers").WithName("FabricOperatorUI"),
		Scheme:    mgr.GetScheme(),
		Config:    mgr.GetConfig(),
		ChartPath: fabricOperatorUIChartPath,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "FabricOperatorUI")
		os.Exit(1)
	}

	if err = (&networkconfig.FabricNetworkConfigReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("FabricNetworkConfig"),
		Scheme: mgr.GetScheme(),
		Config: mgr.GetConfig(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "FabricNetworkConfig")
		os.Exit(1)
	}

	if err = (&mainchannel.FabricMainChannelReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("FabricMainChannel"),
		Scheme: mgr.GetScheme(),
		Config: mgr.GetConfig(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "FabricMainChannel")
		os.Exit(1)
	}

	if err = (&identity.FabricIdentityReconciler{
		Client:                     mgr.GetClient(),
		Log:                        ctrl.Log.WithName("controllers").WithName("FabricIdentity"),
		Scheme:                     mgr.GetScheme(),
		Config:                     mgr.GetConfig(),
		AutoRenewCertificates:      autoRenewCertificatesIdentityEnabled,
		AutoRenewCertificatesDelta: autoRenewIdentityCertificatesDelta,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "FabricIdentity")
		os.Exit(1)
	}

	if err = (&followerchannel.FabricFollowerChannelReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("FabricFollowerChannel"),
		Scheme: mgr.GetScheme(),
		Config: mgr.GetConfig(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "FabricFollowerChannel")
		os.Exit(1)
	}

	if err = (&chaincode.FabricChaincodeReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("FabricChaincode"),
		Scheme: mgr.GetScheme(),
		Config: mgr.GetConfig(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "FabricNetworkConfig")
		os.Exit(1)
	}

	// +kubebuilder:scaffold:builder
	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
