package tests

import (
	"github.com/kfsoftware/hlf-operator/controllers/ca"
	"github.com/kfsoftware/hlf-operator/controllers/ordnode"
	"github.com/kfsoftware/hlf-operator/controllers/ordservice"
	"github.com/kfsoftware/hlf-operator/controllers/peer"
	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"testing"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	k8sconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"context"
	"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"path/filepath"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	// +kubebuilder:scaffold:imports
)

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Controller Suite")
}

var cfg *rest.Config
var K8sClient client.Client
var ClientSet *kubernetes.Clientset
var testEnv *envtest.Environment
var kubeInt kubernetes.Interface
var dynamicClient dynamic.Interface
var k8sManager ctrl.Manager
var RestConfig *rest.Config
var _ = BeforeSuite(func(done Done) {
	logf.SetLogger(zap.New(zap.UseDevMode(true), zap.WriteTo(GinkgoWriter)))

	By("bootstrapping test environment")
	useExistingCluster := true
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:  []string{filepath.Join("..", "config", "crd", "bases")},
		UseExistingCluster: &useExistingCluster,
	}

	var err error
	cfg, err = testEnv.Start()
	Expect(err).ToNot(HaveOccurred())
	Expect(cfg).ToNot(BeNil())

	err = hlfv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	// +kubebuilder:scaffold:scheme

	k8sManager, err = ctrl.NewManager(
		cfg,
		ctrl.Options{
			Scheme: scheme.Scheme,
			Metrics: metricsserver.Options{
				BindAddress: "0", // disable metrics server in tests
			},
		},
	)
	Expect(err).ToNot(HaveOccurred())
	RestConfig = k8sManager.GetConfig()
	ClientSet, err = kubernetes.NewForConfig(RestConfig)
	Expect(err).NotTo(HaveOccurred())
	caChartPath, err := filepath.Abs("../../charts/hlf-ca")
	Expect(err).ToNot(HaveOccurred())

	caReconciler := &ca.FabricCAReconciler{
		Client:    k8sManager.GetClient(),
		Log:       ctrl.Log.WithName("controllers").WithName("FabricCA"),
		Scheme:    nil,
		Config:    RestConfig,
		ClientSet: ClientSet,
		ChartPath: caChartPath,
	}
	err = caReconciler.SetupWithManager(k8sManager, 10)
	Expect(err).ToNot(HaveOccurred())
	peerChartPath, err := filepath.Abs("../../charts/hlf-peer")
	Expect(err).ToNot(HaveOccurred())
	peerReconciler := &peer.FabricPeerReconciler{
		Client:    k8sManager.GetClient(),
		Log:       ctrl.Log.WithName("controllers").WithName("FabricPeer"),
		Scheme:    nil,
		Config:    RestConfig,
		ChartPath: peerChartPath,
	}
	err = peerReconciler.SetupWithManager(k8sManager, 10)

	Expect(err).ToNot(HaveOccurred())
	ordChartPath, err := filepath.Abs("../../charts/hlf-ord")
	Expect(err).ToNot(HaveOccurred())
	ordReconciler := ordservice.FabricOrderingServiceReconciler{
		Client:    k8sManager.GetClient(),
		Log:       ctrl.Log.WithName("controllers").WithName("FabricOrderingService"),
		Scheme:    nil,
		ChartPath: ordChartPath,
		Config:    RestConfig,
	}
	err = ordReconciler.SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	ordNodeChartPath, err := filepath.Abs("../../charts/hlf-ordnode")
	Expect(err).ToNot(HaveOccurred())
	ordNodeReconciler := ordnode.FabricOrdererNodeReconciler{
		Client:    k8sManager.GetClient(),
		Log:       ctrl.Log.WithName("controllers").WithName("FabricOrdererNode"),
		Scheme:    nil,
		ChartPath: ordNodeChartPath,
		Config:    RestConfig,
	}
	err = ordNodeReconciler.SetupWithManager(k8sManager, 10)
	Expect(err).ToNot(HaveOccurred())

	go func() {
		defer GinkgoRecover()
		err = k8sManager.Start(ctrl.SetupSignalHandler())
		Expect(err).ToNot(HaveOccurred())
	}()
	mgrSyncCtx, mgrSyncCtxCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer mgrSyncCtxCancel()
	if synced := k8sManager.GetCache().WaitForCacheSync(mgrSyncCtx); !synced {
		fmt.Println("Failed to sync")
	}
	K8sClient = k8sManager.GetClient()
	Expect(K8sClient).ToNot(BeNil())

	restConfig := k8sconfig.GetConfigOrDie()
	Expect(restConfig).ToNot(BeNil())

	kubeInt = kubernetes.NewForConfigOrDie(restConfig)
	Expect(kubeInt).ToNot(BeNil())

	dynamicClient = dynamic.NewForConfigOrDie(restConfig)
	Expect(dynamicClient).ToNot(BeNil())

	close(done)
}, 60)

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).ToNot(HaveOccurred())
})
