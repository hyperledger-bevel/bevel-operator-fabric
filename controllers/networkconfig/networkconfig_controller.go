package networkconfig

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
	"github.com/go-logr/logr"
	"github.com/kfsoftware/hlf-operator/controllers/utils"
	"github.com/kfsoftware/hlf-operator/kubectl-hlf/cmd/helpers"
	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	operatorv1 "github.com/kfsoftware/hlf-operator/pkg/client/clientset/versioned"
	"github.com/kfsoftware/hlf-operator/pkg/status"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// FabricNetworkConfigReconciler reconciles a FabricNetworkConfig object
type FabricNetworkConfigReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
	Config *rest.Config
}

const tmplGoConfig = `
name: hlf-network
version: 1.0.0
client:
  organization: "{{ .Organization }}"
{{- if not .Organizations }}
organizations: {}
{{- else }}
organizations:
  {{ range $mspID, $org := .Organizations }}
  {{$mspID}}:
    mspid: {{$mspID}}
    cryptoPath: /tmp/cryptopath
{{- if not $org.Users }}
    users: {}
{{- else }}
    users:
    {{- range $user := $org.Users }}
      {{ $user.Name }}:
        cert:
          pem: |
{{ $user.Cert | indent 12 }}
        key:
          pem: |
{{ $user.Key | indent 12 }}
    {{- end }}
{{- end }}
{{- if not $org.Peers }}
    peers: []
{{- else }}
    peers:
      {{- range $peer := $org.Peers }}
      - {{ $peer.Name }}
 	  {{- end }}
{{- end }}
{{- if not $org.OrdererNodes }}
    orderers: []
{{- else }}
    orderers:
      {{- range $orderer := $org.OrdererNodes }}
      - {{ $orderer.Name }}
 	  {{- end }}
      {{- range $orderer := $.ExternalOrderers }}
      - {{ $orderer.Name }}
 	  {{- end }}
    {{- end }}
{{- end }}
{{- end }}
{{ if and (empty .Orderers) (empty .ExternalOrderers) }}
orderers: {}
{{- else }}
orderers:
{{- range $orderer := .Orderers }}
  {{$orderer.Name}}:
{{if $.Internal }}
    url: grpcs://{{ $orderer.PrivateURL }}
{{ else }}
    url: grpcs://{{ $orderer.PublicURL }}
{{ end }}
{{if $orderer.AdminURL }}
    adminUrl: {{ $orderer.AdminURL }}
    adminTlsCert: |
{{ $orderer.Status.TlsAdminCert | indent 8 }}
{{ end }}
    grpcOptions:
      allow-insecure: false
    tlsCACerts:
      pem: |
{{ or $orderer.Status.TlsCACert $orderer.Status.TlsCert | indent 8 }}
{{- end }}

{{- range $orderer := .ExternalOrderers }}
  {{$orderer.Name}}:
    url: {{ $orderer.URL }}
    grpcOptions:
      allow-insecure: false
    tlsCACerts:
      pem: |
{{ or $orderer.TLSCACert | indent 8 }}
{{- end }}

{{- end }}

{{ if and (empty .Peers) (empty .ExternalPeers) }}
peers: {}
{{- else }}
peers:
  {{- range $peer := .Peers }}
  {{$peer.Name}}:
{{if $.Internal }}
    url: grpcs://{{ $peer.PrivateURL }}
{{ else }}
    url: grpcs://{{ $peer.PublicURL }}
{{ end }}
    grpcOptions:
      allow-insecure: false
    tlsCACerts:
      pem: |
{{ $peer.Status.TlsCACert | indent 8 }}
{{- end }}

{{- range $peer := .ExternalPeers }}
  {{$peer.Name}}:
    url: {{ $peer.URL }}
    grpcOptions:
      allow-insecure: false
    tlsCACerts:
      pem: |
{{ $peer.TLSCACert | indent 8 }}
{{- end }}

{{- end }}

{{- if not .CertAuths }}
certificateAuthorities: {}
{{- else }}
certificateAuthorities:
{{- range $ca := .CertAuths }}
  
  {{ $ca.Name }}:
{{if $.Internal }}
    url: https://{{ $ca.PrivateURL }}
{{ else }}
    url: https://{{ $ca.PublicURL }}
{{ end }}
{{if $ca.EnrollID }}
    registrar:
        enrollId: {{ $ca.EnrollID }}
        enrollSecret: "{{ $ca.EnrollPWD }}"
{{ end }}
    caName: ca
    tlsCACerts:
      pem: 
       - |
{{ $ca.Status.TlsCert | indent 12 }}

{{- end }}
{{- end }}


channels:
{{- range $channel := .Channels }}
  {{ $channel }}:
{{ if and (empty $.Orderers) (empty $.ExternalOrderers) }}
    orderers: []
{{- else }}
    orderers:
{{- range $orderer := $.Orderers }}
      - {{$orderer.Name}}
{{- end }}
{{- range $orderer := $.ExternalOrderers }}
      - {{$orderer.Name}}
{{- end }}
{{- end }}
{{ if and (empty $.Peers) (empty $.ExternalPeers) }}
    peers: {}
{{- else }}
    peers:
{{- range $peer := $.Peers }}
       {{$peer.Name}}:
        discover: true
        endorsingPeer: true
        chaincodeQuery: true
        ledgerQuery: true
        eventSource: true
{{- end }}

{{- range $peer := $.ExternalPeers }}
       {{$peer.Name}}:
        discover: true
        endorsingPeer: true
        chaincodeQuery: true
        ledgerQuery: true
        eventSource: true
{{- end }}

{{- end }}
{{- end }}

`

const networkConfigFinalizer = "finalizer.networkConfig.hlf.kungfusoftware.es"

func (r *FabricNetworkConfigReconciler) finalizeNetworkConfig(reqLogger logr.Logger, m *hlfv1alpha1.FabricNetworkConfig) error {
	ns := m.Namespace
	if ns == "" {
		ns = "default"
	}
	//releaseName := m.Name
	reqLogger.Info("Successfully finalized networkConfig")

	return nil
}

func (r *FabricNetworkConfigReconciler) addFinalizer(reqLogger logr.Logger, m *hlfv1alpha1.FabricNetworkConfig) error {
	reqLogger.Info("Adding Finalizer for the NetworkConfig")
	controllerutil.AddFinalizer(m, networkConfigFinalizer)

	// Update CR
	err := r.Update(context.TODO(), m)
	if err != nil {
		reqLogger.Error(err, "Failed to update NetworkConfig with finalizer")
		return err
	}
	return nil
}

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricnetworkconfigs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricnetworkconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricnetworkconfigs/finalizers,verbs=get;update;patch

func (r *FabricNetworkConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	reqLogger := r.Log.WithValues("hlf", req.NamespacedName)
	fabricNetworkConfig := &hlfv1alpha1.FabricNetworkConfig{}
	//releaseName := req.Name

	err := r.Get(ctx, req.NamespacedName, fabricNetworkConfig)
	if err != nil {
		log.Debugf("Error getting the object %s error=%v", req.NamespacedName, err)
		if apierrors.IsNotFound(err) {
			reqLogger.Info("NetworkConfig resource not found. Ignoring since object must be deleted.")
			return ctrl.Result{}, nil
		}
		reqLogger.Error(err, "Failed to get NetworkConfig.")
		return ctrl.Result{}, err
	}
	isMemcachedMarkedToBeDeleted := fabricNetworkConfig.GetDeletionTimestamp() != nil
	if isMemcachedMarkedToBeDeleted {
		if utils.Contains(fabricNetworkConfig.GetFinalizers(), networkConfigFinalizer) {
			if err := r.finalizeNetworkConfig(reqLogger, fabricNetworkConfig); err != nil {
				return ctrl.Result{}, err
			}
			controllerutil.RemoveFinalizer(fabricNetworkConfig, networkConfigFinalizer)
			err := r.Update(ctx, fabricNetworkConfig)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}
	if !utils.Contains(fabricNetworkConfig.GetFinalizers(), networkConfigFinalizer) {
		if err := r.addFinalizer(reqLogger, fabricNetworkConfig); err != nil {
			return ctrl.Result{}, err
		}
	}
	hlfClientSet, err := operatorv1.NewForConfig(r.Config)
	if err != nil {
		r.setConditionStatus(ctx, fabricNetworkConfig, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricNetworkConfig)
	}
	kubeClientset, err := kubernetes.NewForConfig(r.Config)
	if err != nil {
		r.setConditionStatus(ctx, fabricNetworkConfig, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricNetworkConfig)
	}
	var buf bytes.Buffer
	clusterCertAuths, err := helpers.GetClusterCAs(kubeClientset, hlfClientSet, "")
	if err != nil {
		r.setConditionStatus(ctx, fabricNetworkConfig, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricNetworkConfig)
	}

	clusterOrderersNodes, err := helpers.GetClusterOrdererNodes(kubeClientset, hlfClientSet, "")
	if err != nil {
		r.setConditionStatus(ctx, fabricNetworkConfig, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricNetworkConfig)
	}
	peerOrgs, clusterPeers, err := helpers.GetClusterPeers(kubeClientset, hlfClientSet, "")
	if err != nil {
		r.setConditionStatus(ctx, fabricNetworkConfig, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricNetworkConfig)
	}
	orgMap := map[string]*helpers.Organization{}
	filterByOrgs := len(fabricNetworkConfig.Spec.Organizations) > 0
	filterByNS := len(fabricNetworkConfig.Spec.Namespaces) > 0
	var certAuths []*helpers.ClusterCA
	for _, ca := range clusterCertAuths {
		if filterByNS && !utils.Contains(fabricNetworkConfig.Spec.Namespaces, ca.Namespace) {
			continue
		}
		certAuths = append(certAuths, ca)
	}
	// filter by cas included, if any
	if len(fabricNetworkConfig.Spec.CertificateAuthorities) > 0 {
		var cas []*helpers.ClusterCA
		for _, ca := range certAuths {
			for _, fabricNetworkConfigCA := range fabricNetworkConfig.Spec.CertificateAuthorities {
				if ca.Item.Name == fabricNetworkConfigCA.Name && ca.Item.Namespace == fabricNetworkConfigCA.Namespace {
					cas = append(cas, ca)
				}
			}
		}
		certAuths = cas
	}
	for _, v := range peerOrgs {
		if (filterByOrgs && utils.Contains(fabricNetworkConfig.Spec.Organizations, v.MspID)) || !filterByOrgs {
			var peers []*helpers.ClusterPeer
			for _, peer := range v.Peers {
				if filterByNS && !utils.Contains(fabricNetworkConfig.Spec.Namespaces, peer.Namespace) {
					continue
				}
				if (filterByOrgs && utils.Contains(fabricNetworkConfig.Spec.Organizations, peer.MSPID)) || !filterByOrgs {
					peers = append(peers, peer)
				}
			}
			v.Peers = peers
			orgMap[v.MspID] = v
		}
	}

	var orderers []*helpers.ClusterOrdererNode
	for _, orderer := range clusterOrderersNodes {
		if filterByNS && !utils.Contains(fabricNetworkConfig.Spec.Namespaces, orderer.Namespace) {
			continue
		}
		if !filterByOrgs {
			orderers = append(orderers, orderer)
		} else if filterByOrgs && utils.Contains(fabricNetworkConfig.Spec.Organizations, orderer.Item.Spec.MspID) {
			orderers = append(orderers, orderer)
		}
	}
	for _, ordererNode := range clusterOrderersNodes {
		if filterByNS && !utils.Contains(fabricNetworkConfig.Spec.Namespaces, ordererNode.Namespace) {
			continue
		}

		if (filterByOrgs && utils.Contains(fabricNetworkConfig.Spec.Organizations, ordererNode.Spec.MspID)) || !filterByOrgs {
			org, ok := orgMap[ordererNode.Spec.MspID]
			if ok {
				org.OrdererNodes = append(org.OrdererNodes, ordererNode)
			} else {
				orgMap[ordererNode.Spec.MspID] = &helpers.Organization{
					Type:         helpers.OrdererType,
					MspID:        ordererNode.Spec.MspID,
					OrdererNodes: []*helpers.ClusterOrdererNode{ordererNode},
					Peers:        []*helpers.ClusterPeer{},
				}
			}
		}
	}
	for _, identity := range fabricNetworkConfig.Spec.Identities {
		fabIdentity, err := hlfClientSet.HlfV1alpha1().FabricIdentities(identity.Namespace).Get(ctx, identity.Name, metav1.GetOptions{})
		if err != nil {
			r.setConditionStatus(ctx, fabricNetworkConfig, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricNetworkConfig)
		}
		mspID := fabIdentity.Spec.MSPID
		if _, ok := orgMap[mspID]; !ok {
			log.Infof("Organization %s for Identity %s/%s not found in network", mspID, identity.Name, identity.Namespace)
			continue
		}
		org := orgMap[mspID]

		if fabIdentity.Status.Status != hlfv1alpha1.RunningStatus {
			r.setConditionStatus(ctx, fabricNetworkConfig, hlfv1alpha1.FailedStatus, false, errors.New("identity not ready"), false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricNetworkConfig)
		}
		// fetch certificate and password from secret
		secret, err := kubeClientset.CoreV1().Secrets(identity.Namespace).Get(ctx, identity.Name, metav1.GetOptions{})
		if err != nil {
			r.setConditionStatus(ctx, fabricNetworkConfig, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricNetworkConfig)
		}
		certBytes, ok := secret.Data["cert.pem"]
		if !ok {
			r.setConditionStatus(ctx, fabricNetworkConfig, hlfv1alpha1.FailedStatus, false, errors.New("no cert in secret"), false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricNetworkConfig)
		}
		keyBytes, ok := secret.Data["key.pem"]
		if !ok {
			r.setConditionStatus(ctx, fabricNetworkConfig, hlfv1alpha1.FailedStatus, false, errors.New("no key in secret"), false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricNetworkConfig)
		}
		org.Users = append(org.Users, helpers.OrgUser{
			Name: fmt.Sprintf("%s-%s", identity.Name, identity.Namespace),
			Cert: string(certBytes),
			Key:  string(keyBytes),
		})
	}

	var peers []*helpers.ClusterPeer
	for _, peer := range clusterPeers {
		if filterByNS && !utils.Contains(fabricNetworkConfig.Spec.Namespaces, peer.Namespace) {
			continue
		}
		if (peer.Spec.Replicas > 0 && filterByOrgs && utils.Contains(fabricNetworkConfig.Spec.Organizations, peer.MSPID)) || !filterByOrgs {
			peers = append(peers, peer)
		}

	}
	for mspID, org := range fabricNetworkConfig.Spec.OrganizationConfig {
		if len(org.Peers) > 0 {
			// iterate through clusterpeers and remove the ones that are not in the list
			// peers = peer0-org1 peer1-org1 peer1-ch-org1
			// org peers
			var orgPeers []*helpers.ClusterPeer
			for _, peer := range org.Peers {
				for _, p := range peers {
					if p.Object.Name == peer.Name && p.Object.Namespace == peer.Namespace && p.Spec.Replicas > 0 {
						orgPeers = append(orgPeers, p)
					} else {
						// delete from peers
					}
				}
			}
			var restPeerOrgs []*helpers.ClusterPeer
			for _, p := range peers {
				if p.MSPID != mspID && p.Spec.Replicas > 0 {
					restPeerOrgs = append(restPeerOrgs, p)
				}
			}
			peers = append(restPeerOrgs, orgPeers...)
			orgMap[mspID].Peers = orgPeers
		}
	}

	tmpl, err := template.New("networkConfig").Funcs(sprig.HermeticTxtFuncMap()).Parse(tmplGoConfig)
	if err != nil {
		r.setConditionStatus(ctx, fabricNetworkConfig, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricNetworkConfig)
	}
	err = tmpl.Execute(&buf, map[string]interface{}{
		"Peers":            peers,
		"Orderers":         orderers,
		"ExternalPeers":    fabricNetworkConfig.Spec.ExternalPeers,
		"ExternalOrderers": fabricNetworkConfig.Spec.ExternalOrderers,
		"Organizations":    orgMap,
		"Channels":         fabricNetworkConfig.Spec.Channels,
		"CertAuths":        certAuths,
		"Organization":     fabricNetworkConfig.Spec.Organization,
		"Internal":         fabricNetworkConfig.Spec.Internal,
	})
	if err != nil {
		r.setConditionStatus(ctx, fabricNetworkConfig, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricNetworkConfig)
	}
	ns := req.Namespace
	if ns == "" {
		ns = "default"
	}
	secretName := fabricNetworkConfig.Spec.SecretName
	secretData := map[string][]byte{
		"config.yaml": buf.Bytes(),
	}
	secret, err := kubeClientset.CoreV1().Secrets(ns).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			// creating secret
			secret, err = kubeClientset.CoreV1().Secrets(ns).Create(
				ctx,
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      secretName,
						Namespace: ns,
					},
					Data: secretData,
				},
				metav1.CreateOptions{},
			)
			if err != nil {
				r.setConditionStatus(ctx, fabricNetworkConfig, hlfv1alpha1.FailedStatus, false, err, false)
				return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricNetworkConfig)
			}
			return ctrl.Result{}, nil
		}
		r.setConditionStatus(ctx, fabricNetworkConfig, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricNetworkConfig)
	}
	secret.Data = secretData
	secret, err = kubeClientset.CoreV1().Secrets(ns).Update(
		ctx,
		secret,
		metav1.UpdateOptions{},
	)
	if err != nil {
		r.setConditionStatus(ctx, fabricNetworkConfig, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricNetworkConfig)
	}
	r.setConditionStatus(ctx, fabricNetworkConfig, hlfv1alpha1.RunningStatus, true, nil, false)
	fca := fabricNetworkConfig.DeepCopy()
	fca.Status.Status = hlfv1alpha1.RunningStatus
	fca.Status.Conditions.SetCondition(status.Condition{
		Type:   status.ConditionType(fca.Status.Status),
		Status: "True",
	})
	if err := r.Status().Update(ctx, fca); err != nil {
		log.Error(err, fmt.Sprintf("%v failed to update the application status", ErrClientK8s))
		return reconcile.Result{}, err
	}
	r.setConditionStatus(ctx, fabricNetworkConfig, hlfv1alpha1.RunningStatus, true, nil, false)
	return r.updateCRStatusOrFailReconcileWithRequeue(ctx, r.Log, fabricNetworkConfig, 120*time.Minute)
}

var (
	ErrClientK8s = errors.New("k8sAPIClientError")
)

func (r *FabricNetworkConfigReconciler) updateCRStatusOrFailReconcile(ctx context.Context, log logr.Logger, p *hlfv1alpha1.FabricNetworkConfig) (
	reconcile.Result, error) {
	if err := r.Status().Update(ctx, p); err != nil {
		log.Error(err, fmt.Sprintf("%v failed to update the application status", ErrClientK8s))
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}
func (r *FabricNetworkConfigReconciler) updateCRStatusOrFailReconcileWithRequeue(ctx context.Context, log logr.Logger, p *hlfv1alpha1.FabricNetworkConfig, requeueAfter time.Duration) (
	reconcile.Result, error) {
	if err := r.Status().Update(ctx, p); err != nil {
		log.Error(err, fmt.Sprintf("%v failed to update the application status", ErrClientK8s))
		return reconcile.Result{}, err
	}
	return reconcile.Result{
		RequeueAfter: requeueAfter,
	}, nil
}

func (r *FabricNetworkConfigReconciler) setConditionStatus(ctx context.Context, p *hlfv1alpha1.FabricNetworkConfig, conditionType hlfv1alpha1.DeploymentStatus, statusFlag bool, err error, statusUnknown bool) (update bool) {
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

func (r *FabricNetworkConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	managedBy := ctrl.NewControllerManagedBy(mgr)
	return managedBy.
		For(&hlfv1alpha1.FabricNetworkConfig{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}

func actionLogger(logger logr.Logger) func(format string, v ...interface{}) {
	return func(format string, v ...interface{}) {
		logger.Info(fmt.Sprintf(format, v...))
	}
}
