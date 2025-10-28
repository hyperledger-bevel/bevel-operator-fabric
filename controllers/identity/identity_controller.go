package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/ghodss/yaml"
	"github.com/go-logr/logr"
	"github.com/kfsoftware/hlf-operator/controllers/certs"
	"github.com/kfsoftware/hlf-operator/controllers/certs_vault"
	"github.com/kfsoftware/hlf-operator/controllers/utils"
	"github.com/kfsoftware/hlf-operator/internal/github.com/hyperledger/fabric-ca/api"
	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/kfsoftware/hlf-operator/pkg/status"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
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

// FabricIdentityReconciler reconciles a FabricIdentity object
type FabricIdentityReconciler struct {
	client.Client
	Log                        logr.Logger
	Scheme                     *runtime.Scheme
	Config                     *rest.Config
	AutoRenewCertificates      bool
	AutoRenewCertificatesDelta time.Duration
}

// ConfigValidator validates identity configuration
type ConfigValidator struct{}

func (v *ConfigValidator) ValidateIdentity(identity *hlfv1alpha1.FabricIdentity) error {
	var errs []error

	if err := v.validateCredentialStore(identity); err != nil {
		errs = append(errs, err)
	}

	if err := v.validateEnrollment(identity); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("validation failed: %v", errs)
	}

	return nil
}

func (v *ConfigValidator) validateCredentialStore(identity *hlfv1alpha1.FabricIdentity) error {
	switch identity.Spec.CredentialStore {
	case hlfv1alpha1.CredentialStoreVault:
		return v.validateVaultConfig(identity)
	case hlfv1alpha1.CredentialStoreKubernetes, "":
		return v.validateKubernetesConfig(identity)
	default:
		return fmt.Errorf("unsupported credential store: %s", identity.Spec.CredentialStore)
	}
}

func (v *ConfigValidator) validateVaultConfig(identity *hlfv1alpha1.FabricIdentity) error {
	if identity.Spec.Vault == nil {
		return errors.New("vault configuration is required when using vault credential store")
	}
	return nil
}

func (v *ConfigValidator) validateKubernetesConfig(identity *hlfv1alpha1.FabricIdentity) error {
	if identity.Spec.Cahost == "" {
		return errors.New("CA host is required when using kubernetes credential store")
	}
	if identity.Spec.Enrollid == "" {
		return errors.New("enrollment ID is required")
	}
	if identity.Spec.Enrollsecret == "" {
		return errors.New("enrollment secret is required")
	}
	return nil
}

func (v *ConfigValidator) validateEnrollment(identity *hlfv1alpha1.FabricIdentity) error {
	if identity.Spec.MSPID == "" {
		return errors.New("MSP ID is required")
	}
	return nil
}

const identityFinalizer = "finalizer.identity.hlf.kungfusoftware.es"

func (r *FabricIdentityReconciler) finalizeMainChannel(reqLogger logr.Logger, m *hlfv1alpha1.FabricIdentity) error {
	ns := m.Namespace
	if ns == "" {
		ns = "default"
	}
	reqLogger.Info("Successfully finalized identity")

	return nil
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
func (r *FabricIdentityReconciler) addFinalizer(reqLogger logr.Logger, m *hlfv1alpha1.FabricIdentity) error {
	reqLogger.Info("Adding Finalizer for the MainChannel")
	controllerutil.AddFinalizer(m, identityFinalizer)

	// Update CR
	err := r.Update(context.TODO(), m)
	if err != nil {
		reqLogger.Error(err, "Failed to update MainChannel with finalizer")
		return err
	}
	return nil
}

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricidentities,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricidentities/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricidentities/finalizers,verbs=get;update;patch
func (r *FabricIdentityReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	reqLogger := r.Log.WithValues("hlf", req.NamespacedName)
	reqLogger.Info("Reconciling FabricIdentity")
	fabricIdentity := &hlfv1alpha1.FabricIdentity{}

	err := r.Get(ctx, req.NamespacedName, fabricIdentity)
	if err != nil {
		if apierrors.IsNotFound(err) {
			reqLogger.Info("Identity resource not found. Ignoring since object must be deleted.")
			return ctrl.Result{}, nil
		}
		reqLogger.Error(err, "Failed to get Identity", "namespacedName", req.NamespacedName)
		return ctrl.Result{}, fmt.Errorf("failed to get Identity %s: %w", req.NamespacedName, err)
	}
	markedToBeDeleted := fabricIdentity.GetDeletionTimestamp() != nil
	if markedToBeDeleted {
		if utils.Contains(fabricIdentity.GetFinalizers(), identityFinalizer) {
			if err := r.finalizeMainChannel(reqLogger, fabricIdentity); err != nil {
				return ctrl.Result{}, err
			}
			controllerutil.RemoveFinalizer(fabricIdentity, identityFinalizer)
			err := r.Update(ctx, fabricIdentity)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}
	if !utils.Contains(fabricIdentity.GetFinalizers(), identityFinalizer) {
		if err := r.addFinalizer(reqLogger, fabricIdentity); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Validate configuration
	validator := &ConfigValidator{}
	if err := validator.ValidateIdentity(fabricIdentity); err != nil {
		reqLogger.Error(err, "Configuration validation failed")
		r.setConditionStatus(ctx, fabricIdentity, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricIdentity)
	}
	if fabricIdentity.Spec.CredentialStore == "" {
		fabricIdentity.Spec.CredentialStore = "kubernetes"
	}
	clientSet, err := utils.GetClientKubeWithConf(r.Config)
	if err != nil {
		r.setConditionStatus(ctx, fabricIdentity, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricIdentity)
	}
	// get secret if exists
	secretExists := true
	secret, err := clientSet.CoreV1().Secrets(fabricIdentity.Namespace).Get(ctx, fabricIdentity.Name, v1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			secretExists = false
		} else {
			r.setConditionStatus(ctx, fabricIdentity, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricIdentity)
		}
	}
	var x509Cert *x509.Certificate
	var pk *ecdsa.PrivateKey
	var rootCert *x509.Certificate
	if fabricIdentity.Spec.Register != nil && fabricIdentity.Spec.CredentialStore == hlfv1alpha1.CredentialStoreKubernetes {
		reqLogger.Info("Registering user", "enrollId", fabricIdentity.Spec.Enrollid, "mspId", fabricIdentity.Spec.MSPID)
		attributes := []api.Attribute{}
		for _, attr := range fabricIdentity.Spec.Register.Attributes {
			attributes = append(attributes, api.Attribute{
				Name:  attr.Name,
				Value: attr.Value,
				ECert: attr.ECert,
			})
		}

		tlsCert, err := getCertBytesFromCATLS(clientSet, fabricIdentity.Spec.Catls)
		if err != nil {
			r.setConditionStatus(ctx, fabricIdentity, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricIdentity)
		}
		_, err = certs.RegisterUser(certs.RegisterUserRequest{
			TLSCert:      string(tlsCert),
			URL:          fmt.Sprintf("https://%s:%d", fabricIdentity.Spec.Cahost, fabricIdentity.Spec.Caport),
			Name:         fabricIdentity.Spec.Caname,
			MSPID:        fabricIdentity.Spec.MSPID,
			EnrollID:     fabricIdentity.Spec.Register.Enrollid,
			EnrollSecret: fabricIdentity.Spec.Register.Enrollsecret,
			User:         fabricIdentity.Spec.Enrollid,
			Secret:       fabricIdentity.Spec.Enrollsecret,
			Type:         fabricIdentity.Spec.Register.Type,
			Attributes:   attributes,
		})
		if err != nil {
			if !strings.Contains(err.Error(), "already registered") {
				log.Errorf("Error registering user: %v", err)
				r.setConditionStatus(ctx, fabricIdentity, hlfv1alpha1.FailedStatus, false, err, false)
				return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricIdentity)
			}
		}
	}

	requests := []*api.AttributeRequest{}
	for _, attr := range fabricIdentity.Spec.AttributeRequest {
		requests = append(requests, &api.AttributeRequest{
			Name:     attr.Name,
			Optional: attr.Optional,
		})
	}
	if secretExists {
		// get crypto material from secret
		certPemBytes := secret.Data["cert.pem"]
		keyPemBytes := secret.Data["key.pem"]
		rootCertPemBytes := secret.Data["root.pem"]
		x509Cert, err = utils.ParseX509Certificate(certPemBytes)
		if err != nil {
			r.setConditionStatus(ctx, fabricIdentity, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricIdentity)
		}
		pk, err = utils.ParseECDSAPrivateKey(keyPemBytes)
		if err != nil {
			r.setConditionStatus(ctx, fabricIdentity, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricIdentity)
		}
		rootCert, err = utils.ParseX509Certificate(rootCertPemBytes)
		if err != nil {
			r.setConditionStatus(ctx, fabricIdentity, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricIdentity)
		}
		// check if certificates needs to be reenrolled
		certificatesNeedToBeRenewed := false

		if r.AutoRenewCertificates && x509Cert.NotAfter.Before(time.Now().Add(r.AutoRenewCertificatesDelta)) {
			certificatesNeedToBeRenewed = true
		}

		reqLogger.Info("Certificate renewal decision", "identity", fabricIdentity.Name, "needsRenewal", certificatesNeedToBeRenewed)
		if certificatesNeedToBeRenewed {
			x509Cert, pk, rootCert, err = ReenrollSignCryptoMaterial(clientSet, fabricIdentity, string(utils.EncodeX509Certificate(x509Cert)), pk)
			authenticationFailure := false
			if err != nil {
				if strings.Contains(err.Error(), "Authentication failure") {
					authenticationFailure = true
				} else {
					r.setConditionStatus(ctx, fabricIdentity, hlfv1alpha1.FailedStatus, false, err, false)
					return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricIdentity)
				}
			}
			if authenticationFailure {
				r.Log.Info(fmt.Sprintf("Re enroll failed because of credentials, falling back to enroll: %v", err))
				// just enroll the user
				x509Cert, pk, rootCert, err = CreateSignCryptoMaterial(clientSet, fabricIdentity)
				if err != nil {
					if strings.Contains(err.Error(), "Authentication failure") {
						r.setConditionStatus(ctx, fabricIdentity, hlfv1alpha1.FailedStatus, false, errors.New("enroll secret is not correct"), false)
						return r.updateCRStatusOrFailReconcileWithRequeue(ctx, r.Log, fabricIdentity, false, 0*time.Second)
					}
					r.setConditionStatus(ctx, fabricIdentity, hlfv1alpha1.FailedStatus, false, err, false)
					return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricIdentity)
				}
			}

		}
	} else {
		x509Cert, pk, rootCert, err = CreateSignCryptoMaterial(clientSet, fabricIdentity)
		if err != nil {
			if strings.Contains(err.Error(), "Authentication failure") {
				r.setConditionStatus(ctx, fabricIdentity, hlfv1alpha1.FailedStatus, false, errors.New("enroll secret is not correct"), false)
				return r.updateCRStatusOrFailReconcileWithRequeue(ctx, r.Log, fabricIdentity, false, 0*time.Second)
			}
			r.setConditionStatus(ctx, fabricIdentity, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricIdentity)
		}
	}
	pkBytes, err := utils.EncodePrivateKey(pk)
	if err != nil {
		r.setConditionStatus(ctx, fabricIdentity, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricIdentity)
	}
	userYaml, err := yaml.Marshal(map[string]interface{}{
		"key": map[string]interface{}{
			"pem": string(pkBytes),
		},
		"cert": map[string]interface{}{
			"pem": string(utils.EncodeX509Certificate(x509Cert)),
		},
	})
	if err != nil {
		r.setConditionStatus(ctx, fabricIdentity, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricIdentity)
	}
	if secretExists {
		secret.Data = map[string][]byte{
			"cert.pem":  utils.EncodeX509Certificate(x509Cert),
			"key.pem":   pkBytes,
			"root.pem":  utils.EncodeX509Certificate(rootCert),
			"user.yaml": userYaml,
		}
		if err := controllerutil.SetControllerReference(fabricIdentity, secret, r.Scheme); err != nil {
			r.setConditionStatus(ctx, fabricIdentity, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricIdentity)
		}
		if err := r.Update(ctx, secret); err != nil {
			r.setConditionStatus(ctx, fabricIdentity, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricIdentity)
		}
	} else {
		secret = &corev1.Secret{
			ObjectMeta: v1.ObjectMeta{
				Name:      fabricIdentity.Name,
				Namespace: fabricIdentity.Namespace,
			},
			Data: map[string][]byte{
				"cert.pem":  utils.EncodeX509Certificate(x509Cert),
				"key.pem":   pkBytes,
				"root.pem":  utils.EncodeX509Certificate(rootCert),
				"user.yaml": userYaml,
			},
		}
		if err := controllerutil.SetControllerReference(fabricIdentity, secret, r.Scheme); err != nil {
			r.setConditionStatus(ctx, fabricIdentity, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricIdentity)
		}
		if err := r.Create(ctx, secret); err != nil {
			r.setConditionStatus(ctx, fabricIdentity, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricIdentity)
		}
	}
	fabricIdentity.Status.Status = hlfv1alpha1.RunningStatus
	fabricIdentity.Status.Message = "Identity Setup"
	fabricIdentity.Status.Conditions.SetCondition(status.Condition{
		Type:               status.ConditionType(fabricIdentity.Status.Status),
		Status:             "True",
		LastTransitionTime: v1.Time{},
	})
	if err := r.Status().Update(ctx, fabricIdentity); err != nil {
		r.setConditionStatus(ctx, fabricIdentity, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricIdentity)
	}
	return ctrl.Result{
		RequeueAfter: 120 * time.Minute,
	}, nil
}

var (
	ErrClientK8s = errors.New("k8sAPIClientError")
)

func (r *FabricIdentityReconciler) updateCRStatusOrFailReconcile(ctx context.Context, log logr.Logger, p *hlfv1alpha1.FabricIdentity) (
	reconcile.Result, error) {
	return r.updateCRStatusOrFailReconcileWithRequeue(ctx, log, p, true, 10*time.Second)
}

func (r *FabricIdentityReconciler) updateCRStatusOrFailReconcileWithRequeue(
	ctx context.Context,
	log logr.Logger,
	p *hlfv1alpha1.FabricIdentity,
	requeue bool,
	requeueAfter time.Duration,
) (
	reconcile.Result, error) {
	if err := r.Status().Update(ctx, p); err != nil {
		log.Error(err, fmt.Sprintf("%v failed to update the application status", ErrClientK8s))
		return reconcile.Result{}, err
	}
	return reconcile.Result{
		Requeue:      requeue,
		RequeueAfter: requeueAfter,
	}, nil
}

func (r *FabricIdentityReconciler) setConditionStatus(ctx context.Context, p *hlfv1alpha1.FabricIdentity, conditionType hlfv1alpha1.DeploymentStatus, statusFlag bool, err error, statusUnknown bool) (update bool) {
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

func (r *FabricIdentityReconciler) SetupWithManager(mgr ctrl.Manager) error {
	managedBy := ctrl.NewControllerManagedBy(mgr)
	return managedBy.
		For(&hlfv1alpha1.FabricIdentity{}).
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

func CreateSignCryptoMaterial(client *kubernetes.Clientset, conf *hlfv1alpha1.FabricIdentity) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, error) {
	if conf.Spec.CredentialStore == hlfv1alpha1.CredentialStoreVault {
		enrollRequest, err := getEnrollRequestForVault(conf)
		if err != nil {
			return nil, nil, nil, err
		}
		tlsCert, tlsKey, tlsRootCert, err := certs_vault.EnrollUser(
			client,
			&conf.Spec.Vault.Vault,
			&conf.Spec.Vault.Request,
			enrollRequest,
		)
		if err != nil {
			return nil, nil, nil, err
		}
		return tlsCert, tlsKey, tlsRootCert, nil
	}
	enrollRequest, err := getEnrollRequestForFabricCA(client, conf)
	if err != nil {
		return nil, nil, nil, err
	}
	tlsCert, tlsKey, tlsRootCert, err := certs.EnrollUser(enrollRequest)
	if err != nil {
		return nil, nil, nil, err
	}
	return tlsCert, tlsKey, tlsRootCert, nil
}

func getEnrollRequestForFabricCA(client *kubernetes.Clientset, conf *hlfv1alpha1.FabricIdentity) (certs.EnrollUserRequest, error) {
	cacert, err := getCertBytesFromCATLS(client, conf.Spec.Catls)
	if err != nil {
		return certs.EnrollUserRequest{}, err
	}
	tlsCAUrl := fmt.Sprintf("https://%s:%d", conf.Spec.Cahost, conf.Spec.Caport)
	return certs.EnrollUserRequest{
		Hosts:      []string{},
		CN:         "",
		Attributes: nil,
		User:       conf.Spec.Enrollid,
		Secret:     conf.Spec.Enrollsecret,
		URL:        tlsCAUrl,
		Name:       conf.Spec.Caname,
		MSPID:      conf.Spec.MSPID,
		TLSCert:    string(cacert),
	}, nil
}

func getEnrollRequestForVault(conf *hlfv1alpha1.FabricIdentity) (certs_vault.EnrollUserRequest, error) {
	return certs_vault.EnrollUserRequest{
		MSPID:      conf.Spec.MSPID,
		User:       conf.Spec.Enrollid,
		Hosts:      []string{},
		CN:         conf.Name,
		Attributes: nil,
	}, nil
}

func ReenrollSignCryptoMaterial(
	client *kubernetes.Clientset,
	conf *hlfv1alpha1.FabricIdentity,
	signCertPem string,
	privateKey *ecdsa.PrivateKey,
) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, error) {
	if conf.Spec.CredentialStore == hlfv1alpha1.CredentialStoreVault {
		reenrollRequest, err := getReenrollRequestForVault(conf)
		if err != nil {
			return nil, nil, nil, err
		}
		signCert, signRootCert, err := certs_vault.ReenrollUser(
			client,
			&conf.Spec.Vault.Vault,
			&conf.Spec.Vault.Request,
			reenrollRequest,
			signCertPem,
			privateKey,
		)
		if err != nil {
			return nil, nil, nil, err
		}
		return signCert, privateKey, signRootCert, nil
	}

	reenrollRequest, err := getReenrollRequestForFabricCA(client, conf, conf.Spec.Caname)
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

func getReenrollRequestForFabricCA(client *kubernetes.Clientset, conf *hlfv1alpha1.FabricIdentity, profile string) (certs.ReenrollUserRequest, error) {
	cacert, err := getCertBytesFromCATLS(client, conf.Spec.Catls)
	if err != nil {
		return certs.ReenrollUserRequest{}, err
	}
	tlsCAUrl := fmt.Sprintf("https://%s:%d", conf.Spec.Cahost, conf.Spec.Caport)
	return certs.ReenrollUserRequest{
		TLSCert:  string(cacert),
		Hosts:    []string{},
		CN:       "",
		URL:      tlsCAUrl,
		Name:     conf.Spec.Caname,
		EnrollID: conf.Spec.Enrollid,
		MSPID:    conf.Spec.MSPID,
	}, nil
}

func getReenrollRequestForVault(conf *hlfv1alpha1.FabricIdentity) (certs_vault.ReenrollUserRequest, error) {
	return certs_vault.ReenrollUserRequest{
		MSPID:      conf.Spec.MSPID,
		Hosts:      []string{},
		CN:         conf.Name,
		Attributes: nil,
	}, nil
}
