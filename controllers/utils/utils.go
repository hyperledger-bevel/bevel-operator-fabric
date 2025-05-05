package utils

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	corev1 "k8s.io/api/core/v1"
	v12 "k8s.io/api/core/v1"
	apiextv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

func GetClientKubeWithConf(config *rest.Config) (*kubernetes.Clientset, error) {
	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return clientSet, nil
}

func ParseK8sYaml(fileR []byte) []runtime.Object {
	fileAsString := string(fileR[:])
	sepYamlfiles := strings.Split(fileAsString, "---")
	retVal := make([]runtime.Object, 0, len(sepYamlfiles))
	for _, f := range sepYamlfiles {
		if f == "\n" || f == "" {
			// ignore empty cases
			continue
		}
		sch := runtime.NewScheme()
		_ = clientgoscheme.AddToScheme(sch)
		_ = apiextv1beta1.AddToScheme(sch)
		decode := serializer.NewCodecFactory(sch).UniversalDeserializer().Decode
		obj, _, err := decode([]byte(f), nil, nil)

		if err != nil {
			//log.Println(fmt.Sprintf("Error while decoding YAML object. Err was: %s", err))
			continue
		}

		retVal = append(retVal, obj)

	}
	return retVal
}

func ParseECDSAPrivateKey(contents []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(contents)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not of ECDSA type")
	}
	return ecdsaKey, nil
}

func ParseX509Certificate(contents []byte) (*x509.Certificate, error) {
	if len(contents) == 0 {
		return nil, errors.New("certificate pem is empty")
	}
	block, _ := pem.Decode(contents)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return crt, nil
}

func EncodeX509Certificate(crt *x509.Certificate) []byte {
	pemPk := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crt.Raw,
	})
	return pemPk
}

func EncodePrivateKey(key interface{}) ([]byte, error) {
	signEncodedPK, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	pemPk := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: signEncodedPK,
	})
	return pemPk, nil
}

func GetPublicIPKubernetes(clientSet *kubernetes.Clientset) (string, error) {
	ctx := context.Background()
	resp, err := clientSet.CoreV1().Nodes().List(ctx, v1.ListOptions{})
	if err != nil {
		return "", err
	}
	var externalIPAdresses []string
	var internalIPaddresses []string
	for _, node := range resp.Items {
		for _, ipaddress := range node.Status.Addresses {
			switch ipaddress.Type {
			case v12.NodeHostName:
			case v12.NodeExternalDNS:
			case v12.NodeInternalDNS:
				continue
			case v12.NodeExternalIP:
				externalIPAdresses = append(externalIPAdresses, ipaddress.Address)
			case v12.NodeInternalIP:
				internalIPaddresses = append(internalIPaddresses, ipaddress.Address)

			}
		}
	}
	if len(externalIPAdresses) > 0 {
		return externalIPAdresses[0], nil
	} else if len(internalIPaddresses) > 0 {
		return internalIPaddresses[0], nil
	} else {
		return "", nil
	}
}
func GetPublicIPsKubernetes(clientSet *kubernetes.Clientset) ([]string, error) {
	ctx := context.Background()
	resp, err := clientSet.CoreV1().Nodes().List(ctx, v1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var externalIPAdresses []string
	var internalIPaddresses []string
	for _, node := range resp.Items {
		for _, ipaddress := range node.Status.Addresses {
			switch ipaddress.Type {
			case v12.NodeHostName:
			case v12.NodeExternalDNS:
			case v12.NodeInternalDNS:
				continue
			case v12.NodeExternalIP:
				externalIPAdresses = append(externalIPAdresses, ipaddress.Address)
			case v12.NodeInternalIP:
				internalIPaddresses = append(internalIPaddresses, ipaddress.Address)

			}
		}
	}
	if len(externalIPAdresses) > 0 {
		return externalIPAdresses, nil
	} else if len(internalIPaddresses) > 0 {
		return internalIPaddresses, nil
	} else {
		return nil, nil
	}
}

func Contains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[item]
	return ok
}

func GetFreeNodeports(host string, n int) ([]int, error) {
	c := 0
	ports := []int{}
	for port := 30000; port <= 32767; port++ {
		timeout := time.Second
		portStr := strconv.Itoa(port)
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, portStr), timeout)
		if err != nil {
			if !strings.Contains(err.Error(), "i/o timeout") {
				c++
				ports = append(ports, port)
				if c == n {
					return ports, nil
				}
			}

		}
		if conn != nil {
			err = conn.Close()
			if err != nil {
				log.Warnf("Failed to close connection: %v", err)
			}
		}
	}
	return []int{}, errors.New("no ports are free")
}

// IsPodReadyConditionTrue returns true if a pod is ready; false otherwise.
func IsPodReadyConditionTrue(status corev1.PodStatus) bool {
	condition := GetPodReadyCondition(status)
	return condition != nil && condition.Status == corev1.ConditionTrue
}

// GetPodReadyCondition extracts the pod ready condition from the given status and returns that.
// Returns nil if the condition is not present.
func GetPodReadyCondition(status corev1.PodStatus) *corev1.PodCondition {
	_, condition := GetPodCondition(&status, corev1.PodReady)
	return condition
}

// GetPodCondition extracts the provided condition from the given status and returns that.
// Returns nil and -1 if the condition is not present, and the index of the located condition.
func GetPodCondition(status *corev1.PodStatus, conditionType corev1.PodConditionType) (int, *corev1.PodCondition) {
	if status == nil {
		return -1, nil
	}
	return GetPodConditionFromList(status.Conditions, conditionType)
}

// GetPodConditionFromList extracts the provided condition from the given list of condition and
// returns the index of the condition and the condition. Returns -1 and nil if the condition is not present.
func GetPodConditionFromList(conditions []corev1.PodCondition, conditionType corev1.PodConditionType) (int, *corev1.PodCondition) {
	if conditions == nil {
		return -1, nil
	}
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return i, &conditions[i]
		}
	}
	return -1, nil
}
