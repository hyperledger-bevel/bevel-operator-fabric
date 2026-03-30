package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"

	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Regression tests for issue #214: x509 certificate valid for wrong IP

func TestGetDNSNames(t *testing.T) {
	tests := []struct {
		name     string
		hosts    []string
		expected []string
	}{
		{
			name:     "Only hostnames",
			hosts:    []string{"ca.example.com", "ca.org1.example.com"},
			expected: []string{"ca.example.com", "ca.org1.example.com"},
		},
		{
			name:     "Only IPs are excluded",
			hosts:    []string{"192.168.1.1", "10.0.0.1"},
			expected: nil,
		},
		{
			name:     "Mixed hostnames and IPs",
			hosts:    []string{"ca.example.com", "192.168.1.1", "orderer.example.com", "10.0.0.1"},
			expected: []string{"ca.example.com", "orderer.example.com"},
		},
		{
			name:     "Empty hosts",
			hosts:    []string{},
			expected: nil,
		},
		{
			name:     "IPv6 addresses are excluded",
			hosts:    []string{"ca.example.com", "::1", "fe80::1"},
			expected: []string{"ca.example.com"},
		},
		{
			name:     "Localhost hostname is kept as DNS name",
			hosts:    []string{"localhost"},
			expected: []string{"localhost"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			spec := hlfv1alpha1.FabricCASpec{Hosts: tt.hosts}
			result := getDNSNames(spec)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetIPAddresses(t *testing.T) {
	tests := []struct {
		name     string
		hosts    []string
		expected []net.IP
	}{
		{
			name:     "No hosts still includes localhost",
			hosts:    []string{},
			expected: []net.IP{net.ParseIP("127.0.0.1")},
		},
		{
			name:     "Only hostnames - only localhost returned",
			hosts:    []string{"ca.example.com"},
			expected: []net.IP{net.ParseIP("127.0.0.1")},
		},
		{
			name:  "IPv4 addresses are included",
			hosts: []string{"192.168.1.1", "10.0.0.1"},
			expected: []net.IP{
				net.ParseIP("127.0.0.1"),
				net.ParseIP("192.168.1.1"),
				net.ParseIP("10.0.0.1"),
			},
		},
		{
			name:  "Mixed hosts - only IPs extracted",
			hosts: []string{"ca.example.com", "192.168.1.1", "orderer.example.com"},
			expected: []net.IP{
				net.ParseIP("127.0.0.1"),
				net.ParseIP("192.168.1.1"),
			},
		},
		{
			name:  "IPv6 addresses are included",
			hosts: []string{"::1", "fe80::1"},
			expected: []net.IP{
				net.ParseIP("127.0.0.1"),
				net.ParseIP("::1"),
				net.ParseIP("fe80::1"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			spec := hlfv1alpha1.FabricCASpec{Hosts: tt.hosts}
			result := getIPAddresses(spec)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDoesCertNeedsToBeRenewed(t *testing.T) {
	tests := []struct {
		name          string
		certDNSNames  []string
		certIPs       []net.IP
		specHosts     []string
		expectRenewal bool
	}{
		{
			name:          "Cert matches spec - no renewal needed",
			certDNSNames:  []string{"ca.example.com"},
			certIPs:       []net.IP{net.ParseIP("127.0.0.1")},
			specHosts:     []string{"ca.example.com"},
			expectRenewal: false,
		},
		{
			name:          "DNS name added to spec - renewal needed",
			certDNSNames:  []string{"ca.example.com"},
			certIPs:       []net.IP{net.ParseIP("127.0.0.1")},
			specHosts:     []string{"ca.example.com", "ca2.example.com"},
			expectRenewal: true,
		},
		{
			name:          "DNS name removed from spec - renewal needed",
			certDNSNames:  []string{"ca.example.com", "ca2.example.com"},
			certIPs:       []net.IP{net.ParseIP("127.0.0.1")},
			specHosts:     []string{"ca.example.com"},
			expectRenewal: true,
		},
		{
			name:          "IP added to spec - DNS unchanged - no renewal",
			certDNSNames:  []string{"ca.example.com"},
			certIPs:       []net.IP{net.ParseIP("127.0.0.1")},
			specHosts:     []string{"ca.example.com", "192.168.1.1"},
			expectRenewal: false, // function only checks DNS names, not IPs
		},
		{
			name:          "Order differs but same DNS names - no renewal",
			certDNSNames:  []string{"b.example.com", "a.example.com"},
			certIPs:       []net.IP{net.ParseIP("127.0.0.1")},
			specHosts:     []string{"a.example.com", "b.example.com"},
			expectRenewal: false, // function sorts before comparing
		},
		{
			name:          "Empty cert DNS, empty spec hosts - no renewal",
			certDNSNames:  nil,
			certIPs:       []net.IP{net.ParseIP("127.0.0.1")},
			specHosts:     []string{},
			expectRenewal: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create a minimal x509 certificate with the test DNS/IP values
			privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			template := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				NotBefore:    time.Now().Add(-1 * time.Hour),
				NotAfter:     time.Now().Add(24 * time.Hour),
				DNSNames:     tt.certDNSNames,
				IPAddresses:  tt.certIPs,
			}

			certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
			require.NoError(t, err)

			cert, err := x509.ParseCertificate(certBytes)
			require.NoError(t, err)

			conf := &hlfv1alpha1.FabricCA{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-ca",
					Namespace: "test-ns",
				},
				Spec: hlfv1alpha1.FabricCASpec{
					Hosts: tt.specHosts,
				},
			}

			result := doesCertNeedsToBeRenewed(cert, conf)
			assert.Equal(t, tt.expectRenewal, result)
		})
	}
}
