package pki

import (
	"context"
)

// Provider defines the interface for PKI operations.
// Both Fabric CA and HashiCorp Vault implement this interface.
type Provider interface {
	// Enroll enrolls a new identity and returns the certificate and private key
	Enroll(ctx context.Context, req EnrollRequest) (*EnrollResponse, error)

	// Reenroll re-enrolls an existing identity using the existing key
	Reenroll(ctx context.Context, req ReenrollRequest) (*ReenrollResponse, error)

	// Register registers a new identity with the CA (returns enrollment secret)
	// Note: This may not be supported by all providers (e.g., Vault PKI)
	Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error)

	// Revoke revokes a certificate
	// Note: This may not be supported by all providers
	Revoke(ctx context.Context, req RevokeRequest) error

	// GetCAInfo retrieves information about the Certificate Authority
	GetCAInfo(ctx context.Context) (*CAInfo, error)

	// Type returns the provider type
	Type() ProviderType
}

// RegistrationSupporter is an optional interface for providers that support
// identity registration. Fabric CA supports this, but Vault PKI does not
// have native identity registration.
type RegistrationSupporter interface {
	// SupportsRegistration returns true if the provider supports identity registration
	SupportsRegistration() bool
}

// RevocationSupporter is an optional interface for providers that support
// certificate revocation.
type RevocationSupporter interface {
	// SupportsRevocation returns true if the provider supports certificate revocation
	SupportsRevocation() bool
}
