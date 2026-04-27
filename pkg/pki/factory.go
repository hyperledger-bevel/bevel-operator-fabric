package pki

import (
	"fmt"
	"sync"

	"github.com/pkg/errors"
	"k8s.io/client-go/kubernetes"
)

// ProviderFactory is a function that creates a Provider from a ProviderConfig
type ProviderFactory func(config *ProviderConfig) (Provider, error)

var (
	providerFactories = make(map[ProviderType]ProviderFactory)
	factoryMutex      sync.RWMutex
)

// RegisterProvider registers a provider factory for a given provider type.
// This should be called in the init() function of each provider package.
func RegisterProvider(providerType ProviderType, factory ProviderFactory) {
	factoryMutex.Lock()
	defer factoryMutex.Unlock()
	providerFactories[providerType] = factory
}

// NewProvider creates a PKI provider based on the given configuration.
// This is the main entry point for creating PKI providers.
func NewProvider(config *ProviderConfig) (Provider, error) {
	if config == nil {
		return nil, errors.New("provider config is required")
	}

	factoryMutex.RLock()
	factory, ok := providerFactories[config.Type]
	factoryMutex.RUnlock()

	if !ok {
		return nil, fmt.Errorf("no provider registered for type: %s", config.Type)
	}

	return factory(config)
}

// NewProviderFromCredentialStore creates a PKI provider based on the credential store type.
// This is a convenience function that maps credential store types to provider types.
func NewProviderFromCredentialStore(
	credentialStore string,
	clientSet kubernetes.Interface,
	fabricCAConfig *FabricCAConfig,
	vaultConfig *VaultConfig,
) (Provider, error) {
	var providerType ProviderType

	switch credentialStore {
	case "vault":
		providerType = ProviderTypeVault
	case "kubernetes", "":
		providerType = ProviderTypeFabricCA
	default:
		return nil, fmt.Errorf("unsupported credential store: %s", credentialStore)
	}

	return NewProvider(&ProviderConfig{
		Type:      providerType,
		ClientSet: clientSet,
		FabricCA:  fabricCAConfig,
		Vault:     vaultConfig,
	})
}

// GetRegisteredProviders returns a list of registered provider types
func GetRegisteredProviders() []ProviderType {
	factoryMutex.RLock()
	defer factoryMutex.RUnlock()

	types := make([]ProviderType, 0, len(providerFactories))
	for t := range providerFactories {
		types = append(types, t)
	}
	return types
}
