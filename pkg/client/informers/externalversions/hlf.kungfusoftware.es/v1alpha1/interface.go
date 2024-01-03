/*
 * Copyright Kungfusoftware.es. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package v1alpha1

import (
	internalinterfaces "github.com/kfsoftware/hlf-operator/pkg/client/informers/externalversions/internalinterfaces"
)

// Interface provides access to all the informers in this group version.
type Interface interface {
	// FabricCAs returns a FabricCAInformer.
	FabricCAs() FabricCAInformer
	// FabricChaincodes returns a FabricChaincodeInformer.
	FabricChaincodes() FabricChaincodeInformer
	// FabricExplorers returns a FabricExplorerInformer.
	FabricExplorers() FabricExplorerInformer
	// FabricFollowerChannels returns a FabricFollowerChannelInformer.
	FabricFollowerChannels() FabricFollowerChannelInformer
	// FabricIdentities returns a FabricIdentityInformer.
	FabricIdentities() FabricIdentityInformer
	// FabricMainChannels returns a FabricMainChannelInformer.
	FabricMainChannels() FabricMainChannelInformer
	// FabricNetworkConfigs returns a FabricNetworkConfigInformer.
	FabricNetworkConfigs() FabricNetworkConfigInformer
	// FabricOperationsConsoles returns a FabricOperationsConsoleInformer.
	FabricOperationsConsoles() FabricOperationsConsoleInformer
	// FabricOperatorAPIs returns a FabricOperatorAPIInformer.
	FabricOperatorAPIs() FabricOperatorAPIInformer
	// FabricOperatorUIs returns a FabricOperatorUIInformer.
	FabricOperatorUIs() FabricOperatorUIInformer
	// FabricOrdererNodes returns a FabricOrdererNodeInformer.
	FabricOrdererNodes() FabricOrdererNodeInformer
	// FabricOrderingServices returns a FabricOrderingServiceInformer.
	FabricOrderingServices() FabricOrderingServiceInformer
	// FabricPeers returns a FabricPeerInformer.
	FabricPeers() FabricPeerInformer
}

type version struct {
	factory          internalinterfaces.SharedInformerFactory
	namespace        string
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// New returns a new Interface.
func New(f internalinterfaces.SharedInformerFactory, namespace string, tweakListOptions internalinterfaces.TweakListOptionsFunc) Interface {
	return &version{factory: f, namespace: namespace, tweakListOptions: tweakListOptions}
}

// FabricCAs returns a FabricCAInformer.
func (v *version) FabricCAs() FabricCAInformer {
	return &fabricCAInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// FabricChaincodes returns a FabricChaincodeInformer.
func (v *version) FabricChaincodes() FabricChaincodeInformer {
	return &fabricChaincodeInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// FabricExplorers returns a FabricExplorerInformer.
func (v *version) FabricExplorers() FabricExplorerInformer {
	return &fabricExplorerInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// FabricFollowerChannels returns a FabricFollowerChannelInformer.
func (v *version) FabricFollowerChannels() FabricFollowerChannelInformer {
	return &fabricFollowerChannelInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// FabricIdentities returns a FabricIdentityInformer.
func (v *version) FabricIdentities() FabricIdentityInformer {
	return &fabricIdentityInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// FabricMainChannels returns a FabricMainChannelInformer.
func (v *version) FabricMainChannels() FabricMainChannelInformer {
	return &fabricMainChannelInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// FabricNetworkConfigs returns a FabricNetworkConfigInformer.
func (v *version) FabricNetworkConfigs() FabricNetworkConfigInformer {
	return &fabricNetworkConfigInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// FabricOperationsConsoles returns a FabricOperationsConsoleInformer.
func (v *version) FabricOperationsConsoles() FabricOperationsConsoleInformer {
	return &fabricOperationsConsoleInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// FabricOperatorAPIs returns a FabricOperatorAPIInformer.
func (v *version) FabricOperatorAPIs() FabricOperatorAPIInformer {
	return &fabricOperatorAPIInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// FabricOperatorUIs returns a FabricOperatorUIInformer.
func (v *version) FabricOperatorUIs() FabricOperatorUIInformer {
	return &fabricOperatorUIInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// FabricOrdererNodes returns a FabricOrdererNodeInformer.
func (v *version) FabricOrdererNodes() FabricOrdererNodeInformer {
	return &fabricOrdererNodeInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// FabricOrderingServices returns a FabricOrderingServiceInformer.
func (v *version) FabricOrderingServices() FabricOrderingServiceInformer {
	return &fabricOrderingServiceInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// FabricPeers returns a FabricPeerInformer.
func (v *version) FabricPeers() FabricPeerInformer {
	return &fabricPeerInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}
