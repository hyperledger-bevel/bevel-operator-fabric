/*
 * Copyright Kungfusoftware.es. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

// FabricFollowerChannelPeerApplyConfiguration represents a declarative configuration of the FabricFollowerChannelPeer type for use
// with apply.
type FabricFollowerChannelPeerApplyConfiguration struct {
	Name      *string `json:"name,omitempty"`
	Namespace *string `json:"namespace,omitempty"`
}

// FabricFollowerChannelPeerApplyConfiguration constructs a declarative configuration of the FabricFollowerChannelPeer type for use with
// apply.
func FabricFollowerChannelPeer() *FabricFollowerChannelPeerApplyConfiguration {
	return &FabricFollowerChannelPeerApplyConfiguration{}
}

// WithName sets the Name field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Name field is set to the value of the last call.
func (b *FabricFollowerChannelPeerApplyConfiguration) WithName(value string) *FabricFollowerChannelPeerApplyConfiguration {
	b.Name = &value
	return b
}

// WithNamespace sets the Namespace field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Namespace field is set to the value of the last call.
func (b *FabricFollowerChannelPeerApplyConfiguration) WithNamespace(value string) *FabricFollowerChannelPeerApplyConfiguration {
	b.Namespace = &value
	return b
}
