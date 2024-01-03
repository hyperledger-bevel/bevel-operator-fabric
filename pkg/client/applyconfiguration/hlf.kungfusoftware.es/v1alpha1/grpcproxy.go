/*
 * Copyright Kungfusoftware.es. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package v1alpha1

import (
	v1 "k8s.io/api/core/v1"
)

// GRPCProxyApplyConfiguration represents an declarative configuration of the GRPCProxy type for use
// with apply.
type GRPCProxyApplyConfiguration struct {
	Enabled          *bool                          `json:"enabled,omitempty"`
	Image            *string                        `json:"image,omitempty"`
	Tag              *string                        `json:"tag,omitempty"`
	Istio            *FabricIstioApplyConfiguration `json:"istio,omitempty"`
	ImagePullPolicy  *v1.PullPolicy                 `json:"imagePullPolicy,omitempty"`
	Resources        *v1.ResourceRequirements       `json:"resources,omitempty"`
	ImagePullSecrets []v1.LocalObjectReference      `json:"imagePullSecrets,omitempty"`
}

// GRPCProxyApplyConfiguration constructs an declarative configuration of the GRPCProxy type for use with
// apply.
func GRPCProxy() *GRPCProxyApplyConfiguration {
	return &GRPCProxyApplyConfiguration{}
}

// WithEnabled sets the Enabled field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Enabled field is set to the value of the last call.
func (b *GRPCProxyApplyConfiguration) WithEnabled(value bool) *GRPCProxyApplyConfiguration {
	b.Enabled = &value
	return b
}

// WithImage sets the Image field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Image field is set to the value of the last call.
func (b *GRPCProxyApplyConfiguration) WithImage(value string) *GRPCProxyApplyConfiguration {
	b.Image = &value
	return b
}

// WithTag sets the Tag field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Tag field is set to the value of the last call.
func (b *GRPCProxyApplyConfiguration) WithTag(value string) *GRPCProxyApplyConfiguration {
	b.Tag = &value
	return b
}

// WithIstio sets the Istio field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Istio field is set to the value of the last call.
func (b *GRPCProxyApplyConfiguration) WithIstio(value *FabricIstioApplyConfiguration) *GRPCProxyApplyConfiguration {
	b.Istio = value
	return b
}

// WithImagePullPolicy sets the ImagePullPolicy field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ImagePullPolicy field is set to the value of the last call.
func (b *GRPCProxyApplyConfiguration) WithImagePullPolicy(value v1.PullPolicy) *GRPCProxyApplyConfiguration {
	b.ImagePullPolicy = &value
	return b
}

// WithResources sets the Resources field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Resources field is set to the value of the last call.
func (b *GRPCProxyApplyConfiguration) WithResources(value v1.ResourceRequirements) *GRPCProxyApplyConfiguration {
	b.Resources = &value
	return b
}

// WithImagePullSecrets adds the given value to the ImagePullSecrets field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the ImagePullSecrets field.
func (b *GRPCProxyApplyConfiguration) WithImagePullSecrets(values ...v1.LocalObjectReference) *GRPCProxyApplyConfiguration {
	for i := range values {
		b.ImagePullSecrets = append(b.ImagePullSecrets, values[i])
	}
	return b
}
