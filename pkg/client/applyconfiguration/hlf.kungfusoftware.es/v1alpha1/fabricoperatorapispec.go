/*
 * Copyright Kungfusoftware.es. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package v1alpha1

import (
	v1 "k8s.io/api/core/v1"
)

// FabricOperatorAPISpecApplyConfiguration represents an declarative configuration of the FabricOperatorAPISpec type for use
// with apply.
type FabricOperatorAPISpecApplyConfiguration struct {
	Image            *string                                       `json:"image,omitempty"`
	Tag              *string                                       `json:"tag,omitempty"`
	ImagePullPolicy  *v1.PullPolicy                                `json:"imagePullPolicy,omitempty"`
	Istio            *FabricIstioApplyConfiguration                `json:"istio,omitempty"`
	Ingress          *IngressApplyConfiguration                    `json:"ingress,omitempty"`
	Replicas         *int                                          `json:"replicas,omitempty"`
	Auth             *FabricOperatorAPIAuthApplyConfiguration      `json:"auth,omitempty"`
	LogoURL          *string                                       `json:"logoUrl,omitempty"`
	HLFConfig        *FabricOperatorAPIHLFConfigApplyConfiguration `json:"hlfConfig,omitempty"`
	Tolerations      []v1.Toleration                               `json:"tolerations,omitempty"`
	ImagePullSecrets []v1.LocalObjectReference                     `json:"imagePullSecrets,omitempty"`
	Env              []v1.EnvVar                                   `json:"env,omitempty"`
	Affinity         *v1.Affinity                                  `json:"affinity,omitempty"`
	Resources        *v1.ResourceRequirements                      `json:"resources,omitempty"`
}

// FabricOperatorAPISpecApplyConfiguration constructs an declarative configuration of the FabricOperatorAPISpec type for use with
// apply.
func FabricOperatorAPISpec() *FabricOperatorAPISpecApplyConfiguration {
	return &FabricOperatorAPISpecApplyConfiguration{}
}

// WithImage sets the Image field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Image field is set to the value of the last call.
func (b *FabricOperatorAPISpecApplyConfiguration) WithImage(value string) *FabricOperatorAPISpecApplyConfiguration {
	b.Image = &value
	return b
}

// WithTag sets the Tag field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Tag field is set to the value of the last call.
func (b *FabricOperatorAPISpecApplyConfiguration) WithTag(value string) *FabricOperatorAPISpecApplyConfiguration {
	b.Tag = &value
	return b
}

// WithImagePullPolicy sets the ImagePullPolicy field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ImagePullPolicy field is set to the value of the last call.
func (b *FabricOperatorAPISpecApplyConfiguration) WithImagePullPolicy(value v1.PullPolicy) *FabricOperatorAPISpecApplyConfiguration {
	b.ImagePullPolicy = &value
	return b
}

// WithIstio sets the Istio field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Istio field is set to the value of the last call.
func (b *FabricOperatorAPISpecApplyConfiguration) WithIstio(value *FabricIstioApplyConfiguration) *FabricOperatorAPISpecApplyConfiguration {
	b.Istio = value
	return b
}

// WithIngress sets the Ingress field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Ingress field is set to the value of the last call.
func (b *FabricOperatorAPISpecApplyConfiguration) WithIngress(value *IngressApplyConfiguration) *FabricOperatorAPISpecApplyConfiguration {
	b.Ingress = value
	return b
}

// WithReplicas sets the Replicas field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Replicas field is set to the value of the last call.
func (b *FabricOperatorAPISpecApplyConfiguration) WithReplicas(value int) *FabricOperatorAPISpecApplyConfiguration {
	b.Replicas = &value
	return b
}

// WithAuth sets the Auth field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Auth field is set to the value of the last call.
func (b *FabricOperatorAPISpecApplyConfiguration) WithAuth(value *FabricOperatorAPIAuthApplyConfiguration) *FabricOperatorAPISpecApplyConfiguration {
	b.Auth = value
	return b
}

// WithLogoURL sets the LogoURL field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the LogoURL field is set to the value of the last call.
func (b *FabricOperatorAPISpecApplyConfiguration) WithLogoURL(value string) *FabricOperatorAPISpecApplyConfiguration {
	b.LogoURL = &value
	return b
}

// WithHLFConfig sets the HLFConfig field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the HLFConfig field is set to the value of the last call.
func (b *FabricOperatorAPISpecApplyConfiguration) WithHLFConfig(value *FabricOperatorAPIHLFConfigApplyConfiguration) *FabricOperatorAPISpecApplyConfiguration {
	b.HLFConfig = value
	return b
}

// WithTolerations adds the given value to the Tolerations field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Tolerations field.
func (b *FabricOperatorAPISpecApplyConfiguration) WithTolerations(values ...v1.Toleration) *FabricOperatorAPISpecApplyConfiguration {
	for i := range values {
		b.Tolerations = append(b.Tolerations, values[i])
	}
	return b
}

// WithImagePullSecrets adds the given value to the ImagePullSecrets field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the ImagePullSecrets field.
func (b *FabricOperatorAPISpecApplyConfiguration) WithImagePullSecrets(values ...v1.LocalObjectReference) *FabricOperatorAPISpecApplyConfiguration {
	for i := range values {
		b.ImagePullSecrets = append(b.ImagePullSecrets, values[i])
	}
	return b
}

// WithEnv adds the given value to the Env field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Env field.
func (b *FabricOperatorAPISpecApplyConfiguration) WithEnv(values ...v1.EnvVar) *FabricOperatorAPISpecApplyConfiguration {
	for i := range values {
		b.Env = append(b.Env, values[i])
	}
	return b
}

// WithAffinity sets the Affinity field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Affinity field is set to the value of the last call.
func (b *FabricOperatorAPISpecApplyConfiguration) WithAffinity(value v1.Affinity) *FabricOperatorAPISpecApplyConfiguration {
	b.Affinity = &value
	return b
}

// WithResources sets the Resources field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Resources field is set to the value of the last call.
func (b *FabricOperatorAPISpecApplyConfiguration) WithResources(value v1.ResourceRequirements) *FabricOperatorAPISpecApplyConfiguration {
	b.Resources = &value
	return b
}
