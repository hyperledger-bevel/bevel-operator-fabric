/*
 * Copyright Kungfusoftware.es. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package v1alpha1

import (
	v1alpha1 "github.com/kfsoftware/hlf-operator/api/hlf.kungfusoftware.es/v1alpha1"
	status "github.com/kfsoftware/hlf-operator/pkg/status"
)

// FabricCAStatusApplyConfiguration represents an declarative configuration of the FabricCAStatus type for use
// with apply.
type FabricCAStatusApplyConfiguration struct {
	Conditions *status.Conditions         `json:"conditions,omitempty"`
	Message    *string                    `json:"message,omitempty"`
	Status     *v1alpha1.DeploymentStatus `json:"status,omitempty"`
	NodePort   *int                       `json:"nodePort,omitempty"`
	TlsCert    *string                    `json:"tls_cert,omitempty"`
	CACert     *string                    `json:"ca_cert,omitempty"`
	TLSCACert  *string                    `json:"tlsca_cert,omitempty"`
}

// FabricCAStatusApplyConfiguration constructs an declarative configuration of the FabricCAStatus type for use with
// apply.
func FabricCAStatus() *FabricCAStatusApplyConfiguration {
	return &FabricCAStatusApplyConfiguration{}
}

// WithConditions sets the Conditions field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Conditions field is set to the value of the last call.
func (b *FabricCAStatusApplyConfiguration) WithConditions(value status.Conditions) *FabricCAStatusApplyConfiguration {
	b.Conditions = &value
	return b
}

// WithMessage sets the Message field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Message field is set to the value of the last call.
func (b *FabricCAStatusApplyConfiguration) WithMessage(value string) *FabricCAStatusApplyConfiguration {
	b.Message = &value
	return b
}

// WithStatus sets the Status field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Status field is set to the value of the last call.
func (b *FabricCAStatusApplyConfiguration) WithStatus(value v1alpha1.DeploymentStatus) *FabricCAStatusApplyConfiguration {
	b.Status = &value
	return b
}

// WithNodePort sets the NodePort field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the NodePort field is set to the value of the last call.
func (b *FabricCAStatusApplyConfiguration) WithNodePort(value int) *FabricCAStatusApplyConfiguration {
	b.NodePort = &value
	return b
}

// WithTlsCert sets the TlsCert field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the TlsCert field is set to the value of the last call.
func (b *FabricCAStatusApplyConfiguration) WithTlsCert(value string) *FabricCAStatusApplyConfiguration {
	b.TlsCert = &value
	return b
}

// WithCACert sets the CACert field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the CACert field is set to the value of the last call.
func (b *FabricCAStatusApplyConfiguration) WithCACert(value string) *FabricCAStatusApplyConfiguration {
	b.CACert = &value
	return b
}

// WithTLSCACert sets the TLSCACert field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the TLSCACert field is set to the value of the last call.
func (b *FabricCAStatusApplyConfiguration) WithTLSCACert(value string) *FabricCAStatusApplyConfiguration {
	b.TLSCACert = &value
	return b
}
