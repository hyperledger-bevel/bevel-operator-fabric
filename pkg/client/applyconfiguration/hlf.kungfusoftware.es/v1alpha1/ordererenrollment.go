/*
 * Copyright Kungfusoftware.es. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package v1alpha1

// OrdererEnrollmentApplyConfiguration represents an declarative configuration of the OrdererEnrollment type for use
// with apply.
type OrdererEnrollmentApplyConfiguration struct {
	Component *ComponentApplyConfiguration `json:"component,omitempty"`
	TLS       *TLSApplyConfiguration       `json:"tls,omitempty"`
}

// OrdererEnrollmentApplyConfiguration constructs an declarative configuration of the OrdererEnrollment type for use with
// apply.
func OrdererEnrollment() *OrdererEnrollmentApplyConfiguration {
	return &OrdererEnrollmentApplyConfiguration{}
}

// WithComponent sets the Component field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Component field is set to the value of the last call.
func (b *OrdererEnrollmentApplyConfiguration) WithComponent(value *ComponentApplyConfiguration) *OrdererEnrollmentApplyConfiguration {
	b.Component = value
	return b
}

// WithTLS sets the TLS field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the TLS field is set to the value of the last call.
func (b *OrdererEnrollmentApplyConfiguration) WithTLS(value *TLSApplyConfiguration) *OrdererEnrollmentApplyConfiguration {
	b.TLS = value
	return b
}
