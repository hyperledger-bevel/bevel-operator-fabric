/*
 * Copyright Kungfusoftware.es. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

// FabricCASigningSignProfileApplyConfiguration represents a declarative configuration of the FabricCASigningSignProfile type for use
// with apply.
type FabricCASigningSignProfileApplyConfiguration struct {
	Usage        []string                                                `json:"usage,omitempty"`
	Expiry       *string                                                 `json:"expiry,omitempty"`
	CAConstraint *FabricCASigningSignProfileConstraintApplyConfiguration `json:"caconstraint,omitempty"`
}

// FabricCASigningSignProfileApplyConfiguration constructs a declarative configuration of the FabricCASigningSignProfile type for use with
// apply.
func FabricCASigningSignProfile() *FabricCASigningSignProfileApplyConfiguration {
	return &FabricCASigningSignProfileApplyConfiguration{}
}

// WithUsage adds the given value to the Usage field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Usage field.
func (b *FabricCASigningSignProfileApplyConfiguration) WithUsage(values ...string) *FabricCASigningSignProfileApplyConfiguration {
	for i := range values {
		b.Usage = append(b.Usage, values[i])
	}
	return b
}

// WithExpiry sets the Expiry field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Expiry field is set to the value of the last call.
func (b *FabricCASigningSignProfileApplyConfiguration) WithExpiry(value string) *FabricCASigningSignProfileApplyConfiguration {
	b.Expiry = &value
	return b
}

// WithCAConstraint sets the CAConstraint field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the CAConstraint field is set to the value of the last call.
func (b *FabricCASigningSignProfileApplyConfiguration) WithCAConstraint(value *FabricCASigningSignProfileConstraintApplyConfiguration) *FabricCASigningSignProfileApplyConfiguration {
	b.CAConstraint = value
	return b
}
