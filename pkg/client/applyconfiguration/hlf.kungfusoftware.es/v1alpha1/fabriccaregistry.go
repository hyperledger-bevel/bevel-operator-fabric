/*
 * Copyright Kungfusoftware.es. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

// FabricCARegistryApplyConfiguration represents a declarative configuration of the FabricCARegistry type for use
// with apply.
type FabricCARegistryApplyConfiguration struct {
	MaxEnrollments *int                                 `json:"max_enrollments,omitempty"`
	Identities     []FabricCAIdentityApplyConfiguration `json:"identities,omitempty"`
}

// FabricCARegistryApplyConfiguration constructs a declarative configuration of the FabricCARegistry type for use with
// apply.
func FabricCARegistry() *FabricCARegistryApplyConfiguration {
	return &FabricCARegistryApplyConfiguration{}
}

// WithMaxEnrollments sets the MaxEnrollments field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the MaxEnrollments field is set to the value of the last call.
func (b *FabricCARegistryApplyConfiguration) WithMaxEnrollments(value int) *FabricCARegistryApplyConfiguration {
	b.MaxEnrollments = &value
	return b
}

// WithIdentities adds the given value to the Identities field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Identities field.
func (b *FabricCARegistryApplyConfiguration) WithIdentities(values ...*FabricCAIdentityApplyConfiguration) *FabricCARegistryApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithIdentities")
		}
		b.Identities = append(b.Identities, *values[i])
	}
	return b
}
