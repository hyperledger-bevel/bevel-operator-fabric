/*
 * Copyright Kungfusoftware.es. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package v1alpha1

// FabricCACSRApplyConfiguration represents an declarative configuration of the FabricCACSR type for use
// with apply.
type FabricCACSRApplyConfiguration struct {
	CN    *string                           `json:"cn,omitempty"`
	Hosts []string                          `json:"hosts,omitempty"`
	Names []FabricCANamesApplyConfiguration `json:"names,omitempty"`
	CA    *FabricCACSRCAApplyConfiguration  `json:"ca,omitempty"`
}

// FabricCACSRApplyConfiguration constructs an declarative configuration of the FabricCACSR type for use with
// apply.
func FabricCACSR() *FabricCACSRApplyConfiguration {
	return &FabricCACSRApplyConfiguration{}
}

// WithCN sets the CN field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the CN field is set to the value of the last call.
func (b *FabricCACSRApplyConfiguration) WithCN(value string) *FabricCACSRApplyConfiguration {
	b.CN = &value
	return b
}

// WithHosts adds the given value to the Hosts field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Hosts field.
func (b *FabricCACSRApplyConfiguration) WithHosts(values ...string) *FabricCACSRApplyConfiguration {
	for i := range values {
		b.Hosts = append(b.Hosts, values[i])
	}
	return b
}

// WithNames adds the given value to the Names field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Names field.
func (b *FabricCACSRApplyConfiguration) WithNames(values ...*FabricCANamesApplyConfiguration) *FabricCACSRApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithNames")
		}
		b.Names = append(b.Names, *values[i])
	}
	return b
}

// WithCA sets the CA field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the CA field is set to the value of the last call.
func (b *FabricCACSRApplyConfiguration) WithCA(value *FabricCACSRCAApplyConfiguration) *FabricCACSRApplyConfiguration {
	b.CA = value
	return b
}
