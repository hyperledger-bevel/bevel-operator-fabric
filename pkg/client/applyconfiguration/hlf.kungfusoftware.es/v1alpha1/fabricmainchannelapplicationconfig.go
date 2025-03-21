/*
 * Copyright Kungfusoftware.es. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

// FabricMainChannelApplicationConfigApplyConfiguration represents a declarative configuration of the FabricMainChannelApplicationConfig type for use
// with apply.
type FabricMainChannelApplicationConfigApplyConfiguration struct {
	Capabilities []string                                                      `json:"capabilities,omitempty"`
	Policies     *map[string]FabricMainChannelPoliciesConfigApplyConfiguration `json:"policies,omitempty"`
	ACLs         *map[string]string                                            `json:"acls,omitempty"`
}

// FabricMainChannelApplicationConfigApplyConfiguration constructs a declarative configuration of the FabricMainChannelApplicationConfig type for use with
// apply.
func FabricMainChannelApplicationConfig() *FabricMainChannelApplicationConfigApplyConfiguration {
	return &FabricMainChannelApplicationConfigApplyConfiguration{}
}

// WithCapabilities adds the given value to the Capabilities field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Capabilities field.
func (b *FabricMainChannelApplicationConfigApplyConfiguration) WithCapabilities(values ...string) *FabricMainChannelApplicationConfigApplyConfiguration {
	for i := range values {
		b.Capabilities = append(b.Capabilities, values[i])
	}
	return b
}

// WithPolicies sets the Policies field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Policies field is set to the value of the last call.
func (b *FabricMainChannelApplicationConfigApplyConfiguration) WithPolicies(value map[string]FabricMainChannelPoliciesConfigApplyConfiguration) *FabricMainChannelApplicationConfigApplyConfiguration {
	b.Policies = &value
	return b
}

// WithACLs sets the ACLs field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ACLs field is set to the value of the last call.
func (b *FabricMainChannelApplicationConfigApplyConfiguration) WithACLs(value map[string]string) *FabricMainChannelApplicationConfigApplyConfiguration {
	b.ACLs = &value
	return b
}
