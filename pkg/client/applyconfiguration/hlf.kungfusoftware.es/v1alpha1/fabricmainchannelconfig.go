/*
 * Copyright Kungfusoftware.es. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package v1alpha1

// FabricMainChannelConfigApplyConfiguration represents an declarative configuration of the FabricMainChannelConfig type for use
// with apply.
type FabricMainChannelConfigApplyConfiguration struct {
	Application  *FabricMainChannelApplicationConfigApplyConfiguration         `json:"application,omitempty"`
	Orderer      *FabricMainChannelOrdererConfigApplyConfiguration             `json:"orderer,omitempty"`
	Capabilities []string                                                      `json:"capabilities,omitempty"`
	Policies     *map[string]FabricMainChannelPoliciesConfigApplyConfiguration `json:"policies,omitempty"`
}

// FabricMainChannelConfigApplyConfiguration constructs an declarative configuration of the FabricMainChannelConfig type for use with
// apply.
func FabricMainChannelConfig() *FabricMainChannelConfigApplyConfiguration {
	return &FabricMainChannelConfigApplyConfiguration{}
}

// WithApplication sets the Application field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Application field is set to the value of the last call.
func (b *FabricMainChannelConfigApplyConfiguration) WithApplication(value *FabricMainChannelApplicationConfigApplyConfiguration) *FabricMainChannelConfigApplyConfiguration {
	b.Application = value
	return b
}

// WithOrderer sets the Orderer field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Orderer field is set to the value of the last call.
func (b *FabricMainChannelConfigApplyConfiguration) WithOrderer(value *FabricMainChannelOrdererConfigApplyConfiguration) *FabricMainChannelConfigApplyConfiguration {
	b.Orderer = value
	return b
}

// WithCapabilities adds the given value to the Capabilities field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Capabilities field.
func (b *FabricMainChannelConfigApplyConfiguration) WithCapabilities(values ...string) *FabricMainChannelConfigApplyConfiguration {
	for i := range values {
		b.Capabilities = append(b.Capabilities, values[i])
	}
	return b
}

// WithPolicies sets the Policies field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Policies field is set to the value of the last call.
func (b *FabricMainChannelConfigApplyConfiguration) WithPolicies(value map[string]FabricMainChannelPoliciesConfigApplyConfiguration) *FabricMainChannelConfigApplyConfiguration {
	b.Policies = &value
	return b
}
