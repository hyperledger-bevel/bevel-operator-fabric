/*
 * Copyright Kungfusoftware.es. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package v1alpha1

// FabricOrderingServiceSpecApplyConfiguration represents an declarative configuration of the FabricOrderingServiceSpec type for use
// with apply.
type FabricOrderingServiceSpecApplyConfiguration struct {
	Image         *string                                 `json:"image,omitempty"`
	Tag           *string                                 `json:"tag,omitempty"`
	MspID         *string                                 `json:"mspID,omitempty"`
	Enrollment    *OrdererEnrollmentApplyConfiguration    `json:"enrollment,omitempty"`
	Nodes         []OrdererNodeApplyConfiguration         `json:"nodes,omitempty"`
	Service       *OrdererServiceApplyConfiguration       `json:"service,omitempty"`
	Storage       *StorageApplyConfiguration              `json:"storage,omitempty"`
	SystemChannel *OrdererSystemChannelApplyConfiguration `json:"systemChannel,omitempty"`
}

// FabricOrderingServiceSpecApplyConfiguration constructs an declarative configuration of the FabricOrderingServiceSpec type for use with
// apply.
func FabricOrderingServiceSpec() *FabricOrderingServiceSpecApplyConfiguration {
	return &FabricOrderingServiceSpecApplyConfiguration{}
}

// WithImage sets the Image field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Image field is set to the value of the last call.
func (b *FabricOrderingServiceSpecApplyConfiguration) WithImage(value string) *FabricOrderingServiceSpecApplyConfiguration {
	b.Image = &value
	return b
}

// WithTag sets the Tag field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Tag field is set to the value of the last call.
func (b *FabricOrderingServiceSpecApplyConfiguration) WithTag(value string) *FabricOrderingServiceSpecApplyConfiguration {
	b.Tag = &value
	return b
}

// WithMspID sets the MspID field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the MspID field is set to the value of the last call.
func (b *FabricOrderingServiceSpecApplyConfiguration) WithMspID(value string) *FabricOrderingServiceSpecApplyConfiguration {
	b.MspID = &value
	return b
}

// WithEnrollment sets the Enrollment field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Enrollment field is set to the value of the last call.
func (b *FabricOrderingServiceSpecApplyConfiguration) WithEnrollment(value *OrdererEnrollmentApplyConfiguration) *FabricOrderingServiceSpecApplyConfiguration {
	b.Enrollment = value
	return b
}

// WithNodes adds the given value to the Nodes field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Nodes field.
func (b *FabricOrderingServiceSpecApplyConfiguration) WithNodes(values ...*OrdererNodeApplyConfiguration) *FabricOrderingServiceSpecApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithNodes")
		}
		b.Nodes = append(b.Nodes, *values[i])
	}
	return b
}

// WithService sets the Service field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Service field is set to the value of the last call.
func (b *FabricOrderingServiceSpecApplyConfiguration) WithService(value *OrdererServiceApplyConfiguration) *FabricOrderingServiceSpecApplyConfiguration {
	b.Service = value
	return b
}

// WithStorage sets the Storage field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Storage field is set to the value of the last call.
func (b *FabricOrderingServiceSpecApplyConfiguration) WithStorage(value *StorageApplyConfiguration) *FabricOrderingServiceSpecApplyConfiguration {
	b.Storage = value
	return b
}

// WithSystemChannel sets the SystemChannel field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the SystemChannel field is set to the value of the last call.
func (b *FabricOrderingServiceSpecApplyConfiguration) WithSystemChannel(value *OrdererSystemChannelApplyConfiguration) *FabricOrderingServiceSpecApplyConfiguration {
	b.SystemChannel = value
	return b
}
