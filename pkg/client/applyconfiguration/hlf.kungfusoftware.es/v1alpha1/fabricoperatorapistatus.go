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

// FabricOperatorAPIStatusApplyConfiguration represents an declarative configuration of the FabricOperatorAPIStatus type for use
// with apply.
type FabricOperatorAPIStatusApplyConfiguration struct {
	Conditions *status.Conditions         `json:"conditions,omitempty"`
	Message    *string                    `json:"message,omitempty"`
	Status     *v1alpha1.DeploymentStatus `json:"status,omitempty"`
}

// FabricOperatorAPIStatusApplyConfiguration constructs an declarative configuration of the FabricOperatorAPIStatus type for use with
// apply.
func FabricOperatorAPIStatus() *FabricOperatorAPIStatusApplyConfiguration {
	return &FabricOperatorAPIStatusApplyConfiguration{}
}

// WithConditions sets the Conditions field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Conditions field is set to the value of the last call.
func (b *FabricOperatorAPIStatusApplyConfiguration) WithConditions(value status.Conditions) *FabricOperatorAPIStatusApplyConfiguration {
	b.Conditions = &value
	return b
}

// WithMessage sets the Message field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Message field is set to the value of the last call.
func (b *FabricOperatorAPIStatusApplyConfiguration) WithMessage(value string) *FabricOperatorAPIStatusApplyConfiguration {
	b.Message = &value
	return b
}

// WithStatus sets the Status field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Status field is set to the value of the last call.
func (b *FabricOperatorAPIStatusApplyConfiguration) WithStatus(value v1alpha1.DeploymentStatus) *FabricOperatorAPIStatusApplyConfiguration {
	b.Status = &value
	return b
}
