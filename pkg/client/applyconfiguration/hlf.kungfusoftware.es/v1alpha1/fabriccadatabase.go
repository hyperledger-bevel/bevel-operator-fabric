/*
 * Copyright Kungfusoftware.es. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package v1alpha1

// FabricCADatabaseApplyConfiguration represents an declarative configuration of the FabricCADatabase type for use
// with apply.
type FabricCADatabaseApplyConfiguration struct {
	Type       *string `json:"type,omitempty"`
	Datasource *string `json:"datasource,omitempty"`
}

// FabricCADatabaseApplyConfiguration constructs an declarative configuration of the FabricCADatabase type for use with
// apply.
func FabricCADatabase() *FabricCADatabaseApplyConfiguration {
	return &FabricCADatabaseApplyConfiguration{}
}

// WithType sets the Type field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Type field is set to the value of the last call.
func (b *FabricCADatabaseApplyConfiguration) WithType(value string) *FabricCADatabaseApplyConfiguration {
	b.Type = &value
	return b
}

// WithDatasource sets the Datasource field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Datasource field is set to the value of the last call.
func (b *FabricCADatabaseApplyConfiguration) WithDatasource(value string) *FabricCADatabaseApplyConfiguration {
	b.Datasource = &value
	return b
}
