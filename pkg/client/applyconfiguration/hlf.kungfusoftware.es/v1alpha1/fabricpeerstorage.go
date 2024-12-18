/*
 * Copyright Kungfusoftware.es. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

// FabricPeerStorageApplyConfiguration represents a declarative configuration of the FabricPeerStorage type for use
// with apply.
type FabricPeerStorageApplyConfiguration struct {
	CouchDB   *StorageApplyConfiguration `json:"couchdb,omitempty"`
	Peer      *StorageApplyConfiguration `json:"peer,omitempty"`
	Chaincode *StorageApplyConfiguration `json:"chaincode,omitempty"`
}

// FabricPeerStorageApplyConfiguration constructs a declarative configuration of the FabricPeerStorage type for use with
// apply.
func FabricPeerStorage() *FabricPeerStorageApplyConfiguration {
	return &FabricPeerStorageApplyConfiguration{}
}

// WithCouchDB sets the CouchDB field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the CouchDB field is set to the value of the last call.
func (b *FabricPeerStorageApplyConfiguration) WithCouchDB(value *StorageApplyConfiguration) *FabricPeerStorageApplyConfiguration {
	b.CouchDB = value
	return b
}

// WithPeer sets the Peer field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Peer field is set to the value of the last call.
func (b *FabricPeerStorageApplyConfiguration) WithPeer(value *StorageApplyConfiguration) *FabricPeerStorageApplyConfiguration {
	b.Peer = value
	return b
}

// WithChaincode sets the Chaincode field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Chaincode field is set to the value of the last call.
func (b *FabricPeerStorageApplyConfiguration) WithChaincode(value *StorageApplyConfiguration) *FabricPeerStorageApplyConfiguration {
	b.Chaincode = value
	return b
}
