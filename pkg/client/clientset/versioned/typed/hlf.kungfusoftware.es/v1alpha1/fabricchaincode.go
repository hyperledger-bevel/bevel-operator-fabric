/*
 * Copyright Kungfusoftware.es. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"

	v1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	hlfkungfusoftwareesv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/client/applyconfiguration/hlf.kungfusoftware.es/v1alpha1"
	scheme "github.com/kfsoftware/hlf-operator/pkg/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
)

// FabricChaincodesGetter has a method to return a FabricChaincodeInterface.
// A group's client should implement this interface.
type FabricChaincodesGetter interface {
	FabricChaincodes(namespace string) FabricChaincodeInterface
}

// FabricChaincodeInterface has methods to work with FabricChaincode resources.
type FabricChaincodeInterface interface {
	Create(ctx context.Context, fabricChaincode *v1alpha1.FabricChaincode, opts v1.CreateOptions) (*v1alpha1.FabricChaincode, error)
	Update(ctx context.Context, fabricChaincode *v1alpha1.FabricChaincode, opts v1.UpdateOptions) (*v1alpha1.FabricChaincode, error)
	// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
	UpdateStatus(ctx context.Context, fabricChaincode *v1alpha1.FabricChaincode, opts v1.UpdateOptions) (*v1alpha1.FabricChaincode, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.FabricChaincode, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.FabricChaincodeList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.FabricChaincode, err error)
	Apply(ctx context.Context, fabricChaincode *hlfkungfusoftwareesv1alpha1.FabricChaincodeApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricChaincode, err error)
	// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
	ApplyStatus(ctx context.Context, fabricChaincode *hlfkungfusoftwareesv1alpha1.FabricChaincodeApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricChaincode, err error)
	FabricChaincodeExpansion
}

// fabricChaincodes implements FabricChaincodeInterface
type fabricChaincodes struct {
	*gentype.ClientWithListAndApply[*v1alpha1.FabricChaincode, *v1alpha1.FabricChaincodeList, *hlfkungfusoftwareesv1alpha1.FabricChaincodeApplyConfiguration]
}

// newFabricChaincodes returns a FabricChaincodes
func newFabricChaincodes(c *HlfV1alpha1Client, namespace string) *fabricChaincodes {
	return &fabricChaincodes{
		gentype.NewClientWithListAndApply[*v1alpha1.FabricChaincode, *v1alpha1.FabricChaincodeList, *hlfkungfusoftwareesv1alpha1.FabricChaincodeApplyConfiguration](
			"fabricchaincodes",
			c.RESTClient(),
			scheme.ParameterCodec,
			namespace,
			func() *v1alpha1.FabricChaincode { return &v1alpha1.FabricChaincode{} },
			func() *v1alpha1.FabricChaincodeList { return &v1alpha1.FabricChaincodeList{} }),
	}
}
