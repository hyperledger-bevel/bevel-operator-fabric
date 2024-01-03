/*
 * Copyright Kungfusoftware.es. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package v1alpha1

import (
	"context"
	json "encoding/json"
	"fmt"
	"time"

	v1alpha1 "github.com/kfsoftware/hlf-operator/api/hlf.kungfusoftware.es/v1alpha1"
	hlfkungfusoftwareesv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/client/applyconfiguration/hlf.kungfusoftware.es/v1alpha1"
	scheme "github.com/kfsoftware/hlf-operator/pkg/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// FabricOrdererNodesGetter has a method to return a FabricOrdererNodeInterface.
// A group's client should implement this interface.
type FabricOrdererNodesGetter interface {
	FabricOrdererNodes(namespace string) FabricOrdererNodeInterface
}

// FabricOrdererNodeInterface has methods to work with FabricOrdererNode resources.
type FabricOrdererNodeInterface interface {
	Create(ctx context.Context, fabricOrdererNode *v1alpha1.FabricOrdererNode, opts v1.CreateOptions) (*v1alpha1.FabricOrdererNode, error)
	Update(ctx context.Context, fabricOrdererNode *v1alpha1.FabricOrdererNode, opts v1.UpdateOptions) (*v1alpha1.FabricOrdererNode, error)
	UpdateStatus(ctx context.Context, fabricOrdererNode *v1alpha1.FabricOrdererNode, opts v1.UpdateOptions) (*v1alpha1.FabricOrdererNode, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.FabricOrdererNode, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.FabricOrdererNodeList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.FabricOrdererNode, err error)
	Apply(ctx context.Context, fabricOrdererNode *hlfkungfusoftwareesv1alpha1.FabricOrdererNodeApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricOrdererNode, err error)
	ApplyStatus(ctx context.Context, fabricOrdererNode *hlfkungfusoftwareesv1alpha1.FabricOrdererNodeApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricOrdererNode, err error)
	FabricOrdererNodeExpansion
}

// fabricOrdererNodes implements FabricOrdererNodeInterface
type fabricOrdererNodes struct {
	client rest.Interface
	ns     string
}

// newFabricOrdererNodes returns a FabricOrdererNodes
func newFabricOrdererNodes(c *HlfV1alpha1Client, namespace string) *fabricOrdererNodes {
	return &fabricOrdererNodes{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the fabricOrdererNode, and returns the corresponding fabricOrdererNode object, and an error if there is any.
func (c *fabricOrdererNodes) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.FabricOrdererNode, err error) {
	result = &v1alpha1.FabricOrdererNode{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("fabricorderernodes").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of FabricOrdererNodes that match those selectors.
func (c *fabricOrdererNodes) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.FabricOrdererNodeList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.FabricOrdererNodeList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("fabricorderernodes").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested fabricOrdererNodes.
func (c *fabricOrdererNodes) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("fabricorderernodes").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a fabricOrdererNode and creates it.  Returns the server's representation of the fabricOrdererNode, and an error, if there is any.
func (c *fabricOrdererNodes) Create(ctx context.Context, fabricOrdererNode *v1alpha1.FabricOrdererNode, opts v1.CreateOptions) (result *v1alpha1.FabricOrdererNode, err error) {
	result = &v1alpha1.FabricOrdererNode{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("fabricorderernodes").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(fabricOrdererNode).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a fabricOrdererNode and updates it. Returns the server's representation of the fabricOrdererNode, and an error, if there is any.
func (c *fabricOrdererNodes) Update(ctx context.Context, fabricOrdererNode *v1alpha1.FabricOrdererNode, opts v1.UpdateOptions) (result *v1alpha1.FabricOrdererNode, err error) {
	result = &v1alpha1.FabricOrdererNode{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("fabricorderernodes").
		Name(fabricOrdererNode.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(fabricOrdererNode).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *fabricOrdererNodes) UpdateStatus(ctx context.Context, fabricOrdererNode *v1alpha1.FabricOrdererNode, opts v1.UpdateOptions) (result *v1alpha1.FabricOrdererNode, err error) {
	result = &v1alpha1.FabricOrdererNode{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("fabricorderernodes").
		Name(fabricOrdererNode.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(fabricOrdererNode).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the fabricOrdererNode and deletes it. Returns an error if one occurs.
func (c *fabricOrdererNodes) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("fabricorderernodes").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *fabricOrdererNodes) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("fabricorderernodes").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched fabricOrdererNode.
func (c *fabricOrdererNodes) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.FabricOrdererNode, err error) {
	result = &v1alpha1.FabricOrdererNode{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("fabricorderernodes").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}

// Apply takes the given apply declarative configuration, applies it and returns the applied fabricOrdererNode.
func (c *fabricOrdererNodes) Apply(ctx context.Context, fabricOrdererNode *hlfkungfusoftwareesv1alpha1.FabricOrdererNodeApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricOrdererNode, err error) {
	if fabricOrdererNode == nil {
		return nil, fmt.Errorf("fabricOrdererNode provided to Apply must not be nil")
	}
	patchOpts := opts.ToPatchOptions()
	data, err := json.Marshal(fabricOrdererNode)
	if err != nil {
		return nil, err
	}
	name := fabricOrdererNode.Name
	if name == nil {
		return nil, fmt.Errorf("fabricOrdererNode.Name must be provided to Apply")
	}
	result = &v1alpha1.FabricOrdererNode{}
	err = c.client.Patch(types.ApplyPatchType).
		Namespace(c.ns).
		Resource("fabricorderernodes").
		Name(*name).
		VersionedParams(&patchOpts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}

// ApplyStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
func (c *fabricOrdererNodes) ApplyStatus(ctx context.Context, fabricOrdererNode *hlfkungfusoftwareesv1alpha1.FabricOrdererNodeApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricOrdererNode, err error) {
	if fabricOrdererNode == nil {
		return nil, fmt.Errorf("fabricOrdererNode provided to Apply must not be nil")
	}
	patchOpts := opts.ToPatchOptions()
	data, err := json.Marshal(fabricOrdererNode)
	if err != nil {
		return nil, err
	}

	name := fabricOrdererNode.Name
	if name == nil {
		return nil, fmt.Errorf("fabricOrdererNode.Name must be provided to Apply")
	}

	result = &v1alpha1.FabricOrdererNode{}
	err = c.client.Patch(types.ApplyPatchType).
		Namespace(c.ns).
		Resource("fabricorderernodes").
		Name(*name).
		SubResource("status").
		VersionedParams(&patchOpts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
