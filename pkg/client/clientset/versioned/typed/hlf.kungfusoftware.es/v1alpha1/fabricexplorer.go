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

// FabricExplorersGetter has a method to return a FabricExplorerInterface.
// A group's client should implement this interface.
type FabricExplorersGetter interface {
	FabricExplorers(namespace string) FabricExplorerInterface
}

// FabricExplorerInterface has methods to work with FabricExplorer resources.
type FabricExplorerInterface interface {
	Create(ctx context.Context, fabricExplorer *v1alpha1.FabricExplorer, opts v1.CreateOptions) (*v1alpha1.FabricExplorer, error)
	Update(ctx context.Context, fabricExplorer *v1alpha1.FabricExplorer, opts v1.UpdateOptions) (*v1alpha1.FabricExplorer, error)
	UpdateStatus(ctx context.Context, fabricExplorer *v1alpha1.FabricExplorer, opts v1.UpdateOptions) (*v1alpha1.FabricExplorer, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.FabricExplorer, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.FabricExplorerList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.FabricExplorer, err error)
	Apply(ctx context.Context, fabricExplorer *hlfkungfusoftwareesv1alpha1.FabricExplorerApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricExplorer, err error)
	ApplyStatus(ctx context.Context, fabricExplorer *hlfkungfusoftwareesv1alpha1.FabricExplorerApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricExplorer, err error)
	FabricExplorerExpansion
}

// fabricExplorers implements FabricExplorerInterface
type fabricExplorers struct {
	client rest.Interface
	ns     string
}

// newFabricExplorers returns a FabricExplorers
func newFabricExplorers(c *HlfV1alpha1Client, namespace string) *fabricExplorers {
	return &fabricExplorers{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the fabricExplorer, and returns the corresponding fabricExplorer object, and an error if there is any.
func (c *fabricExplorers) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.FabricExplorer, err error) {
	result = &v1alpha1.FabricExplorer{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("fabricexplorers").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of FabricExplorers that match those selectors.
func (c *fabricExplorers) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.FabricExplorerList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.FabricExplorerList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("fabricexplorers").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested fabricExplorers.
func (c *fabricExplorers) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("fabricexplorers").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a fabricExplorer and creates it.  Returns the server's representation of the fabricExplorer, and an error, if there is any.
func (c *fabricExplorers) Create(ctx context.Context, fabricExplorer *v1alpha1.FabricExplorer, opts v1.CreateOptions) (result *v1alpha1.FabricExplorer, err error) {
	result = &v1alpha1.FabricExplorer{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("fabricexplorers").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(fabricExplorer).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a fabricExplorer and updates it. Returns the server's representation of the fabricExplorer, and an error, if there is any.
func (c *fabricExplorers) Update(ctx context.Context, fabricExplorer *v1alpha1.FabricExplorer, opts v1.UpdateOptions) (result *v1alpha1.FabricExplorer, err error) {
	result = &v1alpha1.FabricExplorer{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("fabricexplorers").
		Name(fabricExplorer.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(fabricExplorer).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *fabricExplorers) UpdateStatus(ctx context.Context, fabricExplorer *v1alpha1.FabricExplorer, opts v1.UpdateOptions) (result *v1alpha1.FabricExplorer, err error) {
	result = &v1alpha1.FabricExplorer{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("fabricexplorers").
		Name(fabricExplorer.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(fabricExplorer).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the fabricExplorer and deletes it. Returns an error if one occurs.
func (c *fabricExplorers) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("fabricexplorers").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *fabricExplorers) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("fabricexplorers").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched fabricExplorer.
func (c *fabricExplorers) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.FabricExplorer, err error) {
	result = &v1alpha1.FabricExplorer{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("fabricexplorers").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}

// Apply takes the given apply declarative configuration, applies it and returns the applied fabricExplorer.
func (c *fabricExplorers) Apply(ctx context.Context, fabricExplorer *hlfkungfusoftwareesv1alpha1.FabricExplorerApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricExplorer, err error) {
	if fabricExplorer == nil {
		return nil, fmt.Errorf("fabricExplorer provided to Apply must not be nil")
	}
	patchOpts := opts.ToPatchOptions()
	data, err := json.Marshal(fabricExplorer)
	if err != nil {
		return nil, err
	}
	name := fabricExplorer.Name
	if name == nil {
		return nil, fmt.Errorf("fabricExplorer.Name must be provided to Apply")
	}
	result = &v1alpha1.FabricExplorer{}
	err = c.client.Patch(types.ApplyPatchType).
		Namespace(c.ns).
		Resource("fabricexplorers").
		Name(*name).
		VersionedParams(&patchOpts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}

// ApplyStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
func (c *fabricExplorers) ApplyStatus(ctx context.Context, fabricExplorer *hlfkungfusoftwareesv1alpha1.FabricExplorerApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricExplorer, err error) {
	if fabricExplorer == nil {
		return nil, fmt.Errorf("fabricExplorer provided to Apply must not be nil")
	}
	patchOpts := opts.ToPatchOptions()
	data, err := json.Marshal(fabricExplorer)
	if err != nil {
		return nil, err
	}

	name := fabricExplorer.Name
	if name == nil {
		return nil, fmt.Errorf("fabricExplorer.Name must be provided to Apply")
	}

	result = &v1alpha1.FabricExplorer{}
	err = c.client.Patch(types.ApplyPatchType).
		Namespace(c.ns).
		Resource("fabricexplorers").
		Name(*name).
		SubResource("status").
		VersionedParams(&patchOpts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
