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

// FabricPeersGetter has a method to return a FabricPeerInterface.
// A group's client should implement this interface.
type FabricPeersGetter interface {
	FabricPeers(namespace string) FabricPeerInterface
}

// FabricPeerInterface has methods to work with FabricPeer resources.
type FabricPeerInterface interface {
	Create(ctx context.Context, fabricPeer *v1alpha1.FabricPeer, opts v1.CreateOptions) (*v1alpha1.FabricPeer, error)
	Update(ctx context.Context, fabricPeer *v1alpha1.FabricPeer, opts v1.UpdateOptions) (*v1alpha1.FabricPeer, error)
	UpdateStatus(ctx context.Context, fabricPeer *v1alpha1.FabricPeer, opts v1.UpdateOptions) (*v1alpha1.FabricPeer, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.FabricPeer, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.FabricPeerList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.FabricPeer, err error)
	Apply(ctx context.Context, fabricPeer *hlfkungfusoftwareesv1alpha1.FabricPeerApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricPeer, err error)
	ApplyStatus(ctx context.Context, fabricPeer *hlfkungfusoftwareesv1alpha1.FabricPeerApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricPeer, err error)
	FabricPeerExpansion
}

// fabricPeers implements FabricPeerInterface
type fabricPeers struct {
	client rest.Interface
	ns     string
}

// newFabricPeers returns a FabricPeers
func newFabricPeers(c *HlfV1alpha1Client, namespace string) *fabricPeers {
	return &fabricPeers{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the fabricPeer, and returns the corresponding fabricPeer object, and an error if there is any.
func (c *fabricPeers) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.FabricPeer, err error) {
	result = &v1alpha1.FabricPeer{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("fabricpeers").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of FabricPeers that match those selectors.
func (c *fabricPeers) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.FabricPeerList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.FabricPeerList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("fabricpeers").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested fabricPeers.
func (c *fabricPeers) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("fabricpeers").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a fabricPeer and creates it.  Returns the server's representation of the fabricPeer, and an error, if there is any.
func (c *fabricPeers) Create(ctx context.Context, fabricPeer *v1alpha1.FabricPeer, opts v1.CreateOptions) (result *v1alpha1.FabricPeer, err error) {
	result = &v1alpha1.FabricPeer{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("fabricpeers").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(fabricPeer).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a fabricPeer and updates it. Returns the server's representation of the fabricPeer, and an error, if there is any.
func (c *fabricPeers) Update(ctx context.Context, fabricPeer *v1alpha1.FabricPeer, opts v1.UpdateOptions) (result *v1alpha1.FabricPeer, err error) {
	result = &v1alpha1.FabricPeer{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("fabricpeers").
		Name(fabricPeer.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(fabricPeer).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *fabricPeers) UpdateStatus(ctx context.Context, fabricPeer *v1alpha1.FabricPeer, opts v1.UpdateOptions) (result *v1alpha1.FabricPeer, err error) {
	result = &v1alpha1.FabricPeer{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("fabricpeers").
		Name(fabricPeer.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(fabricPeer).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the fabricPeer and deletes it. Returns an error if one occurs.
func (c *fabricPeers) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("fabricpeers").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *fabricPeers) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("fabricpeers").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched fabricPeer.
func (c *fabricPeers) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.FabricPeer, err error) {
	result = &v1alpha1.FabricPeer{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("fabricpeers").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}

// Apply takes the given apply declarative configuration, applies it and returns the applied fabricPeer.
func (c *fabricPeers) Apply(ctx context.Context, fabricPeer *hlfkungfusoftwareesv1alpha1.FabricPeerApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricPeer, err error) {
	if fabricPeer == nil {
		return nil, fmt.Errorf("fabricPeer provided to Apply must not be nil")
	}
	patchOpts := opts.ToPatchOptions()
	data, err := json.Marshal(fabricPeer)
	if err != nil {
		return nil, err
	}
	name := fabricPeer.Name
	if name == nil {
		return nil, fmt.Errorf("fabricPeer.Name must be provided to Apply")
	}
	result = &v1alpha1.FabricPeer{}
	err = c.client.Patch(types.ApplyPatchType).
		Namespace(c.ns).
		Resource("fabricpeers").
		Name(*name).
		VersionedParams(&patchOpts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}

// ApplyStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
func (c *fabricPeers) ApplyStatus(ctx context.Context, fabricPeer *hlfkungfusoftwareesv1alpha1.FabricPeerApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricPeer, err error) {
	if fabricPeer == nil {
		return nil, fmt.Errorf("fabricPeer provided to Apply must not be nil")
	}
	patchOpts := opts.ToPatchOptions()
	data, err := json.Marshal(fabricPeer)
	if err != nil {
		return nil, err
	}

	name := fabricPeer.Name
	if name == nil {
		return nil, fmt.Errorf("fabricPeer.Name must be provided to Apply")
	}

	result = &v1alpha1.FabricPeer{}
	err = c.client.Patch(types.ApplyPatchType).
		Namespace(c.ns).
		Resource("fabricpeers").
		Name(*name).
		SubResource("status").
		VersionedParams(&patchOpts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
