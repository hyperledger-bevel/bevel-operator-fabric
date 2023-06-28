// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Code generated by client-gen. DO NOT EDIT.

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

// FabricNetworkConfigsGetter has a method to return a FabricNetworkConfigInterface.
// A group's client should implement this interface.
type FabricNetworkConfigsGetter interface {
	FabricNetworkConfigs(namespace string) FabricNetworkConfigInterface
}

// FabricNetworkConfigInterface has methods to work with FabricNetworkConfig resources.
type FabricNetworkConfigInterface interface {
	Create(ctx context.Context, fabricNetworkConfig *v1alpha1.FabricNetworkConfig, opts v1.CreateOptions) (*v1alpha1.FabricNetworkConfig, error)
	Update(ctx context.Context, fabricNetworkConfig *v1alpha1.FabricNetworkConfig, opts v1.UpdateOptions) (*v1alpha1.FabricNetworkConfig, error)
	UpdateStatus(ctx context.Context, fabricNetworkConfig *v1alpha1.FabricNetworkConfig, opts v1.UpdateOptions) (*v1alpha1.FabricNetworkConfig, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.FabricNetworkConfig, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.FabricNetworkConfigList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.FabricNetworkConfig, err error)
	Apply(ctx context.Context, fabricNetworkConfig *hlfkungfusoftwareesv1alpha1.FabricNetworkConfigApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricNetworkConfig, err error)
	ApplyStatus(ctx context.Context, fabricNetworkConfig *hlfkungfusoftwareesv1alpha1.FabricNetworkConfigApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricNetworkConfig, err error)
	FabricNetworkConfigExpansion
}

// fabricNetworkConfigs implements FabricNetworkConfigInterface
type fabricNetworkConfigs struct {
	client rest.Interface
	ns     string
}

// newFabricNetworkConfigs returns a FabricNetworkConfigs
func newFabricNetworkConfigs(c *HlfV1alpha1Client, namespace string) *fabricNetworkConfigs {
	return &fabricNetworkConfigs{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the fabricNetworkConfig, and returns the corresponding fabricNetworkConfig object, and an error if there is any.
func (c *fabricNetworkConfigs) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.FabricNetworkConfig, err error) {
	result = &v1alpha1.FabricNetworkConfig{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("fabricnetworkconfigs").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of FabricNetworkConfigs that match those selectors.
func (c *fabricNetworkConfigs) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.FabricNetworkConfigList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.FabricNetworkConfigList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("fabricnetworkconfigs").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested fabricNetworkConfigs.
func (c *fabricNetworkConfigs) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("fabricnetworkconfigs").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a fabricNetworkConfig and creates it.  Returns the server's representation of the fabricNetworkConfig, and an error, if there is any.
func (c *fabricNetworkConfigs) Create(ctx context.Context, fabricNetworkConfig *v1alpha1.FabricNetworkConfig, opts v1.CreateOptions) (result *v1alpha1.FabricNetworkConfig, err error) {
	result = &v1alpha1.FabricNetworkConfig{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("fabricnetworkconfigs").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(fabricNetworkConfig).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a fabricNetworkConfig and updates it. Returns the server's representation of the fabricNetworkConfig, and an error, if there is any.
func (c *fabricNetworkConfigs) Update(ctx context.Context, fabricNetworkConfig *v1alpha1.FabricNetworkConfig, opts v1.UpdateOptions) (result *v1alpha1.FabricNetworkConfig, err error) {
	result = &v1alpha1.FabricNetworkConfig{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("fabricnetworkconfigs").
		Name(fabricNetworkConfig.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(fabricNetworkConfig).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *fabricNetworkConfigs) UpdateStatus(ctx context.Context, fabricNetworkConfig *v1alpha1.FabricNetworkConfig, opts v1.UpdateOptions) (result *v1alpha1.FabricNetworkConfig, err error) {
	result = &v1alpha1.FabricNetworkConfig{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("fabricnetworkconfigs").
		Name(fabricNetworkConfig.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(fabricNetworkConfig).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the fabricNetworkConfig and deletes it. Returns an error if one occurs.
func (c *fabricNetworkConfigs) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("fabricnetworkconfigs").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *fabricNetworkConfigs) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("fabricnetworkconfigs").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched fabricNetworkConfig.
func (c *fabricNetworkConfigs) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.FabricNetworkConfig, err error) {
	result = &v1alpha1.FabricNetworkConfig{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("fabricnetworkconfigs").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}

// Apply takes the given apply declarative configuration, applies it and returns the applied fabricNetworkConfig.
func (c *fabricNetworkConfigs) Apply(ctx context.Context, fabricNetworkConfig *hlfkungfusoftwareesv1alpha1.FabricNetworkConfigApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricNetworkConfig, err error) {
	if fabricNetworkConfig == nil {
		return nil, fmt.Errorf("fabricNetworkConfig provided to Apply must not be nil")
	}
	patchOpts := opts.ToPatchOptions()
	data, err := json.Marshal(fabricNetworkConfig)
	if err != nil {
		return nil, err
	}
	name := fabricNetworkConfig.Name
	if name == nil {
		return nil, fmt.Errorf("fabricNetworkConfig.Name must be provided to Apply")
	}
	result = &v1alpha1.FabricNetworkConfig{}
	err = c.client.Patch(types.ApplyPatchType).
		Namespace(c.ns).
		Resource("fabricnetworkconfigs").
		Name(*name).
		VersionedParams(&patchOpts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}

// ApplyStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
func (c *fabricNetworkConfigs) ApplyStatus(ctx context.Context, fabricNetworkConfig *hlfkungfusoftwareesv1alpha1.FabricNetworkConfigApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricNetworkConfig, err error) {
	if fabricNetworkConfig == nil {
		return nil, fmt.Errorf("fabricNetworkConfig provided to Apply must not be nil")
	}
	patchOpts := opts.ToPatchOptions()
	data, err := json.Marshal(fabricNetworkConfig)
	if err != nil {
		return nil, err
	}

	name := fabricNetworkConfig.Name
	if name == nil {
		return nil, fmt.Errorf("fabricNetworkConfig.Name must be provided to Apply")
	}

	result = &v1alpha1.FabricNetworkConfig{}
	err = c.client.Patch(types.ApplyPatchType).
		Namespace(c.ns).
		Resource("fabricnetworkconfigs").
		Name(*name).
		SubResource("status").
		VersionedParams(&patchOpts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}