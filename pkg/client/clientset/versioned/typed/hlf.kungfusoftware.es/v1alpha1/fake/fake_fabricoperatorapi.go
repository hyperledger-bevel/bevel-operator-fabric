/*
 * Copyright Kungfusoftware.es. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fake

import (
	"context"
	json "encoding/json"
	"fmt"

	v1alpha1 "github.com/kfsoftware/hlf-operator/api/hlf.kungfusoftware.es/v1alpha1"
	hlfkungfusoftwareesv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/client/applyconfiguration/hlf.kungfusoftware.es/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeFabricOperatorAPIs implements FabricOperatorAPIInterface
type FakeFabricOperatorAPIs struct {
	Fake *FakeHlfV1alpha1
	ns   string
}

var fabricoperatorapisResource = v1alpha1.SchemeGroupVersion.WithResource("fabricoperatorapis")

var fabricoperatorapisKind = v1alpha1.SchemeGroupVersion.WithKind("FabricOperatorAPI")

// Get takes name of the fabricOperatorAPI, and returns the corresponding fabricOperatorAPI object, and an error if there is any.
func (c *FakeFabricOperatorAPIs) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.FabricOperatorAPI, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(fabricoperatorapisResource, c.ns, name), &v1alpha1.FabricOperatorAPI{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.FabricOperatorAPI), err
}

// List takes label and field selectors, and returns the list of FabricOperatorAPIs that match those selectors.
func (c *FakeFabricOperatorAPIs) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.FabricOperatorAPIList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(fabricoperatorapisResource, fabricoperatorapisKind, c.ns, opts), &v1alpha1.FabricOperatorAPIList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.FabricOperatorAPIList{ListMeta: obj.(*v1alpha1.FabricOperatorAPIList).ListMeta}
	for _, item := range obj.(*v1alpha1.FabricOperatorAPIList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested fabricOperatorAPIs.
func (c *FakeFabricOperatorAPIs) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(fabricoperatorapisResource, c.ns, opts))

}

// Create takes the representation of a fabricOperatorAPI and creates it.  Returns the server's representation of the fabricOperatorAPI, and an error, if there is any.
func (c *FakeFabricOperatorAPIs) Create(ctx context.Context, fabricOperatorAPI *v1alpha1.FabricOperatorAPI, opts v1.CreateOptions) (result *v1alpha1.FabricOperatorAPI, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(fabricoperatorapisResource, c.ns, fabricOperatorAPI), &v1alpha1.FabricOperatorAPI{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.FabricOperatorAPI), err
}

// Update takes the representation of a fabricOperatorAPI and updates it. Returns the server's representation of the fabricOperatorAPI, and an error, if there is any.
func (c *FakeFabricOperatorAPIs) Update(ctx context.Context, fabricOperatorAPI *v1alpha1.FabricOperatorAPI, opts v1.UpdateOptions) (result *v1alpha1.FabricOperatorAPI, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(fabricoperatorapisResource, c.ns, fabricOperatorAPI), &v1alpha1.FabricOperatorAPI{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.FabricOperatorAPI), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeFabricOperatorAPIs) UpdateStatus(ctx context.Context, fabricOperatorAPI *v1alpha1.FabricOperatorAPI, opts v1.UpdateOptions) (*v1alpha1.FabricOperatorAPI, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(fabricoperatorapisResource, "status", c.ns, fabricOperatorAPI), &v1alpha1.FabricOperatorAPI{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.FabricOperatorAPI), err
}

// Delete takes name of the fabricOperatorAPI and deletes it. Returns an error if one occurs.
func (c *FakeFabricOperatorAPIs) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(fabricoperatorapisResource, c.ns, name, opts), &v1alpha1.FabricOperatorAPI{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeFabricOperatorAPIs) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(fabricoperatorapisResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.FabricOperatorAPIList{})
	return err
}

// Patch applies the patch and returns the patched fabricOperatorAPI.
func (c *FakeFabricOperatorAPIs) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.FabricOperatorAPI, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(fabricoperatorapisResource, c.ns, name, pt, data, subresources...), &v1alpha1.FabricOperatorAPI{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.FabricOperatorAPI), err
}

// Apply takes the given apply declarative configuration, applies it and returns the applied fabricOperatorAPI.
func (c *FakeFabricOperatorAPIs) Apply(ctx context.Context, fabricOperatorAPI *hlfkungfusoftwareesv1alpha1.FabricOperatorAPIApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricOperatorAPI, err error) {
	if fabricOperatorAPI == nil {
		return nil, fmt.Errorf("fabricOperatorAPI provided to Apply must not be nil")
	}
	data, err := json.Marshal(fabricOperatorAPI)
	if err != nil {
		return nil, err
	}
	name := fabricOperatorAPI.Name
	if name == nil {
		return nil, fmt.Errorf("fabricOperatorAPI.Name must be provided to Apply")
	}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(fabricoperatorapisResource, c.ns, *name, types.ApplyPatchType, data), &v1alpha1.FabricOperatorAPI{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.FabricOperatorAPI), err
}

// ApplyStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
func (c *FakeFabricOperatorAPIs) ApplyStatus(ctx context.Context, fabricOperatorAPI *hlfkungfusoftwareesv1alpha1.FabricOperatorAPIApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricOperatorAPI, err error) {
	if fabricOperatorAPI == nil {
		return nil, fmt.Errorf("fabricOperatorAPI provided to Apply must not be nil")
	}
	data, err := json.Marshal(fabricOperatorAPI)
	if err != nil {
		return nil, err
	}
	name := fabricOperatorAPI.Name
	if name == nil {
		return nil, fmt.Errorf("fabricOperatorAPI.Name must be provided to Apply")
	}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(fabricoperatorapisResource, c.ns, *name, types.ApplyPatchType, data, "status"), &v1alpha1.FabricOperatorAPI{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.FabricOperatorAPI), err
}
