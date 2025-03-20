---
id: introduction
title: Introduction
---

## What is the Gateway API?

Gateway API is an open-source project managed by the SIG-NETWORK community. It is a collection of resources that model service networking in Kubernetes. These resources - GatewayClass, Gateway, HTTPRoute, TCPRoute, Service, etc. - aim to evolve Kubernetes service networking through expressive, extensible, and role-oriented interfaces that are implemented by many vendors and have broad industry support.

More about Kubernetes Gateway API: [Gateway API Documentation](https://gateway-api.sigs.k8s.io/)

## Why Gateway API?

Currently, the hlf-operator only supports the Istio service mesh to manage the traffic between various fabric resources like CAs, Orderers, Peers, etc.

This forces one to use the Istio service mesh, despite their organization having already set up and used a different proxy. Some of the most common ones being:

- Traefik
- HAProxy
- Nginx

and many others...

So, to handle this, support for other proxies must be added. Gateway API addresses this issue by providing a generic implementation that can be implemented by various supported vendors like the ones mentioned above.

In other words, now the hlf-network can be set up by various other proxies other than Istio.

More about the supported implementations of Gateway API: [Gateway API Implementations](https://gateway-api.sigs.k8s.io/implementations/)

## How to use the Gateway API?

Refer to the [Getting Started](./getting-started.md) guide to learn how to use the Gateway API with the hlf-operator.

## How to use the Gateway API with the hlf-operator?

Refer to the [Implementation](./implementation.md) guide to learn how to use the Gateway API with the hlf-operator.
