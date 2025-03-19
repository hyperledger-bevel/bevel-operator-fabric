# Enable GRPC proxy on the orderers
## Enable GRPC proxy for Fabric Operations Console

In order to enable the GRPC Web, needed to connect the peer to the Fabric Operations console, we need to add the `grpcProxy` property with the following attributes:

```yaml
  grpcProxy:
    enabled: true
    image: ghcr.io/hyperledger-labs/grpc-web
    tag: latest
    imagePullPolicy: Always
    istio:
      port: 443
      hosts:
       - <YOUR_HOST>
      ingressGateway: 'ingressgateway'
    resources: 
      limits:
        cpu: '200m'
        memory: 256Mi
      requests:
        cpu: 10m
        memory: 256Mi
```

