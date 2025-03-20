---
id: getting-started
title: Getting started
---

There are two types of resources to manage a channel:

- FabricMainChannel
- FabricFollowerChannel

### FabricMainChannel

This resource creates and manages the channel configuration, including:

- Configuration
- Peer organizations
- Orderer organizations

The role of the FabricMainChannel is to manage the channel configuration, you can think of it as the "founder" of the channel.

### FabricFollowerChannel

This resource joins the channel and manages the channel configuration, including:

- Anchor peers
- Peers to join
- Revocation list

The role of the FabricFollowerChannel is to join the channel and manage the channel configuration, you can think of it as organizations that will be joining the channel.


### Wallet

> **Note:** The recommended way to manage identities is to use the FabricIdentity resource. For more information about identity management, see the [Identity Management](../security/revoke-identities.md) section.


For every resource we need a wallet to interact with the network.

The FabricMainChannel requires a wallet with the admin identity of the orderer organization and the peer organizations that will manage the channel.

The FabricFollowerChannel requires a wallet with the admin identity of the peer organization.

## Enroll the orderer admin organization

```bash
CA_NAME=ord-ca
CA_NAMESPACE=default
CA_MSPID=OrdererMSP
CA_TYPE=tlsca # can be `ca` or `tlsca`
kubectl hlf ca register --name=$CA_NAME --namespace=$CA_NAMESPACE --user=admin --secret=adminpw --type=admin \
 --enroll-id enroll --enroll-secret=enrollpw --mspid OrdererMSP

kubectl hlf ca enroll --name=$CA_NAME --namespace=$CA_NAMESPACE \
    --user=admin --secret=adminpw --mspid $CA_MSPID \
    --ca-name $CA_TYPE  --output orderermsp.yaml
```

## Enroll the admin peer organization

```bash
CA_NAME=org1-ca
CA_NAMESPACE=default
CA_MSPID=Org1MSP
CA_TYPE=ca # can be `ca` or `tlsca`
kubectl hlf ca register --name=$CA_NAME --namespace=$CA_NAMESPACE --user=admin --secret=adminpw --type=admin \
 --enroll-id enroll --enroll-secret=enrollpw --mspid Org1MSP

kubectl hlf ca enroll --name=$CA_NAME --namespace=$CA_NAMESPACE \
    --user=admin --secret=adminpw --mspid $CA_MSPID \
    --ca-name $CA_TYPE  --output org1msp.yaml
```

## Create secret

We need to create a secret for the operator to use the certificates to create the channel and update the channel configuration.

```bash
kubectl create secret generic wallet --namespace=default \
        --from-file=org1msp.yaml=$PWD/org1msp.yaml \
        --from-file=orderermsp.yaml=$PWD/orderermsp.yaml
```

## Create the channel

First, we need to obtain the orderer TLS certificate, this would need to be performed for each orderer that is in the consenters list.

```bash
kubectl get fabricorderernodes ord-node1 \
    -o jsonpath='{.status.tlsCert}' > ./orderer-cert.pem
```

Second, we create the main channel CRD and apply it.

```bash
kubectl hlf channelcrd main create \
    --channel-name=demo \
    --name=demo \
    --orderer-orgs=OrdererMSP \
    --peer-orgs=Org1MSP \
    --admin-orderer-orgs=OrdererMSP \
    --admin-peer-orgs=Org1MSP \
    --secret-name=wallet \
    --secret-ns=default \
    --consenters=ord-node1.default:7050 \
    --consenter-certificates=./orderer-cert.pem \
    --identities="OrdererMSP;admin-tls-ordservice.yaml" \
    --identities="Org1MSP;peer-org1.yaml" \
    --consenters=ord-node1.default:7050 --consenter-certificates="orderer0-tls-cert.pem"

```

## Join the channel for Org1MSP

First, we need to obtain the orderer TLS certificate, this would need to be performed for each orderer that is in the consenters list.

```bash
kubectl get fabricorderernodes ord-node1 \
    -o jsonpath='{.status.tlsCert}' > ./orderer-cert.pem
```

Second, we create the main channel CRD and apply it.

```bash
kubectl hlf channelcrd follower create \
    --channel-name=demo \
    --mspid=Org1MSP \
    --name="demo-org1msp" \
    --orderer-certificates="./orderer-cert.pem" \
    --orderer-urls="grpcs://ord-node1.default:7050" \
    --anchor-peers="org1-peer0:7051" \
    --peers="org1-peer0.default" \
    --secret-name=wallet \
    --secret-ns=default \
    --secret-key="peer-org1.yaml"
```
