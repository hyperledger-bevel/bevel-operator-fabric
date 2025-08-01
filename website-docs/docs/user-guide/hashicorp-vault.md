---
id: hashicorp-vault
title: HashiCorp Vault Integration
---

# HashiCorp Vault Integration with Bevel Operator

This workshop provides a comprehensive, hands-on guide to integrating HashiCorp Vault with the Bevel Operator for Hyperledger Fabric. You'll learn how to securely manage certificates, private keys, and cryptographic materials using Vault's advanced secrets management capabilities.

## Why HashiCorp Vault?

HashiCorp Vault is essential for production Hyperledger Fabric deployments because it provides:

- **Secure Certificate Management**: Centralized storage and lifecycle management of TLS certificates
- **Private Key Protection**: Encrypted storage of sensitive cryptographic materials
- **Dynamic Secrets**: On-demand generation of credentials with automatic rotation
- **Audit Trail**: Complete logging of all secret access for compliance
- **Access Control**: Fine-grained policies for who can access what secrets
- **High Availability**: Clustered deployment for production resilience

## Prerequisites

Before starting this workshop, ensure you have:

- A Kubernetes cluster (KinD, K3D, or production cluster)
- kubectl configured and working
- Helm installed
- HashiCorp Vault CLI installed
- Basic understanding of Hyperledger Fabric concepts

## Workshop Overview

In this workshop, you will:

1. **Set up HashiCorp Vault** - Initialize and configure Vault for certificate management
2. **Configure Bevel Operator** - Install and configure the operator to use Vault
3. **Deploy Certificate Authorities** - Create CAs with Vault-backed certificate storage
4. **Deploy Network Components** - Create peers and orderers using Vault-managed certificates
5. **Create and Manage Channels** - Set up channels with Vault-secured identities
6. **Deploy Chaincode** - Install and instantiate chaincode with secure credential management
7. **Test the Network** - Verify the complete setup works end-to-end

## Getting started

# Tutorial

Resources:
- [Hyperledger Fabric build ARM](https://www.polarsparc.com/xhtml/Hyperledger-ARM-Build.html)

## Create Kubernetes Cluster

To start deploying our red fabric we have to have a Kubernetes cluster. For this we will use KinD.

Ensure you have these ports available before creating the cluster:
- 80
- 443

If these ports are not available this tutorial will not work.

### Using K3D

```bash
k3d cluster create  -p "80:30949@agent:0" -p "443:30950@agent:0" --agents 2 k8s-hlf
```

### Using KinD

```bash
cat << EOF > kind-config.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  image: kindest/node:v1.30.2
  extraPortMappings:
  - containerPort: 30949
    hostPort: 80
  - containerPort: 30950
    hostPort: 443
EOF

kind create cluster --config=./kind-config.yaml

```

## Install Kubernetes operator

In this step we are going to install the kubernetes operator for Fabric, this will install:

- CRD (Custom Resource Definitions) to deploy Certification Fabric Peers, Orderers and Authorities
- Deploy the program to deploy the nodes in Kubernetes

To install helm: [https://helm.sh/docs/intro/install/](https://helm.sh/docs/intro/install/)

```bash
helm repo add kfs https://kfsoftware.github.io/hlf-helm-charts --force-update

helm install hlf-operator --version=1.11.1 -- kfs/hlf-operator
```


### Install the Kubectl plugin

To install the kubectl plugin, you must first install Krew:
[https://krew.sigs.k8s.io/docs/user-guide/setup/install/](https://krew.sigs.k8s.io/docs/user-guide/setup/install/)

Afterwards, the plugin can be installed with the following command:

```bash
kubectl krew install hlf
```

### Install Istio

Install Istio binaries on the machine:
```bash
curl -L https://istio.io/downloadIstio | ISTIO_VERSION=1.23.3 sh -
```

Install Istio on the Kubernetes cluster:

```bash

kubectl create namespace istio-system

export ISTIO_PATH=$(echo $PWD/istio-*/bin)
export PATH="$PATH:$ISTIO_PATH"

istioctl operator init

kubectl apply -f - <<EOF
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
metadata:
  name: istio-gateway
  namespace: istio-system
spec:
  addonComponents:
    grafana:
      enabled: false
    kiali:
      enabled: false
    prometheus:
      enabled: false
    tracing:
      enabled: false
  components:
    ingressGateways:
      - enabled: true
        k8s:
          hpaSpec:
            minReplicas: 1
          resources:
            limits:
              cpu: 500m
              memory: 512Mi
            requests:
              cpu: 100m
              memory: 128Mi
          service:
            ports:
              - name: http
                port: 80
                targetPort: 8080
                nodePort: 30949
              - name: https
                port: 443
                targetPort: 8443
                nodePort: 30950
            type: NodePort
        name: istio-ingressgateway
    pilot:
      enabled: true
      k8s:
        hpaSpec:
          minReplicas: 1
        resources:
          limits:
            cpu: 300m
            memory: 512Mi
          requests:
            cpu: 100m
            memory: 128Mi
  meshConfig:
    accessLogFile: /dev/stdout
    enableTracing: false
    outboundTrafficPolicy:
      mode: ALLOW_ANY
  profile: default

EOF

```


## Install Vault


Here's how to install Vault on Linux:
```bash
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
sudo apt-get update && sudo apt-get install vault
```

Here's how to install Vault on MacOS:
```bash
brew tap hashicorp/tap
brew install hashicorp/tap/vault
```


## Setup Vault server


### With docker
```bash
# Run HashiCorp Vault in development mode (in-memory storage)
docker run -d \
  --name vault-dev \
  -p 8200:8200 \
  -e 'VAULT_DEV_ROOT_TOKEN_ID=my-dev-root-token' \
  -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200' \
  hashicorp/vault:latest
```

### With the CLI 

You'll need to run the following command and leave it running to start the Vault server:

```bash
vault server -dev -dev-root-token-id=my-dev-root-token -dev-listen-address=0.0.0.0:8200
```



## Deploy a `Peer` organization

### Setup certificates for Org1MSP in Vault

```bash
export VAULT_ADDR='http://localhost:8200'
export VAULT_TOKEN='my-dev-root-token'

# Enable PKI secrets engine for peer organization
vault secrets enable -path=pki pki

# Configure PKI settings
vault secrets tune -max-lease-ttl=87600h pki

# Generate root certificate for signing
vault write pki/root/generate/internal \
    common_name="Org1MSP Root Sign CA" \
    ttl=87600h \
    issuer_name="signing-ca" \
    key_type="ec" \
    key_bits=256

# Generate TLS root certificate 
vault write pki/root/generate/internal \
    common_name="Org1MSP TLS Root CA" \
    ttl=87600h \
    issuer_name="tls-ca" \
    key_type="ec" \
    key_bits=256

# Create roles for signing certificates
vault write pki/roles/peer-sign \
    allow_subdomains=true \
    allow_any_name=true \
    max_ttl="87600h" \
    key_type="ec" \
    key_bits=256 \
    ou="peer" \
    organization="Org1MSP" \
    issuer_ref="signing-ca"

vault write pki/roles/orderer-sign \
    allow_subdomains=true \
    allow_any_name=true \
    max_ttl="87600h" \
    key_type="ec" \
    key_bits=256 \
    ou="orderer" \
    organization="Org1MSP" \
    issuer_ref="signing-ca"

vault write pki/roles/client-sign \
    allow_subdomains=true \
    allow_any_name=true \
    max_ttl="87600h" \
    key_type="ec" \
    key_bits=256 \
    ou="client" \
    organization="Org1MSP" \
    issuer_ref="signing-ca"

vault write pki/roles/admin-sign \
    allow_subdomains=true \
    allow_any_name=true \
    max_ttl="87600h" \
    key_type="ec" \
    key_bits=256 \
    ou="admin" \
    organization="Org1MSP" \
    issuer_ref="signing-ca"

# Create roles for TLS certificates
vault write pki/roles/peer-tls \
    issuer_ref="tls-ca" \
    allow_subdomains=true \
    allow_any_name=true \
    max_ttl="87600h" \
    key_type="ec" \
    key_bits=256 \
    ou="peer" \
    organization="Org1MSP"

vault write pki/roles/orderer-tls \
    issuer_ref="tls-ca" \
    allow_subdomains=true \
    allow_any_name=true \
    max_ttl="87600h" \
    key_type="ec" \
    key_bits=256 \
    ou="orderer" \
    organization="Org1MSP"

vault write pki/roles/client-tls \
    issuer_ref="tls-ca" \
    allow_subdomains=true \
    allow_any_name=true \
    max_ttl="87600h" \
    key_type="ec" \
    key_bits=256 \
    ou="client" \
    organization="Org1MSP"

vault write pki/roles/admin-tls \
    issuer_ref="tls-ca" \
    allow_subdomains=true \
    allow_any_name=true \
    max_ttl="87600h" \
    key_type="ec" \
    key_bits=256 \
    ou="admin" \
    organization="Org1MSP"

```


### Environment Variables

```bash
export PEER_IMAGE=hyperledger/fabric-peer
export PEER_VERSION=3.1.0

export ORDERER_IMAGE=hyperledger/fabric-orderer
export ORDERER_VERSION=3.1.0

```

### Configure Internal DNS

```bash
kubectl apply -f - <<EOF
kind: ConfigMap
apiVersion: v1
metadata:
  name: coredns
  namespace: kube-system
data:
  Corefile: |
    .:53 {
        errors
        health {
           lameduck 5s
        }
        rewrite name regex (.*)\.localho\.st istio-ingressgateway.istio-system.svc.cluster.local
        hosts {
          fallthrough
        }
        ready
        kubernetes cluster.local in-addr.arpa ip6.arpa {
           pods insecure
           fallthrough in-addr.arpa ip6.arpa
           ttl 30
        }
        prometheus :9153
        forward . /etc/resolv.conf {
           max_concurrent 1000
        }
        cache 30
        loop
        reload
        loadbalance
    }
EOF
```

### Configure Storage Class
Set storage class depending on the Kubernetes cluster you are using:
```bash
# for Kind
export SC_NAME=standard
# for K3D
export SC_NAME=local-path
```

### Create a secret for hashicorp vault

```bash
kubectl create secret generic vault-token --from-literal=token=my-dev-root-token
```

### Deploy a peer

```bash
# this needs to be accessible from the cluster
export VAULT_ADDR="http://192.168.0.20:8200"

kubectl hlf peer create \
    --statedb=leveldb \
    --image=$PEER_IMAGE \
    --version=$PEER_VERSION \
    --storage-class=$SC_NAME \
    --enroll-id=peer \
    --mspid=Org1MSP \
    --enroll-pw=peerpw \
    --capacity=5Gi \
    --name=org1-peer0 \
    --hosts=peer0-org1.localho.st \
    --istio-port=443 \
    --credential-store=vault \
    --vault-address="$VAULT_ADDR" \
    --vault-token-secret="vault-token" \
    --vault-token-secret-namespace="default" \
    --vault-token-secret-key="token" \
    --vault-pki-path="pki" \
    --vault-role="peer-sign" \
    --vault-ttl="8760h" \
    --tls-vault-address="$VAULT_ADDR" \
    --tls-vault-token-secret="vault-token" \
    --tls-vault-token-secret-namespace="default" \
    --tls-vault-token-secret-key="token" \
    --tls-vault-pki-path="pki" \
    --tls-vault-role="peer-tls" \
    --tls-vault-ttl="8760h"


kubectl wait --timeout=180s --for=condition=Running fabricpeers.hlf.kungfusoftware.es --all
```

Check that the peer is deployed and works:

```bash
openssl s_client -connect peer0-org1.localho.st:443
```

## Deploy an `Orderer` organization

To deploy an `Orderer` organization we have to:

1. Setup CAs in Vault
2. Create orderer

### Setup CAs in Vault

```bash
export VAULT_ADDR='http://localhost:8200'
export VAULT_TOKEN='my-dev-root-token'

# Enable PKI secrets engine for orderer organization
vault secrets enable -path=pki_orderer pki

# Configure PKI settings
vault secrets tune -max-lease-ttl=87600h pki_orderer


# Generate root certificate for signing
vault write pki_orderer/root/generate/internal \
    common_name="OrdererMSP Signing Root CA" \
    ttl=87600h \
    issuer_name="signing-ca" \
    key_type="ec" \
    key_bits=256

# Generate TLS root certificate 
vault write pki_orderer/root/generate/internal \
    common_name="OrdererMSP TLS Root CA" \
    ttl=87600h \
    issuer_name="tls-ca" \
    key_type="ec" \
    key_bits=256

# Create roles for signing certificates
vault write pki_orderer/roles/peer-sign \
    allow_subdomains=true \
    allow_any_name=true \
    max_ttl="87600h" \
    key_type="ec" \
    key_bits=256 \
    ou="peer" \
    organization="OrdererMSP" \
    issuer_ref="signing-ca"

vault write pki_orderer/roles/orderer-sign \
    allow_subdomains=true \
    allow_any_name=true \
    max_ttl="87600h" \
    key_type="ec" \
    key_bits=256 \
    ou="orderer" \
    organization="OrdererMSP" \
    issuer_ref="signing-ca"

vault write pki_orderer/roles/client-sign \
    allow_subdomains=true \
    allow_any_name=true \
    max_ttl="87600h" \
    key_type="ec" \
    key_bits=256 \
    ou="client" \
    organization="OrdererMSP" \
    issuer_ref="signing-ca"

vault write pki_orderer/roles/admin-sign \
    allow_subdomains=true \
    allow_any_name=true \
    max_ttl="87600h" \
    key_type="ec" \
    key_bits=256 \
    ou="admin" \
    organization="OrdererMSP" \
    issuer_ref="signing-ca"

# Create roles for TLS certificates
vault write pki_orderer/roles/peer-tls \
    issuer_ref="tls-ca" \
    allow_subdomains=true \
    allow_any_name=true \
    max_ttl="87600h" \
    key_type="ec" \
    key_bits=256 \
    ou="peer" \
    organization="OrdererMSP"

vault write pki_orderer/roles/orderer-tls \
    issuer_ref="tls-ca" \
    allow_subdomains=true \
    allow_any_name=true \
    max_ttl="87600h" \
    key_type="ec" \
    key_bits=256 \
    ou="orderer" \
    organization="OrdererMSP"

vault write pki_orderer/roles/client-tls \
    issuer_ref="tls-ca" \
    allow_subdomains=true \
    allow_any_name=true \
    max_ttl="87600h" \
    key_type="ec" \
    key_bits=256 \
    ou="client" \
    organization="OrdererMSP"

vault write pki_orderer/roles/admin-tls \
    issuer_ref="tls-ca" \
    allow_subdomains=true \
    allow_any_name=true \
    max_ttl="87600h" \
    key_type="ec" \
    key_bits=256 \
    ou="admin" \
    organization="OrdererMSP"


```

### Deploy orderer

```bash

export VAULT_ADDR="http://192.168.0.20:8200"
export VAULT_TOKEN_NAME="vault-token"
export VAULT_TOKEN_NS="default"
export VAULT_TOKEN_KEY="token"
export VAULT_CA_PATH="pki_orderer"
export VAULT_ROLE_SIGN="orderer-sign"
export VAULT_ROLE_TLS="orderer-tls"


export NODE_NUM=0
kubectl hlf ordnode create \
    --credential-store=vault \
    --image=$ORDERER_IMAGE \
    --version=$ORDERER_VERSION \
    --storage-class=$SC_NAME \
    --enroll-id=orderer \
    --mspid=OrdererMSP \
    --enroll-pw=ordererpw \
    --capacity=2Gi \
    --name=ord-node1 \
    --hosts=orderer${NODE_NUM}-ord.localho.st \
    --admin-hosts=admin-orderer${NODE_NUM}-ord.localho.st \
    --istio-port=443 \
    --vault-address="$VAULT_ADDR" \
    --vault-token-secret="$VAULT_TOKEN_NAME" \
    --vault-token-secret-namespace="$VAULT_TOKEN_NS" \
    --vault-token-secret-key="$VAULT_TOKEN_KEY" \
    --vault-pki-path="$VAULT_CA_PATH" \
    --vault-role="$VAULT_ROLE_SIGN" \
    --vault-ttl="8760h" \
    --tls-vault-address="$VAULT_ADDR" \
    --tls-vault-token-secret="$VAULT_TOKEN_NAME" \
    --tls-vault-token-secret-namespace="$VAULT_TOKEN_NS" \
    --tls-vault-token-secret-key="$VAULT_TOKEN_KEY" \
    --tls-vault-pki-path="$VAULT_CA_PATH" \
    --tls-vault-role="$VAULT_ROLE_TLS" \
    --tls-vault-ttl="8760h"


export NODE_NUM=1
kubectl hlf ordnode create \
    --credential-store=vault \
    --image=$ORDERER_IMAGE \
    --version=$ORDERER_VERSION \
    --storage-class=$SC_NAME \
    --enroll-id=orderer \
    --mspid=OrdererMSP \
    --enroll-pw=ordererpw \
    --capacity=2Gi \
    --name=ord-node2 \
    --hosts=orderer${NODE_NUM}-ord.localho.st \
    --admin-hosts=admin-orderer${NODE_NUM}-ord.localho.st \
    --istio-port=443 \
    --vault-address="$VAULT_ADDR" \
    --vault-token-secret="$VAULT_TOKEN_NAME" \
    --vault-token-secret-namespace="$VAULT_TOKEN_NS" \
    --vault-token-secret-key="$VAULT_TOKEN_KEY" \
    --vault-pki-path="$VAULT_CA_PATH" \
    --vault-role="$VAULT_ROLE_SIGN" \
    --vault-ttl="8760h" \
    --tls-vault-address="$VAULT_ADDR" \
    --tls-vault-token-secret="$VAULT_TOKEN_NAME" \
    --tls-vault-token-secret-namespace="$VAULT_TOKEN_NS" \
    --tls-vault-token-secret-key="$VAULT_TOKEN_KEY" \
    --tls-vault-pki-path="$VAULT_CA_PATH" \
    --tls-vault-role="$VAULT_ROLE_TLS" \
    --tls-vault-ttl="8760h"


export NODE_NUM=2
kubectl hlf ordnode create \
    --credential-store=vault \
    --image=$ORDERER_IMAGE \
    --version=$ORDERER_VERSION \
    --storage-class=$SC_NAME \
    --enroll-id=orderer \
    --mspid=OrdererMSP \
    --enroll-pw=ordererpw \
    --capacity=2Gi \
    --name=ord-node3 \
    --hosts=orderer${NODE_NUM}-ord.localho.st \
    --admin-hosts=admin-orderer${NODE_NUM}-ord.localho.st \
    --istio-port=443 \
    --vault-address="$VAULT_ADDR" \
    --vault-token-secret="$VAULT_TOKEN_NAME" \
    --vault-token-secret-namespace="$VAULT_TOKEN_NS" \
    --vault-token-secret-key="$VAULT_TOKEN_KEY" \
    --vault-pki-path="$VAULT_CA_PATH" \
    --vault-role="$VAULT_ROLE_SIGN" \
    --vault-ttl="8760h" \
    --tls-vault-address="$VAULT_ADDR" \
    --tls-vault-token-secret="$VAULT_TOKEN_NAME" \
    --tls-vault-token-secret-namespace="$VAULT_TOKEN_NS" \
    --tls-vault-token-secret-key="$VAULT_TOKEN_KEY" \
    --tls-vault-pki-path="$VAULT_CA_PATH" \
    --tls-vault-role="$VAULT_ROLE_TLS" \
    --tls-vault-ttl="8760h"


export NODE_NUM=3
kubectl hlf ordnode create \
    --credential-store=vault \
    --image=$ORDERER_IMAGE \
    --version=$ORDERER_VERSION \
    --storage-class=$SC_NAME \
    --enroll-id=orderer \
    --mspid=OrdererMSP \
    --enroll-pw=ordererpw \
    --capacity=2Gi \
    --name=ord-node4 \
    --hosts=orderer${NODE_NUM}-ord.localho.st \
    --admin-hosts=admin-orderer${NODE_NUM}-ord.localho.st \
    --istio-port=443 \
    --vault-address="$VAULT_ADDR" \
    --vault-token-secret="$VAULT_TOKEN_NAME" \
    --vault-token-secret-namespace="$VAULT_TOKEN_NS" \
    --vault-token-secret-key="$VAULT_TOKEN_KEY" \
    --vault-pki-path="$VAULT_CA_PATH" \
    --vault-role="$VAULT_ROLE_SIGN" \
    --vault-ttl="8760h" \
    --tls-vault-address="$VAULT_ADDR" \
    --tls-vault-token-secret="$VAULT_TOKEN_NAME" \
    --tls-vault-token-secret-namespace="$VAULT_TOKEN_NS" \
    --tls-vault-token-secret-key="$VAULT_TOKEN_KEY" \
    --tls-vault-pki-path="$VAULT_CA_PATH" \
    --tls-vault-role="$VAULT_ROLE_TLS" \
    --tls-vault-ttl="8760h"



kubectl wait --timeout=180s --for=condition=Running fabricorderernodes.hlf.kungfusoftware.es --all
```

Check that the orderer is running:

```bash
kubectl get pods
```

```bash
openssl s_client -connect orderer0-ord.localho.st:443
openssl s_client -connect orderer1-ord.localho.st:443
openssl s_client -connect orderer2-ord.localho.st:443
openssl s_client -connect orderer3-ord.localho.st:443
```


## Create channel

To create the channel we need to first create the wallet secret, which will contain the identities used by the operator to manage the channel

### Register and enrolling OrdererMSP identity

```bash

kubectl hlf identity create --name ord-ca-sign --namespace default \
    --mspid OrdererMSP  \
    --credential-store=vault \
    --vault-address="$VAULT_ADDR" \
    --vault-token-secret="vault-token" \
    --vault-token-secret-namespace="default" \
    --vault-token-secret-key="token" \
    --vault-pki-path="pki_orderer" \
    --vault-role="admin-sign" \
    --vault-ttl="8760h"

kubectl hlf identity create --name ord-ca-tls --namespace default \
    --mspid OrdererMSP  \
    --credential-store=vault \
    --vault-address="$VAULT_ADDR" \
    --vault-token-secret="vault-token" \
    --vault-token-secret-namespace="default" \
    --vault-token-secret-key="token" \
    --vault-pki-path="pki_orderer" \
    --vault-role="admin-tls" \
    --vault-ttl="8760h"

```


### Register and enrolling Org1MSP identity

```bash
# enroll
kubectl hlf identity create --name org1-admin --namespace default \
    --mspid Org1MSP  \
    --credential-store=vault \
    --vault-address="$VAULT_ADDR" \
    --vault-token-secret="vault-token" \
    --vault-token-secret-namespace="default" \
    --vault-token-secret-key="token" \
    --vault-pki-path="pki" \
    --vault-role="admin-sign" \
    --vault-ttl="8760h"

```

### Create main channel

```bash

export PEER_ORG_SIGN_CERT=$(vault read pki/issuer/signing-ca --format=json | jq -r '.data.certificate' | sed -e "s/^/${IDENT_8}/" )
export PEER_ORG_TLS_CERT=$(vault read pki/issuer/tls-ca --format=json | jq -r '.data.certificate' | sed -e "s/^/${IDENT_8}/" )

export IDENT_8=$(printf "%8s" "")
export ORDERER_TLS_CERT=$(vault read pki_orderer/issuer/tls-ca --format=json | jq -r '.data.certificate' | sed -e "s/^/${IDENT_8}/" )
export ORDERER_SIGN_CERT=$(vault read pki_orderer/issuer/signing-ca --format=json | jq -r '.data.certificate' | sed -e "s/^/${IDENT_8}/" )


export ORDERER0_TLS_CERT=$(kubectl get fabricorderernodes ord-node1 -o=jsonpath='{.status.tlsCert}' | sed -e "s/^/${IDENT_8}/" )
export ORDERER1_TLS_CERT=$(kubectl get fabricorderernodes ord-node2 -o=jsonpath='{.status.tlsCert}' | sed -e "s/^/${IDENT_8}/" )
export ORDERER2_TLS_CERT=$(kubectl get fabricorderernodes ord-node3 -o=jsonpath='{.status.tlsCert}' | sed -e "s/^/${IDENT_8}/" )
export ORDERER3_TLS_CERT=$(kubectl get fabricorderernodes ord-node4 -o=jsonpath='{.status.tlsCert}' | sed -e "s/^/${IDENT_8}/" )

kubectl apply -f - <<EOF
apiVersion: hlf.kungfusoftware.es/v1alpha1
kind: FabricMainChannel
metadata:
  name: demo
spec:
  name: demo
  adminOrdererOrganizations:
    - mspID: OrdererMSP
  adminPeerOrganizations:
    - mspID: Org1MSP
  channelConfig:
    application:
      acls: null
      capabilities:
        - V2_0
        - V2_5
      policies: null
    capabilities:
      - V2_0
    orderer:
      batchSize:
        absoluteMaxBytes: 1048576
        maxMessageCount: 10
        preferredMaxBytes: 524288
      batchTimeout: 2s
      capabilities:
        - V2_0
      etcdRaft:
        options:
          electionTick: 10
          heartbeatTick: 1
          maxInflightBlocks: 5
          snapshotIntervalSize: 16777216
          tickInterval: 500ms
      ordererType: etcdraft
      policies: null
      state: STATE_NORMAL
    policies: null
  externalOrdererOrganizations: []
  externalPeerOrganizations: []
  peerOrganizations:
    - mspID: Org1MSP
      signCACert: |
${PEER_ORG_SIGN_CERT}
      tlsCACert: |
${PEER_ORG_TLS_CERT}

  identities:
    OrdererMSP-tls:
      secretKey: user.yaml
      secretName: ord-ca-tls
      secretNamespace: default
    OrdererMSP-sign:
      secretKey: user.yaml
      secretName: ord-ca-sign
      secretNamespace: default
    Org1MSP:
      secretKey: user.yaml
      secretName: org1-admin
      secretNamespace: default

  ordererOrganizations:
    - externalOrderersToJoin:
        - host: ord-node1.default
          port: 7053
        - host: ord-node2.default
          port: 7053
        - host: ord-node3.default
          port: 7053
        - host: ord-node4.default
          port: 7053
      tlsCACert: |
${ORDERER_TLS_CERT}
      signCACert: |
${ORDERER_SIGN_CERT}
      mspID: OrdererMSP
      ordererEndpoints:
        - orderer0-ord.localho.st:443
        - orderer1-ord.localho.st:443
        - orderer2-ord.localho.st:443
        - orderer3-ord.localho.st:443
      orderersToJoin: []
  orderers:
    - host: orderer0-ord.localho.st
      port: 443
      tlsCert: |-
${ORDERER0_TLS_CERT}
    - host: orderer1-ord.localho.st
      port: 443
      tlsCert: |-
${ORDERER1_TLS_CERT}
    - host: orderer2-ord.localho.st
      port: 443
      tlsCert: |-
${ORDERER2_TLS_CERT}
    - host: orderer3-ord.localho.st
      port: 443
      tlsCert: |-
${ORDERER3_TLS_CERT}

EOF

```

## Join peer to the channel

```bash

export IDENT_8=$(printf "%8s" "")
export ORDERER0_TLS_CERT=$(kubectl get fabricorderernodes ord-node1 -o=jsonpath='{.status.tlsCert}' | sed -e "s/^/${IDENT_8}/" )

kubectl apply -f - <<EOF
apiVersion: hlf.kungfusoftware.es/v1alpha1
kind: FabricFollowerChannel
metadata:
  name: demo-org1msp
spec:
  anchorPeers:
    - host: peer0-org1.localho.st
      port: 443
  hlfIdentity:
    secretKey: user.yaml
    secretName: org1-admin
    secretNamespace: default
  mspId: Org1MSP
  name: demo
  externalPeersToJoin: []
  orderers:
    - certificate: |
${ORDERER0_TLS_CERT}
      url: grpcs://orderer0-ord.localho.st:443
  peersToJoin:
    - name: org1-peer0
      namespace: default
EOF


```

## Install a chaincode

### Prepare connection string for a peer

To prepare the connection string, we have to:

1. Create network config connection string for organization Org1MSP and OrdererMSP
2. Get the network config from the cluster


1. Register a user in the certification authority for signing

```bash
kubectl hlf networkconfig create --name=org1-cp \
  -o Org1MSP -o OrdererMSP -c demo \
  --identities=org1-admin.default --secret=org1-cp  
```

1. Get the certificates using the user created above
```bash
kubectl get secret org1-cp -o jsonpath="{.data.config\.yaml}" | base64 --decode > org1.yaml

```

### Create metadata file

```bash
# remove the code.tar.gz chaincode.tgz if they exist
rm code.tar.gz chaincode.tgz
export CHAINCODE_NAME=asset
export CHAINCODE_LABEL=asset
cat << METADATA-EOF > "metadata.json"
{
    "type": "ccaas",
    "label": "${CHAINCODE_LABEL}"
}
METADATA-EOF
## chaincode as a service
```

### Prepare connection file

```bash
cat > "connection.json" <<CONN_EOF
{
  "address": "${CHAINCODE_NAME}:7052",
  "dial_timeout": "10s",
  "tls_required": false
}
CONN_EOF

tar cfz code.tar.gz connection.json
tar cfz chaincode.tgz metadata.json code.tar.gz
export PACKAGE_ID=$(kubectl hlf chaincode calculatepackageid --path=chaincode.tgz --language=node --label=$CHAINCODE_LABEL)
echo "PACKAGE_ID=$PACKAGE_ID"

kubectl hlf chaincode install --path=./chaincode.tgz \
    --config=org1.yaml --language=golang --label=$CHAINCODE_LABEL --user=org1-admin-default --peer=org1-peer0.default

```


## Deploy chaincode container on cluster
The following command will create or update the CRD based on the packageID, chaincode name, and docker image.

```bash
kubectl hlf externalchaincode sync --image=kfsoftware/chaincode-external:latest \
    --name=$CHAINCODE_NAME \
    --namespace=default \
    --package-id=$PACKAGE_ID \
    --tls-required=false \
    --replicas=1
```


## Check installed chaincodes
```bash
kubectl hlf chaincode queryinstalled --config=org1.yaml --user=org1-admin-default --peer=org1-peer0.default
```

## Approve chaincode
```bash
export SEQUENCE=1
export VERSION="1.0"
kubectl hlf chaincode approveformyorg --config=org1.yaml --user=org1-admin-default --peer=org1-peer0.default \
    --package-id=$PACKAGE_ID \
    --version "$VERSION" --sequence "$SEQUENCE" --name=asset \
    --policy="OR('Org1MSP.member')" --channel=demo

```

## Commit chaincode
```bash
kubectl hlf chaincode commit --config=org1.yaml --user=org1-admin-default --mspid=Org1MSP \
    --version "$VERSION" --sequence "$SEQUENCE" --name=asset \
    --policy="OR('Org1MSP.member')" --channel=demo
```


## Invoke a transaction on the channel

```bash
kubectl hlf chaincode invoke --config=org1.yaml \
    --user=org1-admin-default --peer=org1-peer0.default \
    --chaincode=asset --channel=demo \
    --fcn=initLedger -a '[]'
```

## Query assets in the channel

```bash
kubectl hlf chaincode query --config=org1.yaml \
    --user=org1-admin-default --peer=org1-peer0.default \
    --chaincode=asset --channel=demo \
    --fcn=GetAllAssets -a '[]'
```


At this point, you should have:

- Ordering service with 1 nodes and a CA
- Peer organization with a peer and a CA
- A channel **demo**
- A chaincode install in peer0
- A chaincode approved and committed

If something went wrong or didn't work, please, open an issue.


## Cleanup the environment

```bash
kubectl delete fabricorderernodes.hlf.kungfusoftware.es --all-namespaces --all
kubectl delete fabricpeers.hlf.kungfusoftware.es --all-namespaces --all
kubectl delete fabriccas.hlf.kungfusoftware.es --all-namespaces --all
kubectl delete fabricchaincode.hlf.kungfusoftware.es --all-namespaces --all
kubectl delete fabricmainchannels --all-namespaces --all
kubectl delete fabricfollowerchannels --all-namespaces --all
```

## Troubleshooting

### Chaincode installation/build error

Chaincode installation/build can fail due to unsupported local kubertenes version such as [minikube](https://github.com/kubernetes/minikube).

```shell
$ kubectl hlf chaincode install --path=./fixtures/chaincodes/fabcar/go \
        --config=org1.yaml --language=golang --label=fabcar --user=org1-admin-default --peer=org1-peer0.default

Error: Transaction processing for endorser [192.168.49.2:31278]: Chaincode status Code: (500) UNKNOWN.
Description: failed to invoke backing implementation of 'InstallChaincode': could not build chaincode:
external builder failed: external builder failed to build: external builder 'my-golang-builder' failed:
exit status 1
```

If your purpose is to test the hlf-operator please consider to switch to [kind](https://github.com/kubernetes-sigs/kind) that is tested and supported.
