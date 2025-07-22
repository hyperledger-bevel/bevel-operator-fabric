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

## Step 1: Install HashiCorp Vault

### Why This Step Matters

Vault serves as the foundation for all cryptographic material management in your Hyperledger Fabric network. Installing it first ensures you have a secure, centralized location for storing certificates and private keys.

### Installation Options

#### Option A: Using Docker (Recommended for Development)

```bash
# Run HashiCorp Vault in development mode
docker run -d \
  --name vault-dev \
  -p 8200:8200 \
  -e 'VAULT_DEV_ROOT_TOKEN_ID=my-dev-root-token' \
  -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200' \
  hashicorp/vault:latest
```

#### Option B: Using Vault CLI

```bash
# Start Vault server in development mode
vault server -dev -dev-root-token-id=my-dev-root-token -dev-listen-address=0.0.0.0:8200
```

#### Option C: Production Installation

For production environments, install Vault using your preferred method:

**Linux:**
```bash
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
sudo apt-get update && sudo apt-get install vault
```

**macOS:**
```bash
brew tap hashicorp/tap
brew install hashicorp/tap/vault
```

### Verify Vault Installation

```bash
# Set environment variables
export VAULT_ADDR='http://localhost:8200'
export VAULT_TOKEN='my-dev-root-token'

# Check Vault status
vault status
```

You should see output indicating Vault is running and unsealed.

## Step 2: Configure Vault for Hyperledger Fabric

### Why This Step Matters

Proper Vault configuration is crucial for managing Hyperledger Fabric's complex certificate hierarchy. This step sets up the PKI secrets engine and creates the necessary roles for different types of certificates (signing, TLS, client, admin).

### Enable PKI Secrets Engine

```bash
# Enable PKI secrets engine for certificate management
vault secrets enable -path=pki pki

# Configure PKI settings with extended TTL
vault secrets tune -max-lease-ttl=87600h pki
```

### Generate Root Certificates

```bash
# Generate root certificate for signing (identity certificates)
vault write pki/root/generate/internal \
    common_name="Hyperledger Fabric Root Sign CA" \
    ttl=87600h \
    issuer_name="signing-ca" \
    key_type="ec" \
    key_bits=256

# Generate TLS root certificate (for TLS connections)
vault write pki/root/generate/internal \
    common_name="Hyperledger Fabric TLS Root CA" \
    ttl=87600h \
    issuer_name="tls-ca" \
    key_type="ec" \
    key_bits=256
```

### Create Certificate Roles

Create roles for different types of certificates used in Hyperledger Fabric:

```bash
# Signing certificate roles
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
    organization="OrdererMSP" \
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

# TLS certificate roles
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
    organization="OrdererMSP"

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

### Verify PKI Configuration

```bash
# List enabled secrets engines
vault secrets list

# List PKI roles
vault list pki/roles
```

## Step 3: Install and Configure Bevel Operator

### Why This Step Matters

The Bevel Operator is the Kubernetes-native way to manage Hyperledger Fabric networks. Configuring it to use Vault ensures all cryptographic materials are stored securely and managed centrally.

### Install Bevel Operator

```bash
# Add the Helm repository
helm repo add kfs https://kfsoftware.github.io/hlf-helm-charts --force-update

# Install the operator
helm install hlf-operator --version=1.11.1 kfs/hlf-operator
```

### Install kubectl Plugin

```bash
# Install Krew (kubectl plugin manager)
# Follow instructions at: https://krew.sigs.k8s.io/docs/user-guide/setup/install/

# Install the HLF plugin
kubectl krew install hlf
```

### Create Vault Token Secret

```bash
# Create a Kubernetes secret with Vault token
kubectl create secret generic vault-token \
    --from-literal=token=my-dev-root-token
```

### Configure Environment Variables

```bash
# Set image versions
export PEER_IMAGE=hyperledger/fabric-peer
export PEER_VERSION=3.1.0
export ORDERER_IMAGE=hyperledger/fabric-orderer
export ORDERER_VERSION=3.1.0
export CA_IMAGE=hyperledger/fabric-ca
export CA_VERSION=1.5.15

# Set Vault configuration
export VAULT_ADDR="http://192.168.0.20:8200"  # Replace with your Vault address
export SC_NAME=standard  # Use 'local-path' for K3D
```

## Step 4: Deploy Certificate Authorities

### Why This Step Matters

Certificate Authorities (CAs) are the foundation of Hyperledger Fabric's identity management. Using Vault-backed CAs ensures that all certificates are generated, stored, and managed securely with proper audit trails.

### Deploy Fabric CA with Vault Integration

```bash
# Deploy CA for Org1
kubectl hlf ca create \
    --image=$CA_IMAGE \
    --version=$CA_VERSION \
    --storage-class=$SC_NAME \
    --capacity=2Gi \
    --name=org1-ca \
    --hosts=ca-org1.localho.st \
    --istio-port=443 \
    --credential-store=vault \
    --vault-address="$VAULT_ADDR" \
    --vault-token-secret="vault-token" \
    --vault-token-secret-namespace="default" \
    --vault-token-secret-key="token" \
    --vault-pki-path="pki" \
    --vault-role="admin-sign" \
    --vault-ttl="8760h"

# Wait for CA to be ready
kubectl wait --timeout=180s --for=condition=Running fabriccas.hlf.kungfusoftware.es --all
```

### Verify CA Deployment

```bash
# Check CA status
kubectl get fabriccas

# Test CA connectivity
openssl s_client -connect ca-org1.localho.st:443
```

## Step 5: Deploy Peer Organization

### Why This Step Matters

Peers are the core components that maintain the ledger and execute chaincode. Deploying them with Vault-managed certificates ensures secure communication and proper identity management.

### Deploy Peer with Vault Integration

```bash
# Deploy peer for Org1
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

# Wait for peer to be ready
kubectl wait --timeout=180s --for=condition=Running fabricpeers.hlf.kungfusoftware.es --all
```

### Verify Peer Deployment

```bash
# Check peer status
kubectl get fabricpeers

# Test peer connectivity
openssl s_client -connect peer0-org1.localho.st:443
```

## Step 6: Deploy Ordering Service

### Why This Step Matters

The ordering service ensures transaction ordering and consensus across the network. Using Vault for orderer certificates maintains the security chain and provides centralized certificate management.

### Configure Orderer PKI in Vault

```bash
# Enable separate PKI for orderer organization
vault secrets enable -path=pki_orderer pki
vault secrets tune -max-lease-ttl=87600h pki_orderer

# Generate orderer root certificates
vault write pki_orderer/root/generate/internal \
    common_name="OrdererMSP Signing Root CA" \
    ttl=87600h \
    issuer_name="signing-ca" \
    key_type="ec" \
    key_bits=256

vault write pki_orderer/root/generate/internal \
    common_name="OrdererMSP TLS Root CA" \
    ttl=87600h \
    issuer_name="tls-ca" \
    key_type="ec" \
    key_bits=256

# Create orderer certificate roles
vault write pki_orderer/roles/orderer-sign \
    allow_subdomains=true \
    allow_any_name=true \
    max_ttl="87600h" \
    key_type="ec" \
    key_bits=256 \
    ou="orderer" \
    organization="OrdererMSP" \
    issuer_ref="signing-ca"

vault write pki_orderer/roles/orderer-tls \
    issuer_ref="tls-ca" \
    allow_subdomains=true \
    allow_any_name=true \
    max_ttl="87600h" \
    key_type="ec" \
    key_bits=256 \
    ou="orderer" \
    organization="OrdererMSP"
```

### Deploy Orderer Nodes

```bash
# Deploy multiple orderer nodes for high availability
for i in {0..3}; do
    kubectl hlf ordnode create \
        --credential-store=vault \
        --image=$ORDERER_IMAGE \
        --version=$ORDERER_VERSION \
        --storage-class=$SC_NAME \
        --enroll-id=orderer \
        --mspid=OrdererMSP \
        --enroll-pw=ordererpw \
        --capacity=2Gi \
        --name=ord-node$((i+1)) \
        --hosts=orderer${i}-ord.localho.st \
        --admin-hosts=admin-orderer${i}-ord.localho.st \
        --istio-port=443 \
        --vault-address="$VAULT_ADDR" \
        --vault-token-secret="vault-token" \
        --vault-token-secret-namespace="default" \
        --vault-token-secret-key="token" \
        --vault-pki-path="pki_orderer" \
        --vault-role="orderer-sign" \
        --vault-ttl="8760h" \
        --tls-vault-address="$VAULT_ADDR" \
        --tls-vault-token-secret="vault-token" \
        --tls-vault-token-secret-namespace="default" \
        --tls-vault-token-secret-key="token" \
        --tls-vault-pki-path="pki_orderer" \
        --tls-vault-role="orderer-tls" \
        --tls-vault-ttl="8760h"
done

# Wait for orderers to be ready
kubectl wait --timeout=180s --for=condition=Running fabricorderernodes.hlf.kungfusoftware.es --all
```

### Verify Orderer Deployment

```bash
# Check orderer status
kubectl get fabricorderernodes

# Test orderer connectivity
for i in {0..3}; do
    openssl s_client -connect orderer${i}-ord.localho.st:443
done
```

## Step 7: Create Network Identities

### Why This Step Matters

Network identities are required for channel management and chaincode operations. Creating these identities in Vault ensures they are securely stored and can be easily managed and rotated.

### Create Orderer Identities

```bash
# Create orderer signing identity
kubectl hlf identity create --name ord-ca-sign --namespace default \
    --mspid OrdererMSP \
    --credential-store=vault \
    --vault-address="$VAULT_ADDR" \
    --vault-token-secret="vault-token" \
    --vault-token-secret-namespace="default" \
    --vault-token-secret-key="token" \
    --vault-pki-path="pki_orderer" \
    --vault-role="admin-sign" \
    --vault-ttl="8760h"

# Create orderer TLS identity
kubectl hlf identity create --name ord-ca-tls --namespace default \
    --mspid OrdererMSP \
    --credential-store=vault \
    --vault-address="$VAULT_ADDR" \
    --vault-token-secret="vault-token" \
    --vault-token-secret-namespace="default" \
    --vault-token-secret-key="token" \
    --vault-pki-path="pki_orderer" \
    --vault-role="admin-tls" \
    --vault-ttl="8760h"
```

### Create Peer Organization Identity

```bash
# Create peer admin identity
kubectl hlf identity create --name org1-admin --namespace default \
    --mspid Org1MSP \
    --credential-store=vault \
    --vault-address="$VAULT_ADDR" \
    --vault-token-secret="vault-token" \
    --vault-token-secret-namespace="default" \
    --vault-token-secret-key="token" \
    --vault-pki-path="pki" \
    --vault-role="admin-sign" \
    --vault-ttl="8760h"
```

## Step 8: Create Channel

### Why This Step Matters

Channels provide private communication between organizations in Hyperledger Fabric. Creating channels with Vault-managed identities ensures secure channel operations and proper access control.

### Extract Certificates for Channel Configuration

```bash
# Get peer organization certificates
export PEER_ORG_SIGN_CERT=$(vault read pki/issuer/signing-ca --format=json | jq -r '.data.certificate' | sed -e "s/^/${IDENT_8}/" )
export PEER_ORG_TLS_CERT=$(vault read pki/issuer/tls-ca --format=json | jq -r '.data.certificate' | sed -e "s/^/${IDENT_8}/" )

# Get orderer organization certificates
export IDENT_8=$(printf "%8s" "")
export ORDERER_TLS_CERT=$(vault read pki_orderer/issuer/tls-ca --format=json | jq -r '.data.certificate' | sed -e "s/^/${IDENT_8}/" )
export ORDERER_SIGN_CERT=$(vault read pki_orderer/issuer/signing-ca --format=json | jq -r '.data.certificate' | sed -e "s/^/${IDENT_8}/" )

# Get orderer node certificates
export ORDERER0_TLS_CERT=$(kubectl get fabricorderernodes ord-node1 -o=jsonpath='{.status.tlsCert}' | sed -e "s/^/${IDENT_8}/" )
export ORDERER1_TLS_CERT=$(kubectl get fabricorderernodes ord-node2 -o=jsonpath='{.status.tlsCert}' | sed -e "s/^/${IDENT_8}/" )
export ORDERER2_TLS_CERT=$(kubectl get fabricorderernodes ord-node3 -o=jsonpath='{.status.tlsCert}' | sed -e "s/^/${IDENT_8}/" )
export ORDERER3_TLS_CERT=$(kubectl get fabricorderernodes ord-node4 -o=jsonpath='{.status.tlsCert}' | sed -e "s/^/${IDENT_8}/" )
```

### Create Main Channel

```bash
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

### Join Peer to Channel

```bash
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

## Step 9: Deploy and Test Chaincode

### Why This Step Matters

Chaincode is the business logic that runs on the blockchain. Deploying it with Vault-managed credentials ensures secure chaincode operations and proper access control.

### Create Network Configuration

```bash
# Create network config for chaincode operations
kubectl hlf networkconfig create --name=org1-cp \
  -o Org1MSP -o OrdererMSP -c demo \
  --identities=org1-admin.default --secret=org1-cp

# Extract configuration
kubectl get secret org1-cp -o jsonpath="{.data.config\.yaml}" | base64 --decode > org1.yaml
```

### Prepare Chaincode Package

```bash
# Set chaincode parameters
export CHAINCODE_NAME=asset
export CHAINCODE_LABEL=asset

# Create metadata
cat << EOF > "metadata.json"
{
    "type": "ccaas",
    "label": "${CHAINCODE_LABEL}"
}
EOF

# Create connection configuration
cat > "connection.json" << EOF
{
  "address": "${CHAINCODE_NAME}:7052",
  "dial_timeout": "10s",
  "tls_required": false
}
EOF

# Package chaincode
tar cfz code.tar.gz connection.json
tar cfz chaincode.tgz metadata.json code.tar.gz

# Calculate package ID
export PACKAGE_ID=$(kubectl hlf chaincode calculatepackageid --path=chaincode.tgz --language=node --label=$CHAINCODE_LABEL)
echo "PACKAGE_ID=$PACKAGE_ID"
```

### Install Chaincode

```bash
# Install chaincode on peer
kubectl hlf chaincode install --path=./chaincode.tgz \
    --config=org1.yaml --language=golang --label=$CHAINCODE_LABEL \
    --user=org1-admin-default --peer=org1-peer0.default

# Verify installation
kubectl hlf chaincode queryinstalled --config=org1.yaml \
    --user=org1-admin-default --peer=org1-peer0.default
```

### Deploy External Chaincode

```bash
# Deploy chaincode container
kubectl hlf externalchaincode sync --image=kfsoftware/chaincode-external:latest \
    --name=$CHAINCODE_NAME \
    --namespace=default \
    --package-id=$PACKAGE_ID \
    --tls-required=false \
    --replicas=1
```

### Approve and Commit Chaincode

```bash
# Approve chaincode for organization
export SEQUENCE=1
export VERSION="1.0"
kubectl hlf chaincode approveformyorg --config=org1.yaml \
    --user=org1-admin-default --peer=org1-peer0.default \
    --package-id=$PACKAGE_ID \
    --version "$VERSION" --sequence "$SEQUENCE" --name=asset \
    --policy="OR('Org1MSP.member')" --channel=demo

# Commit chaincode to channel
kubectl hlf chaincode commit --config=org1.yaml \
    --user=org1-admin-default --mspid=Org1MSP \
    --version "$VERSION" --sequence "$SEQUENCE" --name=asset \
    --policy="OR('Org1MSP.member')" --channel=demo
```

## Step 10: Test the Complete Network

### Why This Step Matters

Testing the complete network ensures that all components work together correctly and that Vault integration is functioning properly across the entire system.

### Initialize Chaincode

```bash
# Initialize the ledger
kubectl hlf chaincode invoke --config=org1.yaml \
    --user=org1-admin-default --peer=org1-peer0.default \
    --chaincode=asset --channel=demo \
    --fcn=initLedger -a '[]'
```

### Query Data

```bash
# Query all assets
kubectl hlf chaincode query --config=org1.yaml \
    --user=org1-admin-default --peer=org1-peer0.default \
    --chaincode=asset --channel=demo \
    --fcn=GetAllAssets -a '[]'
```

### Verify Vault Integration

```bash
# Check Vault audit logs
vault audit list

# List certificates in Vault
vault list pki/roles

# Check certificate issuance
vault read pki/issuer/signing-ca
```

## Step 11: Monitor and Maintain

### Why This Step Matters

Ongoing monitoring and maintenance ensure the network remains secure and operational. Vault provides tools for certificate lifecycle management and audit compliance.

### Monitor Vault Metrics

```bash
# Check Vault status
vault status

# Monitor secret access
vault audit list

# Check certificate expiration
vault read pki/issuer/signing-ca
```

### Certificate Renewal

```bash
# Vault automatically manages certificate renewal based on TTL
# Check certificate TTL
vault read pki/issuer/signing-ca --format=json | jq '.data.ttl'
```

### Backup and Recovery

```bash
# Backup Vault data (for production)
vault operator raft snapshot save backup.snap

# List backup snapshots
vault operator raft snapshot list
```

## Cleanup

When you're done testing, clean up the environment:

```bash
# Delete all Fabric resources
kubectl delete fabricorderernodes.hlf.kungfusoftware.es --all-namespaces --all
kubectl delete fabricpeers.hlf.kungfusoftware.es --all-namespaces --all
kubectl delete fabriccas.hlf.kungfusoftware.es --all-namespaces --all
kubectl delete fabricchaincode.hlf.kungfusoftware.es --all-namespaces --all
kubectl delete fabricmainchannels --all-namespaces --all
kubectl delete fabricfollowerchannels --all-namespaces --all

# Stop Vault (if using Docker)
docker stop vault-dev
docker rm vault-dev
```

## Troubleshooting

### Common Issues and Solutions

1. **Vault Connection Issues**
   - Verify `VAULT_ADDR` is accessible from Kubernetes cluster
   - Check Vault token is valid and has proper permissions
   - Ensure Vault is unsealed and running

2. **Certificate Generation Failures**
   - Verify PKI secrets engine is properly configured
   - Check certificate roles have correct permissions
   - Ensure proper TTL settings

3. **Kubernetes Authentication Issues**
   - Verify service account configuration
   - Check Vault Kubernetes auth method setup
   - Ensure proper policy assignments

### Debug Commands

```bash
# Check Vault status
vault status

# List secrets engines
vault secrets list

# Check authentication methods
vault auth list

# View audit logs
vault audit list

# Check Kubernetes resources
kubectl get all -l app.kubernetes.io/name=hlf-operator
```

## Next Steps

Congratulations! You've successfully deployed a Hyperledger Fabric network with HashiCorp Vault integration. Here are some next steps to consider:

1. **Production Hardening**: Configure Vault clustering, auto-unseal, and high availability
2. **Multi-Organization Setup**: Add additional peer organizations with their own Vault PKI paths
3. **Advanced Security**: Implement Vault policies, response wrapping, and time-based access
4. **Monitoring**: Set up comprehensive monitoring and alerting for both Fabric and Vault
5. **Backup Strategy**: Implement automated backup and disaster recovery procedures

## Additional Resources

- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)
- [Vault Kubernetes Integration](https://www.vaultproject.io/docs/platform/k8s)
- [Bevel Operator Documentation](../operator-guide/configuration.md)
- [Hyperledger Fabric Documentation](https://hyperledger-fabric.readthedocs.io/)
- [Hyperledger Discord Community](https://discord.com/invite/hyperledger) 