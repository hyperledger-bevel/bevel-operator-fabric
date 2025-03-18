---
id: revoke-identities
title: Revoking Identity Credentials
---

# Revoking Identity Credentials

This guide walks you through the process of revoking identity credentials in a Hyperledger Fabric network managed by HLF Operator. Identity revocation is a critical security operation when credentials are compromised or when users leave your organization.

## Before You Begin

To revoke credentials, you must have an admin identity with the proper permissions. The following attributes are required:

```yaml
identities:
  - affiliation: ''
    attrs:
      hf.AffiliationMgr: false
      hf.GenCRL: true
      hf.IntermediateCA: false
      hf.Registrar.Attributes: '*'
      hf.Registrar.Roles: '*'
      hf.Registrar.DelegateRoles: '*'
      hf.Revoker: true
    name: ${ADMIN_NAME}
    pass: ${ADMIN_PASSWORD}
    type: admin
```

The critical attributes for revocation are:
- `hf.GenCRL: true` - Allows generation of Certificate Revocation Lists
- `hf.Revoker: true` - Grants permission to revoke certificates
- `hf.Registrar.Roles: '*'` - Manages roles for the CA

## Step-by-Step Revocation Process

### 1. Configure Environment Variables

First, set up your environment to connect to the Certificate Authority:

```bash
# Set CA URL
export FABRIC_CA_CLIENT_URL=https://${CA_HOST}:${CA_PORT}

# Set TLS certificate path
# You can obtain this from the `status.tls_cert` field of the CA custom resource
export FABRIC_CA_CLIENT_TLS_CERTFILES=${PWD}/${TLS_CERT_FILE}
```

### 2. Authenticate as Admin

Enroll the admin user that has revocation privileges:

```bash
fabric-ca-client enroll -u https://${ADMIN_NAME}:${ADMIN_PASSWORD}@${CA_HOST}:${CA_PORT}
```

### 3. Execute the Revocation

Revoke the target identity using its enrollment ID:

```bash
fabric-ca-client revoke -e ${TARGET_IDENTITY}
```

### 4. Generate and Apply the CRL

After revoking the identity, create a Certificate Revocation List:

```bash
fabric-ca-client gencrl
```

Apply the generated CRL to your FabricFollowerChannel custom resource:

```yaml
apiVersion: hlf.kungfusoftware.es/v1alpha1
kind: FabricFollowerChannel
metadata:
  name: ${CHANNEL_NAME}
spec:
  # ...other configuration...
  revocationList:
    - |
      <CRL_GENERATED_ABOVE>
```
