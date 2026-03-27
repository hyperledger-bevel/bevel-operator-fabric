# Security Guide

This guide covers security best practices for deploying and operating the HLF Operator and Hyperledger Fabric networks.

## Table of Contents

- [Operator Security](#operator-security)
- [Network Security](#network-security)
- [Certificate Management](#certificate-management)
- [Secret Management](#secret-management)
- [RBAC Configuration](#rbac-configuration)
- [Pod Security](#pod-security)
- [Network Policies](#network-policies)
- [Audit Logging](#audit-logging)
- [Security Checklist](#security-checklist)

---

## Operator Security

### Principle of Least Privilege

The HLF Operator requires specific RBAC permissions to function. Avoid granting cluster-admin privileges.

```yaml
# Recommended: Use namespace-scoped permissions where possible
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: hlf-operator
  namespace: hlf-network
rules:
  - apiGroups: ["hlf.kungfusoftware.es"]
    resources: ["*"]
    verbs: ["*"]
  - apiGroups: [""]
    resources: ["secrets", "configmaps", "services", "pods"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
```

### Container Security

Run the operator with restricted security context:

```yaml
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        fsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: manager
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
```

---

## Network Security

### TLS Configuration

Always enable TLS for all Fabric components:

```yaml
# FabricCA with TLS
apiVersion: hlf.kungfusoftware.es/v1alpha1
kind: FabricCA
metadata:
  name: org1-ca
spec:
  tlsSecretName: org1-ca-tls
  # ... other configuration
```

```yaml
# FabricPeer with TLS
apiVersion: hlf.kungfusoftware.es/v1alpha1
kind: FabricPeer
metadata:
  name: org1-peer0
spec:
  tls:
    enabled: true
```

### Mutual TLS (mTLS)

Enable mTLS for peer-to-peer and peer-to-orderer communication:

```yaml
spec:
  tls:
    enabled: true
  mspID: Org1MSP
  # Client TLS certificates will be used for mutual authentication
```

### External Access

When exposing services externally, use Istio or another ingress controller with proper TLS termination:

```yaml
# Istio Gateway configuration
apiVersion: networking.istio.io/v1beta1
kind: Gateway
metadata:
  name: hlf-gateway
spec:
  selector:
    istio: ingressgateway
  servers:
    - port:
        number: 443
        name: https
        protocol: HTTPS
      tls:
        mode: PASSTHROUGH  # Use PASSTHROUGH for Fabric's native TLS
      hosts:
        - "*.fabric.example.com"
```

---

## Certificate Management

### Certificate Rotation

Enable automatic certificate renewal:

```yaml
apiVersion: hlf.kungfusoftware.es/v1alpha1
kind: FabricPeer
spec:
  updateCertificateTime:
    enabled: true
    renewBefore: 720h  # Renew 30 days before expiry
```

### Certificate Expiry Monitoring

Set up alerts for expiring certificates:

```yaml
# PrometheusRule for certificate monitoring
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: hlf-cert-alerts
spec:
  groups:
    - name: certificates
      rules:
        - alert: HLFCertificateExpiringSoon
          expr: (hlf_certificate_expiry_seconds - time()) < 604800
          for: 1h
          labels:
            severity: warning
          annotations:
            summary: Certificate expiring within 7 days
```

### HSM Integration

For production environments, consider using Hardware Security Modules:

```yaml
apiVersion: hlf.kungfusoftware.es/v1alpha1
kind: FabricCA
spec:
  bccsp:
    default: PKCS11
    pkcs11:
      library: /usr/lib/softhsm/libsofthsm2.so
      label: "ForFabric"
      pin: "98765432"
```

---

## Secret Management

### Using HashiCorp Vault

The operator supports Vault for secret management:

```yaml
apiVersion: hlf.kungfusoftware.es/v1alpha1
kind: FabricPeer
spec:
  secret:
    enrollment:
      component:
        cahost: org1-ca
        caname: ca
        caport: 7054
        catls:
          cacert: |
            # CA TLS certificate
        enrollid: peer0
        enrollsecret:
          vaultSecretRef:
            name: peer-credentials
            key: password
            # Vault path configuration
```

### Kubernetes Secrets Best Practices

1. **Enable encryption at rest:**
   ```yaml
   # kube-apiserver configuration
   --encryption-provider-config=/path/to/encryption-config.yaml
   ```

2. **Use external secret managers:**
   ```yaml
   apiVersion: external-secrets.io/v1beta1
   kind: ExternalSecret
   metadata:
     name: fabric-secrets
   spec:
     secretStoreRef:
       name: vault-backend
       kind: ClusterSecretStore
     target:
       name: fabric-credentials
     data:
       - secretKey: admin-password
         remoteRef:
           key: secret/fabric/admin
           property: password
   ```

3. **Never commit secrets to Git:**
   - Use `.gitignore` for secret files
   - Use sealed-secrets or SOPS for GitOps

---

## RBAC Configuration

### Service Accounts

Create dedicated service accounts for each component:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: fabric-peer
  namespace: hlf-network
automountServiceAccountToken: false  # Disable if not needed
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: fabric-peer
  namespace: hlf-network
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["peer-tls", "peer-msp"]
    verbs: ["get"]
```

### Namespace Isolation

Deploy different organizations in separate namespaces:

```yaml
# Organization 1
apiVersion: v1
kind: Namespace
metadata:
  name: org1
  labels:
    hlf.network/organization: org1
---
# Organization 2
apiVersion: v1
kind: Namespace
metadata:
  name: org2
  labels:
    hlf.network/organization: org2
```

---

## Pod Security

### Pod Security Standards

Apply Pod Security Standards to namespaces:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: hlf-network
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### Security Context Constraints (OpenShift)

```yaml
apiVersion: security.openshift.io/v1
kind: SecurityContextConstraints
metadata:
  name: hlf-restricted
allowPrivilegedContainer: false
allowPrivilegeEscalation: false
requiredDropCapabilities:
  - ALL
runAsUser:
  type: MustRunAsNonRoot
seLinuxContext:
  type: MustRunAs
fsGroup:
  type: MustRunAs
volumes:
  - configMap
  - secret
  - persistentVolumeClaim
  - emptyDir
```

---

## Network Policies

### Isolate Fabric Components

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: fabric-peer-policy
  namespace: hlf-network
spec:
  podSelector:
    matchLabels:
      app: fabric-peer
  policyTypes:
    - Ingress
    - Egress
  ingress:
    # Allow from other peers (gossip)
    - from:
        - podSelector:
            matchLabels:
              app: fabric-peer
      ports:
        - port: 7051
          protocol: TCP
    # Allow from orderer
    - from:
        - podSelector:
            matchLabels:
              app: fabric-orderer
      ports:
        - port: 7051
          protocol: TCP
    # Allow from chaincode
    - from:
        - podSelector:
            matchLabels:
              app: chaincode
      ports:
        - port: 7052
          protocol: TCP
  egress:
    # Allow to CA for enrollment
    - to:
        - podSelector:
            matchLabels:
              app: fabric-ca
      ports:
        - port: 7054
          protocol: TCP
    # Allow to orderer for transaction submission
    - to:
        - podSelector:
            matchLabels:
              app: fabric-orderer
      ports:
        - port: 7050
          protocol: TCP
    # Allow DNS
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - port: 53
          protocol: UDP
```

### Deny All by Default

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: hlf-network
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

---

## Audit Logging

### Kubernetes Audit Policy

Enable audit logging for Fabric resources:

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Log all changes to Fabric CRDs
  - level: RequestResponse
    resources:
      - group: hlf.kungfusoftware.es
        resources: ["*"]
    verbs: ["create", "update", "patch", "delete"]

  # Log secret access (metadata only)
  - level: Metadata
    resources:
      - group: ""
        resources: ["secrets"]
    namespaces: ["hlf-network"]
```

### Operator Logging

Configure structured logging:

```yaml
spec:
  template:
    spec:
      containers:
        - name: manager
          args:
            - --zap-log-level=info
            - --zap-encoder=json
            - --zap-time-encoding=iso8601
```

---

## Security Checklist

### Pre-Deployment

- [ ] Review and customize RBAC roles
- [ ] Configure network policies
- [ ] Set up TLS certificates
- [ ] Configure secret management (Vault or external-secrets)
- [ ] Enable audit logging
- [ ] Review Pod Security Standards

### Deployment

- [ ] Deploy operator with minimal privileges
- [ ] Enable TLS for all components
- [ ] Configure mTLS for peer communication
- [ ] Set resource limits
- [ ] Configure security contexts

### Post-Deployment

- [ ] Verify TLS is working
- [ ] Test network policies
- [ ] Set up certificate expiry monitoring
- [ ] Configure alerting
- [ ] Document security procedures

### Ongoing

- [ ] Regularly rotate certificates
- [ ] Update operator and components
- [ ] Review audit logs
- [ ] Perform security assessments
- [ ] Test disaster recovery procedures

---

## Vulnerability Reporting

If you discover a security vulnerability, please report it responsibly:

1. **Do not** create a public GitHub issue
2. Email security concerns to the maintainers
3. Provide detailed information about the vulnerability
4. Allow time for a fix before public disclosure

## References

- [Hyperledger Fabric Security Model](https://hyperledger-fabric.readthedocs.io/en/latest/security_model.html)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NIST Blockchain Security](https://csrc.nist.gov/projects/blockchain)
