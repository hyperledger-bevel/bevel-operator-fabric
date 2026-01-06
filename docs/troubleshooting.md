# Troubleshooting Guide

This guide helps you diagnose and resolve common issues with the HLF Operator.

## Table of Contents

- [Diagnostic Commands](#diagnostic-commands)
- [Common Issues](#common-issues)
  - [Certificate Authority (CA) Issues](#certificate-authority-ca-issues)
  - [Peer Issues](#peer-issues)
  - [Orderer Issues](#orderer-issues)
  - [Channel Issues](#channel-issues)
  - [Chaincode Issues](#chaincode-issues)
  - [Network Connectivity](#network-connectivity)
- [Operator Issues](#operator-issues)
- [Performance Issues](#performance-issues)

---

## Diagnostic Commands

### Check Resource Status

```bash
# Check all HLF resources
kubectl get fabriccas.hlf.kungfusoftware.es -A
kubectl get fabricpeers.hlf.kungfusoftware.es -A
kubectl get fabricorderernodes.hlf.kungfusoftware.es -A
kubectl get fabricmainchannels.hlf.kungfusoftware.es -A
kubectl get fabricfollowerchannels.hlf.kungfusoftware.es -A

# Detailed status with conditions
kubectl get fabriccas.hlf.kungfusoftware.es -A -o=custom-columns='NAME:metadata.name,NAMESPACE:metadata.namespace,STATE:status.status,MESSAGE:status.message'
```

### Check Operator Logs

```bash
# Get operator logs
kubectl logs -l app.kubernetes.io/name=hlf-operator -c manager --tail=500

# Follow operator logs in real-time
kubectl logs -l app.kubernetes.io/name=hlf-operator -c manager -f

# Get logs with timestamps
kubectl logs -l app.kubernetes.io/name=hlf-operator -c manager --timestamps
```

### Check Component Logs

```bash
# CA logs
kubectl logs -l app=<ca-name> -c ca

# Peer logs
kubectl logs -l app=<peer-name> -c peer

# Orderer logs
kubectl logs -l app=<orderer-name>
```

### Describe Resources

```bash
# Describe a specific resource for events and conditions
kubectl describe fabricca <ca-name> -n <namespace>
kubectl describe fabricpeer <peer-name> -n <namespace>
kubectl describe fabricorderernode <orderer-name> -n <namespace>
```

---

## Common Issues

### Certificate Authority (CA) Issues

#### CA Pod Not Starting

**Symptoms:**
- CA pod stuck in `Pending` or `CrashLoopBackOff`
- Status shows `FAILED` or no status

**Diagnosis:**
```bash
kubectl describe pod -l app=<ca-name> -n <namespace>
kubectl logs -l app=<ca-name> -c ca -n <namespace>
```

**Common Causes & Solutions:**

1. **Insufficient Resources**
   ```yaml
   # Increase resource limits in FabricCA spec
   spec:
     resources:
       requests:
         memory: "256Mi"
         cpu: "100m"
       limits:
         memory: "512Mi"
         cpu: "500m"
   ```

2. **Storage Issues**
   - Check PVC is bound: `kubectl get pvc -n <namespace>`
   - Verify StorageClass exists: `kubectl get sc`

3. **Invalid TLS Configuration**
   - Verify TLS secrets exist
   - Check certificate validity

#### CA Enrollment Failures

**Symptoms:**
- Identity enrollment fails
- "Failed to enroll" errors in logs

**Solutions:**
1. Verify CA is running and healthy
2. Check CA credentials are correct
3. Verify network connectivity to CA

```bash
# Test CA connectivity
kubectl run test-ca --rm -it --image=curlimages/curl -- \
  curl -k https://<ca-service>:7054/cainfo
```

---

### Peer Issues

#### Peer Not Joining Channel

**Symptoms:**
- Peer shows as running but not in channel
- FabricFollowerChannel stuck in pending state

**Diagnosis:**
```bash
kubectl logs -l app=<peer-name> -c peer | grep -i "channel\|join\|error"
kubectl describe fabricfollowerchannel <channel-name>
```

**Common Causes & Solutions:**

1. **Orderer Unreachable**
   - Verify orderer is running
   - Check network policies allow peer-orderer communication

2. **Invalid MSP Configuration**
   - Verify peer certificates are valid
   - Check MSP ID matches channel configuration

3. **Genesis Block Issues**
   - Ensure genesis block is accessible
   - Verify orderer system channel is configured correctly

#### Peer CouchDB Connection Issues

**Symptoms:**
- Peer fails to start with CouchDB errors
- State database unavailable

**Solutions:**
```yaml
# Verify CouchDB settings in FabricPeer spec
spec:
  stateDb: couchdb
  couchdb:
    user: couchdb
    password: couchdb123
```

Check CouchDB pod:
```bash
kubectl logs -l app=<peer-name>-couchdb
```

---

### Orderer Issues

#### Orderer Not Starting

**Symptoms:**
- Orderer pod in CrashLoopBackOff
- "Failed to create genesis block" errors

**Diagnosis:**
```bash
kubectl logs -l app=<orderer-name>
kubectl describe fabricorderernode <orderer-name>
```

**Common Causes & Solutions:**

1. **Genesis Block Configuration**
   - Verify consortium configuration
   - Check orderer organization MSP

2. **TLS Certificate Issues**
   - Verify TLS certificates are valid
   - Check certificate chain is complete

3. **Cluster Communication**
   - For Raft orderers, ensure all nodes can communicate
   - Check etcdraft configuration

#### Raft Leader Election Issues

**Symptoms:**
- Orderers stuck in "No leader" state
- Transaction timeouts

**Solutions:**
1. Verify all orderer nodes are running
2. Check network connectivity between orderers
3. Review Raft configuration:
   ```yaml
   spec:
     consensusType: etcdraft
     raftConfig:
       tickInterval: 500ms
       electionTick: 10
       heartbeatTick: 1
   ```

---

### Channel Issues

#### Channel Creation Fails

**Symptoms:**
- FabricMainChannel stuck in pending
- "Failed to create channel" errors

**Diagnosis:**
```bash
kubectl describe fabricmainchannel <channel-name>
kubectl logs -l app.kubernetes.io/name=hlf-operator -c manager | grep -i channel
```

**Common Causes & Solutions:**

1. **Insufficient Signatures**
   - Verify all required organizations have signed
   - Check policy requirements

2. **Invalid Channel Configuration**
   - Validate channel name (lowercase, alphanumeric)
   - Check application capabilities version

3. **Orderer Connection**
   - Verify orderer endpoint is correct
   - Check TLS configuration

#### Anchor Peer Update Fails

**Symptoms:**
- Anchor peer not set
- Cross-organization discovery fails

**Solutions:**
```yaml
# Ensure anchor peers are defined in FabricFollowerChannel
spec:
  anchorPeers:
    - host: peer0.org1.example.com
      port: 7051
```

---

### Chaincode Issues

#### Chaincode Installation Fails

**Symptoms:**
- FabricChaincode stuck in "Installing"
- Package errors in peer logs

**Diagnosis:**
```bash
kubectl logs -l app=<peer-name> -c peer | grep -i chaincode
kubectl describe fabricchaincode <chaincode-name>
```

**Common Causes & Solutions:**

1. **Invalid Chaincode Package**
   - Verify package format (tar.gz)
   - Check chaincode metadata.json

2. **External Builder Issues**
   - For external chaincodes, verify builder configuration
   - Check connection.json is correct

3. **Resource Limits**
   - Chaincode container may need more resources
   ```yaml
   spec:
     chaincodeResources:
       limits:
         memory: "512Mi"
         cpu: "500m"
   ```

#### Chaincode Commit Fails

**Symptoms:**
- Approval succeeds but commit fails
- "Chaincode definition not agreed" errors

**Solutions:**
1. Verify all required organizations have approved
2. Check endorsement policy matches approvals
3. Ensure sequence numbers are correct

---

### Network Connectivity

#### DNS Resolution Issues

**Symptoms:**
- Components can't find each other
- "Unknown host" errors

**Solutions:**
1. Check CoreDNS configuration:
   ```bash
   kubectl get configmap coredns -n kube-system -o yaml
   ```

2. Verify service names resolve:
   ```bash
   kubectl run test-dns --rm -it --image=busybox -- \
     nslookup <service-name>.<namespace>.svc.cluster.local
   ```

#### Istio/Service Mesh Issues

**Symptoms:**
- External access fails
- mTLS handshake errors

**Solutions:**
1. Verify Istio gateway configuration
2. Check VirtualService and DestinationRule
3. Ensure SNI routing is configured correctly:
   ```yaml
   spec:
     istio:
       hosts:
         - peer0.org1.example.com
       port: 443
   ```

---

## Operator Issues

### Operator Not Reconciling

**Symptoms:**
- Resources stuck in current state
- No operator logs for resource

**Diagnosis:**
```bash
# Check operator health
kubectl get pods -l app.kubernetes.io/name=hlf-operator
kubectl logs -l app.kubernetes.io/name=hlf-operator -c manager --tail=1000

# Check for rate limiting
kubectl logs -l app.kubernetes.io/name=hlf-operator -c manager | grep -i "rate\|limit\|queue"
```

**Solutions:**
1. Restart the operator:
   ```bash
   kubectl rollout restart deployment hlf-operator
   ```

2. Check RBAC permissions:
   ```bash
   kubectl auth can-i --list --as=system:serviceaccount:<namespace>:hlf-operator
   ```

### Webhook Failures

**Symptoms:**
- Resource creation rejected
- "Webhook denied" errors

**Solutions:**
1. Check webhook configuration:
   ```bash
   kubectl get validatingwebhookconfigurations
   kubectl get mutatingwebhookconfigurations
   ```

2. Verify webhook service is running
3. Check webhook TLS certificates

---

## Performance Issues

### Slow Reconciliation

**Symptoms:**
- Resources take long time to update
- High operator CPU/memory usage

**Solutions:**
1. Increase operator resources:
   ```yaml
   resources:
     limits:
       cpu: "1"
       memory: "1Gi"
   ```

2. Check for resource contention
3. Review reconciliation frequency

### High Memory Usage

**Symptoms:**
- Operator OOMKilled
- Pods evicted

**Solutions:**
1. Increase memory limits
2. Check for memory leaks in operator logs
3. Reduce number of watched resources if possible

---

## Getting Help

If you're still experiencing issues:

1. **Check GitHub Issues:** [github.com/kfsoftware/hlf-operator/issues](https://github.com/kfsoftware/hlf-operator/issues)

2. **Collect Debug Information:**
   ```bash
   # Create debug bundle
   kubectl get all -n <namespace> -o yaml > debug-bundle.yaml
   kubectl logs -l app.kubernetes.io/name=hlf-operator -c manager > operator-logs.txt
   kubectl describe fabriccas,fabricpeers,fabricorderernodes -A > resources.txt
   ```

3. **Community Support:**
   - Hyperledger Discord: #fabric-operator
   - Hyperledger Bevel Documentation

4. **Report a Bug:**
   - Include Kubernetes version: `kubectl version`
   - Include operator version
   - Provide minimal reproduction steps
