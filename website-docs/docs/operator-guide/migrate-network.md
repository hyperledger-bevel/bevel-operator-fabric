---
id: migrate-network
title: Migrate network
---

# Migrating to HLF Operator

This document provides a comprehensive walkthrough of the steps required to migrate an existing Hyperledger Fabric network to the HLF operator. This includes migrating peer organizations, orderer services, and ensuring continuity of block delivery.

## Migration Strategy Overview

Migrating an existing network to use the HLF operator requires careful planning. There are two primary components to consider:

1. **Peer organizations** - Migrating existing peer nodes or creating new ones
2. **Ordering service** - Adding new orderer nodes managed by the operator and phasing out old ones

## Peer Migration

### Option 1: Creating New Peers (Recommended)

The cleanest migration approach is to create entirely new peer nodes with new domains. This provides a fresh start while maintaining access to the same channels and data.

Steps:
1. Create a Certificate Authority in the HLF operator using the **same MSP ID** as your existing organization
2. Import the existing CA keys and certificates that were used to create your previous peer certificates
3. Deploy new peers using the HLF operator with new domain names
4. Join the new peers to the same channels as the original peers
5. Install the same chaincode versions on the new peers
6. Test the new peers thoroughly before decommissioning the old ones

### Option 2: In-place Migration (Advanced)

For scenarios where creating new peers isn't feasible, in-place migration requires more careful handling:

1. Backup all peer data, MSP folders, and configuration
2. Create identical peer configurations in the HLF operator
3. Import the peer's TLS and MSP certificates into the operator
4. Migrate the peer's storage (ledger data) to the new storage location

> ⚠️ **Warning**: In-place migration is complex and risky. Always have a rollback plan ready.

## Ordering Service Migration

Migrating the ordering service requires adding new orderer nodes and carefully transitioning the consensus responsibilities:

1. Create a Certificate Authority for your orderer organization in the HLF operator
2. Import the existing CA keys and certificates that were used for your previous orderers
3. Deploy new orderer nodes with new domain names

For example, if your existing ordering service consists of:
- orderer1.myorg.com:7050
- orderer2.myorg.com:7050
- orderer3.myorg.com:7050
- orderer4.myorg.com:7050
- orderer5.myorg.com:7050

You would create new orderer nodes using the HLF operator:
- orderer6.myorg.com:7050
- orderer7.myorg.com:7050
- orderer8.myorg.com:7050
- orderer9.myorg.com:7050
- orderer10.myorg.com:7050

### Transitioning Orderer Consensus

Once the new orderer nodes are created:

1. Join each new orderer to all existing channels
2. Verify proper synchronization of the new orderers with the existing blockchain
3. Update the channel configuration to add the new orderers as consenters (one at a time)
4. Test the network with the mixed orderer set (old and new)
5. Gradually remove the old orderers from the channel configuration

## Configuring Block Delivery for Peers

> **Important**: When migrating orderers, you must configure peers to correctly pull blocks from the new orderer nodes after the old ones are removed.

### Using `deliveryClientAddressOverrides`

The `deliveryClientAddressOverrides` field in the peer configuration allows you to redirect block delivery requests from removed orderers to the new orderers. This is **critical** for maintaining peer synchronization once old orderers are removed from the network.

Example peer configuration with delivery client overrides:

```yaml
apiVersion: hlf.kungfusoftware.es/v1alpha1
kind: FabricPeer
metadata:
  name: peer1
spec:
  # ... other peer configuration ...
  deliveryClientAddressOverrides:
    - from: "orderer1.myorg.com:7050"
      to: "orderer6.myorg.com:7050"
	  caCertsFile: "/path/to/ca-certs/orderer1.myorg.com.pem"
    - from: "orderer2.myorg.com:7050"
      to: "orderer7.myorg.com:7050"
	  caCertsFile: "/path/to/ca-certs/orderer2.myorg.com.pem"
    - from: "orderer3.myorg.com:7050"
      to: "orderer8.myorg.com:7050"
	  caCertsFile: "/path/to/ca-certs/orderer3.myorg.com.pem"
    - from: "orderer4.myorg.com:7050"
      to: "orderer9.myorg.com:7050"
	  caCertsFile: "/path/to/ca-certs/orderer4.myorg.com.pem"
    - from: "orderer5.myorg.com:7050"
      to: "orderer10.myorg.com:7050"
	  caCertsFile: "/path/to/ca-certs/orderer5.myorg.com.pem"
```

This configuration ensures that when a peer attempts to fetch blocks from the old orderer URLs, the requests are automatically redirected to the corresponding new orderer nodes.

## Verifying the Migration

After completing the migration:

1. Check all channel participation for both peers and orderers
2. Verify chaincode invocations work on all migrated peers
3. Monitor logs for any errors, especially during block delivery
4. Test all application connections to ensure they can interact with the network
5. Validate that transactions continue to be endorsed and committed correctly

## Troubleshooting Common Issues

### Peer Block Delivery Problems
- Check peer logs for delivery client connection errors
- Verify `deliveryClientAddressOverrides` configuration is correct
- Ensure TLS certificates are properly configured for the new orderer endpoints

### Orderer Channel Participation
- Use the Orderer Admin API to verify channel participation
- Check that system channel configuration (if used) includes the new orderers
- Verify Raft consensus snapshots are being created properly

### Certificate Issues
- Validate that all imported certificates match the original network's certificates
- Check MSP folder structures match what the peers and orderers expect

## Conclusion

Migration to the HLF operator can significantly simplify the management of your Hyperledger Fabric network. While the process requires careful planning and execution, the resulting operator-managed network will be easier to maintain, scale, and upgrade.
