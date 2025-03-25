# Backup procedure

Velero is a powerful tool for backing up and restoring Kubernetes cluster resources, including persistent volumes. This guide will walk you through the process of backing up persistent volumes and restoring a network using Velero.

## Prerequisites

- A Kubernetes cluster
- kubectl CLI installed and configured
- Helm (optional, for Velero installation)
- Access to a storage provider (AWS S3, GCS, Azure Blob Storage, etc.)

## Installing Velero

### Using the Velero CLI

```bash
# Download the Velero CLI
wget https://github.com/vmware-tanzu/velero/releases/download/v1.10.0/velero-v1.10.0-linux-amd64.tar.gz
tar -xvf velero-v1.10.0-linux-amd64.tar.gz
sudo mv velero-v1.10.0-linux-amd64/velero /usr/local/bin/

# Install Velero in your cluster (example with AWS S3)
velero install \
  --provider aws \
  --plugins velero/velero-plugin-for-aws:v1.5.0 \
  --bucket velero-backups \
  --backup-location-config region=us-east-1 \
  --snapshot-location-config region=us-east-1 \
  --secret-file ./credentials-velero
```

### Using Helm (Alternative)

```bash
# Add the Velero Helm repository
helm repo add vmware-tanzu https://vmware-tanzu.github.io/helm-charts
helm repo update

# Install Velero
helm install velero vmware-tanzu/velero \
  --namespace velero \
  --create-namespace \
  --set credentials.secretContents.cloud=<CREDENTIALS_FILE_CONTENT> \
  --set configuration.provider=aws \
  --set configuration.backupStorageLocation.bucket=velero-backups \
  --set configuration.backupStorageLocation.config.region=us-east-1 \
  --set configuration.volumeSnapshotLocation.config.region=us-east-1
```

## Configuring Volume Snapshot Provider

Velero requires a volume snapshot provider to back up persistent volumes. Configure the appropriate plugin for your environment:

```bash
# For AWS EBS
velero plugin add velero/velero-plugin-for-aws:v1.5.0

# For GCP
velero plugin add velero/velero-plugin-for-gcp:v1.5.0

# For Azure
velero plugin add velero/velero-plugin-for-microsoft-azure:v1.5.0
```

## Backing Up Persistent Volumes

### Creating a Backup with Volume Snapshots

```bash
# Backup entire cluster with PVs
velero backup create full-cluster-backup --include-namespaces=* --snapshot-volumes=true

# Backup specific namespace with PVs
velero backup create app-backup --include-namespaces=app-namespace --snapshot-volumes=true

# Backup with specific label selector
velero backup create database-backup --selector app=database --snapshot-volumes=true
```

### Scheduling Regular Backups

```bash
# Schedule daily backups
velero schedule create daily-backup --schedule="0 0 * * *" --include-namespaces=* --snapshot-volumes=true

# Schedule hourly backups for critical services
velero schedule create hourly-critical-backup --schedule="0 * * * *" --selector app=critical --snapshot-volumes=true
```

## Restoring a Network

When restoring a network configuration and its associated resources, follow these steps:

### 1. Identify Network Resources to Restore

Network resources typically include:
- Services
- Ingress controllers
- Network policies
- ConfigMaps and Secrets related to networking

### 2. Performing the Restore

```bash
# List available backups
velero backup get

# Restore the entire network namespace
velero restore create network-restore --from-backup=<BACKUP_NAME> --include-namespaces=network-namespace

# Restore only network components using labels
velero restore create network-components-restore --from-backup=<BACKUP_NAME> --selector component=network

# Restore specific network resources
velero restore create ingress-restore --from-backup=<BACKUP_NAME> --include-resources=ingresses.networking.k8s.io
```

### 3. Handling Network-Specific Considerations

```bash
# Restore with resource mapping (if IP or hostname changes are needed)
velero restore create network-restore --from-backup=<BACKUP_NAME> \
  --namespace-mappings old-namespace:new-namespace \
  --include-namespaces=old-namespace
```

## Verifying the Restore

After restoring network resources, verify the restoration:

```bash
# Check network services
kubectl get services --all-namespaces

# Verify ingress resources
kubectl get ingress --all-namespaces

# Test network connectivity
kubectl run test-connectivity --image=busybox -- sleep 3600
kubectl exec -it test-connectivity -- wget -O- <service-name>:<port>
```

## Troubleshooting

### Common Issues and Solutions

1. **Volume Snapshot Failures**
```bash
# Check backup logs
velero backup logs <BACKUP_NAME>

# Describe backup for details
velero backup describe <BACKUP_NAME> --details
```

2. **Network Connectivity Issues After Restore**
```bash
# Check for pending services
kubectl get services --all-namespaces | grep Pending

# Verify network policies
kubectl get networkpolicies --all-namespaces
```

3. **Permission Issues**

```bash
# Check Velero server logs
kubectl logs deployment/velero -n velero
```

## Best Practices

1. **Regular Testing**: Periodically test your backups by performing restore operations in a test environment
2. **Comprehensive Backups**: Include all dependent resources when backing up applications
3. **Documentation**: Document your backup and restore procedures
4. **Retention Policy**: Set appropriate retention policies for your backups
5. **Monitoring**: Set up alerts for backup failures

By following this guide, you should be able to effectively back up persistent volumes and restore network resources using Velero in your Kubernetes environment.

