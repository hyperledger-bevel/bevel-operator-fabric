---
id: prometheus-metrics
title: Prometheus Metrics
---

# Prometheus Metrics

The HLF Operator exposes several Prometheus metrics that can be used for monitoring and alerting on your Hyperledger Fabric network. These metrics provide insights into certificate expiration times and current system time.

## Available Metrics

### Certificate Expiration Metrics

#### `hlf_operator_certificate_expiration_timestamp_seconds`

**Type:** Gauge Vector  
**Description:** The date after which the certificate expires, expressed as a Unix Epoch Time.

**Labels:**
- `node_type`: Type of the Fabric node (e.g., "peer", "orderer", "ca")
- `crt_type`: Type of certificate (e.g., "tls", "signcert", "cacert")
- `namespace`: Kubernetes namespace where the resource is deployed
- `name`: Name of the Fabric resource

**Example:**
```
hlf_operator_certificate_expiration_timestamp_seconds{node_type="peer",crt_type="tls",namespace="hlf-network",name="peer0-org1"} 1735689600
```

### System Time Metrics

#### `hlf_operator_current_time_seconds`

**Type:** Gauge  
**Description:** The current time in Unix Epoch Time.

**Example:**
```
hlf_operator_current_time_seconds 1735689600
```

## Usage Examples

### Monitoring Certificate Expiration

You can create Prometheus queries to monitor certificate expiration:

```promql
# Get all certificates expiring within the next 30 days
hlf_operator_certificate_expiration_timestamp_seconds - hlf_operator_current_time_seconds < 2592000

# Get certificates expiring within the next 7 days
hlf_operator_certificate_expiration_timestamp_seconds - hlf_operator_current_time_seconds < 604800

# Get certificates by node type
hlf_operator_certificate_expiration_timestamp_seconds{node_type="peer"}

# Get TLS certificates specifically
hlf_operator_certificate_expiration_timestamp_seconds{crt_type="tls"}
```

### Alerting Rules

Here are some example Prometheus alerting rules you can use:

```yaml
groups:
  - name: hlf-certificate-alerts
    rules:
      - alert: CertificateExpiringSoon
        expr: (hlf_operator_certificate_expiration_timestamp_seconds - hlf_operator_current_time_seconds) < 604800
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Certificate expiring soon"
          description: "Certificate for {{ $labels.node_type }} {{ $labels.name }} in namespace {{ $labels.namespace }} will expire in less than 7 days"

      - alert: CertificateExpiringVerySoon
        expr: (hlf_operator_certificate_expiration_timestamp_seconds - hlf_operator_current_time_seconds) < 86400
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Certificate expiring very soon"
          description: "Certificate for {{ $labels.node_type }} {{ $labels.name }} in namespace {{ $labels.namespace }} will expire in less than 24 hours"
```

### Grafana Dashboard Queries

For Grafana dashboards, you can use these queries:

**Certificate Expiration Timeline:**
```promql
hlf_operator_certificate_expiration_timestamp_seconds
```

**Days Until Expiration:**
```promql
(hlf_operator_certificate_expiration_timestamp_seconds - hlf_operator_current_time_seconds) / 86400
```

**Certificates by Node Type:**
```promql
count by (node_type) (hlf_operator_certificate_expiration_timestamp_seconds)
```

## Enabling Metrics Collection

To collect these metrics, ensure that:

1. **ServiceMonitor is enabled** in your Fabric resources:
   ```yaml
   serviceMonitor:
     enabled: true
     interval: 10s
     labels: {}
     sampleLimit: 0
     scrapeTimeout: 10s
   ```

2. **Prometheus Operator is installed** in your cluster to automatically discover and scrape the metrics.

3. **Metrics endpoint is accessible** on the HLF Operator service.

## Metric Updates

- **Certificate expiration metrics** are updated whenever certificates are processed or renewed
- **Current time metric** is updated regularly to provide a reference point for time-based calculations

These metrics help you maintain visibility into your Hyperledger Fabric network's certificate lifecycle and ensure timely certificate renewals to prevent service disruptions. 