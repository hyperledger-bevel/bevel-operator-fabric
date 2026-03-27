# Monitoring

This directory contains monitoring resources for the HLF Operator.

## Grafana Dashboards

### HLF Operator Dashboard

**File:** `grafana-dashboard-operator.json`

This dashboard provides visibility into:

- **Operator Overview**: Running CAs, Peers, Orderers, and Channels
- **Reconciliation Metrics**: Reconciliation rate, latency (p99), errors, and work queue depth
- **Operator Resources**: CPU and memory usage
- **Certificate Metrics**: Certificate expiry tracking

#### Importing the Dashboard

1. Open Grafana
2. Go to **Dashboards** > **Import**
3. Upload the `grafana-dashboard-operator.json` file or paste its contents
4. Select your Prometheus data source
5. Click **Import**

#### Prerequisites

- Prometheus monitoring stack installed (e.g., kube-prometheus-stack)
- HLF Operator with metrics enabled
- `controller-runtime` metrics exposed (default port 8080)

## Prometheus Metrics

The HLF Operator exposes the following metrics:

### Controller Runtime Metrics

| Metric | Description |
|--------|-------------|
| `controller_runtime_reconcile_total` | Total reconciliations per controller |
| `controller_runtime_reconcile_errors_total` | Total reconciliation errors |
| `controller_runtime_reconcile_time_seconds` | Reconciliation duration histogram |
| `workqueue_depth` | Current depth of the work queue |
| `workqueue_adds_total` | Total items added to work queue |
| `workqueue_retries_total` | Total retries in work queue |

### Custom HLF Metrics

| Metric | Description |
|--------|-------------|
| `hlf_certificate_expiry_seconds` | Certificate expiry timestamp |
| `hlf_component_status` | Component health status (1=healthy, 0=unhealthy) |

## ServiceMonitor

If using Prometheus Operator, create a ServiceMonitor:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: hlf-operator
  labels:
    app.kubernetes.io/name: hlf-operator
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: hlf-operator
  endpoints:
    - port: metrics
      interval: 30s
      path: /metrics
  namespaceSelector:
    matchNames:
      - hlf-operator-system
```

## Alerting Rules

Example PrometheusRule for alerting:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: hlf-operator-alerts
spec:
  groups:
    - name: hlf-operator
      rules:
        - alert: HLFOperatorReconcileErrors
          expr: sum(rate(controller_runtime_reconcile_errors_total[5m])) > 0
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: HLF Operator reconciliation errors
            description: The HLF Operator is experiencing reconciliation errors

        - alert: HLFCertificateExpiringSoon
          expr: (hlf_certificate_expiry_seconds - time()) < 604800
          for: 1h
          labels:
            severity: warning
          annotations:
            summary: HLF Certificate expiring within 7 days
            description: Certificate {{ $labels.name }} expires in {{ $value | humanizeDuration }}

        - alert: HLFCertificateExpired
          expr: (hlf_certificate_expiry_seconds - time()) < 0
          labels:
            severity: critical
          annotations:
            summary: HLF Certificate expired
            description: Certificate {{ $labels.name }} has expired

        - alert: HLFOperatorHighMemory
          expr: container_memory_working_set_bytes{pod=~"hlf-operator.*", container="manager"} > 1073741824
          for: 15m
          labels:
            severity: warning
          annotations:
            summary: HLF Operator high memory usage
            description: HLF Operator memory usage is above 1GB

        - alert: HLFComponentNotRunning
          expr: kube_customresource_fabricpeer_status_condition{status="False", type="Running"} == 1
          for: 10m
          labels:
            severity: critical
          annotations:
            summary: HLF component not running
            description: Fabric Peer {{ $labels.name }} is not running
```

## Enabling Metrics

Ensure the operator is deployed with metrics enabled:

```yaml
# In your operator deployment
spec:
  template:
    spec:
      containers:
        - name: manager
          args:
            - --metrics-bind-address=:8080
            - --health-probe-bind-address=:8081
          ports:
            - containerPort: 8080
              name: metrics
              protocol: TCP
```
