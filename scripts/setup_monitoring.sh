#!/bin/bash
set -e

# Create directories
mkdir -p /opt/scrambled-eggs/deploy/{prometheus,grafana,alertmanager}
chmod -R 777 /opt/scrambled-eggs/deploy/{prometheus,grafana,alertmanager}

# Create Prometheus configuration
cat > /opt/scrambled-eggs/deploy/prometheus/prometheus.yml << 'EOL'
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  scrape_timeout: 10s

rule_files:
  - 'alert.rules'

alerting:
  alertmanagers:
  - static_configs:
    - targets: ['alertmanager:9093']

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node'
    static_configs:
      - targets: ['node-exporter:9100']

  - job_name: 'cadvisor'
    static_configs:
      - targets: ['cadvisor:8080']

  - job_name: 'scrambled-eggs'
    metrics_path: '/metrics'
    static_configs:
      - targets: ['app:5000']
    metrics_path: /metrics
    scheme: http

  - job_name: 'redis'
    static_configs:
      - targets: ['redis:9121']

  - job_name: 'postgres'
    static_configs:
      - targets: ['db:9187']
EOL

# Create alert rules
cat > /opt/scrambled-eggs/deploy/prometheus/alert.rules << 'EOL'
groups:
- name: instance
  rules:
  - alert: InstanceDown
    expr: up == 0
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "Instance {{ $labels.instance }} down"
      description: "{{ $labels.instance }} of job {{ $labels.job }} has been down for more than 5 minutes."

  - alert: HighRequestLatency
    expr: http_request_duration_seconds_count{job="scrambled-eggs", quantile="0.95"} > 1
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "High request latency on {{ $labels.instance }}"
      description: "{{ $labels.instance }} has a 95th percentile request latency above 1s (current value: {{ $value }}s)"

  - alert: HighErrorRate
    expr: rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m]) > 0.01
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "High error rate on {{ $labels.instance }}"
      description: "{{ $labels.instance }} has error rate {{ $value }} of total requests"

  - alert: HighMemoryUsage
    expr: (node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100 > 90
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "High memory usage on {{ $labels.instance }}"
      description: "{{ $labels.instance }} memory usage is {{ $value }}%"

  - alert: HighCPUUsage
    expr: 100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100 > 80
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "High CPU usage on {{ $labels.instance }}"
      description: "{{ $labels.instance }} CPU usage is {{ $value }}%"
EOL

# Create Grafana provisioning
mkdir -p /opt/scrambled-eggs/deploy/grafana/provisioning/datasources
mkdir -p /opt/scrambled-eggs/deploy/grafana/provisioning/dashboards

# Create Grafana datasource
cat > /opt/scrambled-eggs/deploy/grafana/provisioning/datasources/datasource.yml << 'EOL'
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
EOL

# Create Grafana dashboard provisioning
cat > /opt/scrambled-eggs/deploy/grafana/provisioning/dashboards/dashboard.yml << 'EOL'
apiVersion: 1

providers:
  - name: 'Scrambled Eggs'
    orgId: 1
    folder: 'Scrambled Eggs'
    type: file
    disableDeletion: false
    editable: true
    options:
      path: /etc/grafana/provisioning/dashboards
EOL

# Create default dashboards
mkdir -p /opt/scrambled-eggs/deploy/grafana/dashboards

# Create a simple dashboard (you can import more from Grafana's dashboard library)
cat > /opt/scrambled-eggs/deploy/grafana/dashboards/overview.json << 'EOL'
{
  "annotations": {
    "list": [
      {
        "builtIn": 1,
        "datasource": "-- Grafana --",
        "enable": true,
        "hide": true,
        "iconColor": "rgba(0, 211, 255, 1)",
        "name": "Annotations & Alerts",
        "type": "dashboard"
      }
    ]
  },
  "editable": true,
  "gnetId": null,
  "graphTooltip": 0,
  "id": 1,
  "links": [],
  "panels": [
    {
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "links": []
        },
        "overrides": []
      },
      "gridPos": {
        "h": 3,
        "w": 24,
        "x": 0,
        "y": 0
      },
      "id": 2,
      "options": {
        "colorMode": "value",
        "graphMode": "area",
        "justifyMode": "auto",
        "orientation": "auto",
        "reduceOptions": {
          "calcs": [
            "lastNotNull"
          ],
          "fields": "",
          "values": false
        },
        "textMode": "auto"
      },
      "pluginVersion": "9.0.3",
      "targets": [
        {
          "expr": "up{job=\"scrambled-eggs\"}",
          "legendFormat": "{{instance}}",
          "refId": "A"
        }
      ],
      "title": "Service Status",
      "type": "stat"
    },
    {
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "palette-classic"
          },
          "custom": {
            "axisCenteredZero": false,
            "axisColorMode": "text",
            "axisLabel": "",
            "axisPlacement": "auto",
            "barAlignment": 0,
            "drawStyle": "line",
            "fillOpacity": 10,
            "gradientMode": "none",
            "hideFrom": {
              "legend": false,
              "tooltip": false,
              "viz": false
            },
            "lineInterpolation": "linear",
            "lineWidth": 1,
            "pointSize": 5,
            "scaleDistribution": {
              "type": "linear"
            },
            "showPoints": "auto",
            "spanNulls": false,
            "stacking": {
              "group": "A",
              "mode": "none"
            },
            "thresholdsStyle": {
              "mode": "off"
            }
          },
          "links": [],
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "red",
                "value": 80
              }
            ]
          },
          "unit": "reqps"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 0,
        "y": 3
      },
      "id": 4,
      "options": {
        "legend": {
          "calcs": [],
          "displayMode": "list",
          "placement": "bottom",
          "showLegend": true
        },
        "tooltip": {
          "mode": "single",
          "sort": "none"
        }
      },
      "targets": [
        {
          "expr": "sum(rate(http_requests_total[1m])) by (status_code)",
          "legendFormat": "{{status_code}}",
          "refId": "A"
        }
      ],
      "title": "Request Rate by Status Code",
      "type": "timeseries"
    },
    {
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "palette-classic"
          },
          "custom": {
            "axisCenteredZero": false,
            "axisColorMode": "text",
            "axisLabel": "",
            "axisPlacement": "auto",
            "barAlignment": 0,
            "drawStyle": "line",
            "fillOpacity": 10,
            "gradientMode": "none",
            "hideFrom": {
              "legend": false,
              "tooltip": false,
              "viz": false
            },
            "lineInterpolation": "smooth",
            "lineWidth": 1,
            "pointSize": 5,
            "scaleDistribution": {
              "type": "linear"
            },
            "showPoints": "auto",
            "spanNulls": false,
            "stacking": {
              "group": "A",
              "mode": "none"
            },
            "thresholdsStyle": {
              "mode": "off"
            }
          },
          "links": [],
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "red",
                "value": 80
              }
            ]
          },
          "unit": "s"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 12,
        "y": 3
      },
      "id": 6,
      "options": {
        "legend": {
          "calcs": [],
          "displayMode": "list",
          "placement": "bottom",
          "showLegend": true
        },
        "tooltip": {
          "mode": "single",
          "sort": "none"
        }
      },
      "targets": [
        {
          "expr": "histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le))",
          "legendFormat": "95th percentile",
          "refId": "A"
        },
        {
          "expr": "histogram_quantile(0.99, sum(rate(http_request_duration_seconds_bucket[5m])) by (le))",
          "legendFormat": "99th percentile",
          "refId": "B"
        }
      ],
      "title": "Request Latency",
      "type": "timeseries"
    },
    {
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "thresholds"
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "red",
                "value": 80
              }
            ]
          },
          "unit": "percent"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 5,
        "w": 6,
        "x": 0,
        "y": 11
      },
      "id": 8,
      "options": {
        "colorMode": "value",
        "graphMode": "area",
        "justifyMode": "auto",
        "orientation": "auto",
        "reduceOptions": {
          "calcs": [
            "lastNotNull"
          ],
          "fields": "",
          "values": false
        },
        "textMode": "auto"
      },
      "pluginVersion": "9.0.3",
      "targets": [
        {
          "expr": "100 - (avg by(instance) (irate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100",
          "legendFormat": "{{instance}}",
          "refId": "A"
        }
      ],
      "title": "CPU Usage",
      "type": "stat"
    },
    {
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "thresholds"
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "red",
                "value": 90
              }
            ]
          },
          "unit": "percent"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 5,
        "w": 6,
        "x": 6,
        "y": 11
      },
      "id": 10,
      "options": {
        "colorMode": "value",
        "graphMode": "area",
        "justifyMode": "auto",
        "orientation": "auto",
        "reduceOptions": {
          "calcs": [
            "lastNotNull"
          ],
          "fields": "",
          "values": false
        },
        "textMode": "auto"
      },
      "pluginVersion": "9.0.3",
      "targets": [
        {
          "expr": "(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100",
          "legendFormat": "{{instance}}",
          "refId": "A"
        }
      ],
      "title": "Memory Usage",
      "type": "stat"
    },
    {
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "thresholds"
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "red",
                "value": 90
              }
            ]
          },
          "unit": "percent"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 5,
        "w": 6,
        "x": 12,
        "y": 11
      },
      "id": 12,
      "options": {
        "colorMode": "value",
        "graphMode": "area",
        "justifyMode": "auto",
        "orientation": "auto",
        "reduceOptions": {
          "calcs": [
            "lastNotNull"
          ],
          "fields": "",
          "values": false
        },
        "textMode": "auto"
      },
      "pluginVersion": "9.0.3",
      "targets": [
        {
          "expr": "100 - (node_filesystem_avail_bytes{mountpoint='/',fstype!='rootfs'} * 100) / node_filesystem_size_bytes{mountpoint='/',fstype!='rootfs'}",
          "legendFormat": "{{instance}}",
          "refId": "A"
        }
      ],
      "title": "Disk Usage",
      "type": "stat"
    },
    {
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "thresholds"
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "red",
                "value": 80
              }
            ]
          },
          "unit": "percent"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 5,
        "w": 6,
        "x": 18,
        "y": 11
      },
      "id": 14,
      "options": {
        "colorMode": "value",
        "graphMode": "area",
        "justifyMode": "auto",
        "orientation": "auto",
        "reduceOptions": {
          "calcs": [
            "lastNotNull"
          ],
          "fields": "",
          "values": false
        },
        "textMode": "auto"
      },
      "pluginVersion": "9.0.3",
      "targets": [
        {
          "expr": "rate(node_network_receive_bytes_total[1m]) * 8",
          "legendFormat": "{{device}}",
          "refId": "A"
        }
      ],
      "title": "Network Traffic",
      "type": "stat"
    }
  ],
  "refresh": "10s",
  "schemaVersion": 36,
  "style": "dark",
  "tags": [],
  "templating": {
    "list": []
  },
  "time": {
    "from": "now-6h",
    "to": "now"
  },
  "timepicker": {},
  "timezone": "",
  "title": "Scrambled Eggs Overview",
  "uid": "scrambled-eggs-overview",
  "version": 1,
  "weekStart": ""
}
EOL

# Set permissions
chown -R 472:472 /opt/scrambled-eggs/deploy/grafana

# Create Alertmanager configuration
mkdir -p /opt/scrambled-eggs/deploy/alertmanager

cat > /opt/scrambled-eggs/deploy/alertmanager/config.yml << 'EOL'
global:
  resolve_timeout: 5m
  smtp_smarthost: 'smtp.gmail.com:587'
  smtp_from: '${ALERT_EMAIL_FROM}'
  smtp_auth_username: '${ALERT_EMAIL_USER}'
  smtp_auth_password: '${ALERT_EMAIL_PASSWORD}'
  smtp_require_tls: true

route:
  group_by: ['alertname', 'severity']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 12h
  receiver: 'email'
  routes:
    - match:
        severity: 'critical'
      receiver: 'email-critical'
    - match:
        severity: 'warning'
      receiver: 'email-warning'

receivers:
- name: 'email'
  email_configs:
  - to: '${ALERT_EMAIL_TO}'
    send_resolved: true
    headers:
      subject: '[{{ .Status | toUpper }}{{ if eq .Status "firing" }}:{{ .Alerts.Firing | len }}{{ end }}] {{ .CommonLabels.alertname }}'
    html: |
      <h2>Alert Details</h2>
      <table>
        <tr><td><strong>Status</strong></td><td>{{ .Status | toUpper }}</td></tr>
        <tr><td><strong>Alert Name</strong></td><td>{{ .CommonLabels.alertname }}</td></tr>
        <tr><td><strong>Severity</strong></td><td>{{ .CommonLabels.severity }}</td></tr>
        <tr><td><strong>Instance</strong></td><td>{{ .CommonLabels.instance }}</td></tr>
        <tr><td><strong>Summary</strong></td><td>{{ .CommonAnnotations.summary }}</td></tr>
        <tr><td><strong>Description</strong></td><td>{{ .CommonAnnotations.description }}</td></tr>
      </table>
      <h3>Alerts</h3>
      <table>
        <tr>
          <th>Status</th>
          <th>Labels</th>
          <th>Starts At</th>
        </tr>
        {{ range .Alerts }}
        <tr>
          <td>{{ .Status }}</td>
          <td>
            {{ range .Labels.SortedPairs }}
              {{ .Name }}: {{ .Value }}<br>
            {{ end }}
          </td>
          <td>{{ .StartsAt }}</td>
        </tr>
        {{ end }}
      </table>

- name: 'email-critical'
  email_configs:
  - to: '${ALERT_EMAIL_CRITICAL}'
    send_resolved: true
    headers:
      subject: '[CRITICAL] {{ .CommonLabels.alertname }} - {{ .CommonAnnotations.summary }}'

- name: 'email-warning'
  email_configs:
  - to: '${ALERT_EMAIL_TO}'
    send_resolved: true
    headers:
      subject: '[WARNING] {{ .CommonLabels.alertname }} - {{ .CommonAnnotations.summary }}'
EOL

echo "Monitoring setup complete!"
echo "To start monitoring, run: docker-compose -f /opt/scrambled-eggs/docker-compose.prod.yml up -d"
