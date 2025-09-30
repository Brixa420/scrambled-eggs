# Brixa AI Monitoring Stack

This directory contains the monitoring infrastructure for the Brixa AI platform, including Prometheus for metrics collection and Grafana for visualization.

## Components

1. **Prometheus** - Time-series database for storing metrics
2. **Grafana** - Visualization platform for monitoring dashboards
3. **Node Exporter** - System metrics collection
4. **Custom Metrics** - Application-specific metrics from the Brixa AI services

## Getting Started

### Prerequisites

- Docker
- Docker Compose

### Running the Stack

1. Start the monitoring stack:

```bash
docker-compose -f ../docker-compose.monitoring.yml up -d
```

2. Access the services:
   - Grafana: http://localhost:3000
   - Prometheus: http://localhost:9090

3. Log in to Grafana (default credentials: admin/admin)

## Dashboards

The following dashboards are available:

- **Brixa AI Overview**: High-level overview of system and application metrics
- **Model Performance**: Detailed metrics for AI model predictions and performance
- **System Metrics**: CPU, memory, disk, and network usage

## Adding Custom Metrics

To add custom metrics to your application:

1. Import the metrics module:
```python
from brixa.api.metrics import (
    REQUEST_COUNT, REQUEST_LATENCY, MODEL_PREDICTIONS,
    MODEL_PREDICTION_LATENCY, MODEL_CONFIDENCE, ERROR_COUNT
)
```

2. Use the metrics in your code:
```python
# Increment a counter
REQUEST_COUNT.labels(method="GET", endpoint="/api/health", status_code=200).inc()

# Record a duration
start_time = time.time()
# ... your code ...
REQUEST_LATENCY.labels(method="GET", endpoint="/api/health").observe(time.time() - start_time)
```

## Alerting

Alerts can be configured in Grafana or Prometheus to notify you of issues:

- High error rates
- Increased latency
- System resource constraints
- Model performance degradation

## Troubleshooting

- If metrics aren't appearing, check the Prometheus targets page: http://localhost:9090/targets
- Check container logs for errors:
  ```bash
  docker-compose -f ../docker-compose.monitoring.yml logs -f
  ```
- Verify that your application is exposing metrics at the `/metrics` endpoint

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.
