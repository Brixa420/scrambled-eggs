"""
Prometheus metrics for monitoring the application.
"""
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from fastapi import Response, Request
import time

# Request metrics
REQUEST_COUNT = Counter(
    'http_requests_total',
    'Total number of HTTP requests',
    ['method', 'endpoint', 'status_code']
)

REQUEST_LATENCY = Histogram(
    'http_request_duration_seconds',
    'HTTP request latency in seconds',
    ['method', 'endpoint']
)

# Model metrics
MODEL_PREDICTIONS = Counter(
    'model_predictions_total',
    'Total number of model predictions',
    ['model_name', 'model_version', 'status']
)

MODEL_PREDICTION_LATENCY = Histogram(
    'model_prediction_duration_seconds',
    'Model prediction latency in seconds',
    ['model_name', 'model_version']
)

MODEL_CONFIDENCE = Gauge(
    'model_prediction_confidence',
    'Confidence score of model predictions',
    ['model_name', 'model_version']
)

# System metrics
SYSTEM_CPU_USAGE = Gauge('system_cpu_usage', 'Current CPU usage percentage')
SYSTEM_MEMORY_USAGE = Gauge('system_memory_usage', 'Current memory usage in bytes')
SYSTEM_DISK_USAGE = Gauge('system_disk_usage', 'Current disk usage in bytes')

# Error metrics
ERROR_COUNT = Counter(
    'http_errors_total',
    'Total number of HTTP errors',
    ['method', 'endpoint', 'status_code']
)

def monitor_request(request: Request, call_next):
    """Middleware to monitor requests and update metrics."""
    start_time = time.time()
    method = request.method
    endpoint = request.url.path
    
    try:
        response = call_next(request)
        status_code = response.status_code
        
        # Update request metrics
        REQUEST_COUNT.labels(method=method, endpoint=endpoint, status_code=status_code).inc()
        REQUEST_LATENCY.labels(method=method, endpoint=endpoint).observe(time.time() - start_time)
        
        # Track errors
        if status_code >= 400:
            ERROR_COUNT.labels(method=method, endpoint=endpoint, status_code=status_code).inc()
            
        return response
        
    except Exception as e:
        status_code = 500
        ERROR_COUNT.labels(method=method, endpoint=endpoint, status_code=status_code).inc()
        raise

async def get_metrics():
    """Return Prometheus metrics."""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )

def record_model_metrics(
    model_name: str,
    model_version: str,
    latency: float,
    confidence: float = None,
    success: bool = True
):
    """Record model prediction metrics."""
    status = 'success' if success else 'error'
    MODEL_PREDICTIONS.labels(
        model_name=model_name,
        model_version=model_version,
        status=status
    ).inc()
    
    MODEL_PREDICTION_LATENCY.labels(
        model_name=model_name,
        model_version=model_version
    ).observe(latency)
    
    if confidence is not None:
        MODEL_CONFIDENCE.labels(
            model_name=model_name,
            model_version=model_version
        ).set(confidence)

def update_system_metrics(cpu_usage: float, memory_usage: int, disk_usage: int):
    """Update system resource metrics."""
    SYSTEM_CPU_USAGE.set(cpu_usage)
    SYSTEM_MEMORY_USAGE.set(memory_usage)
    SYSTEM_DISK_USAGE.set(disk_usage)
