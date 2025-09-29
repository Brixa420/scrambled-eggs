"""
Metrics collection and export for the P2P network.

This module provides functionality to collect, aggregate, and export metrics
about the P2P network's performance and health.
"""
import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
import json
import logging

# Configure logging
logger = logging.getLogger(__name__)

class MetricType(Enum):
    """Types of metrics that can be collected."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"

@dataclass
class Metric:
    """Base class for all metrics."""
    name: str
    metric_type: MetricType
    description: str = ""
    labels: Dict[str, str] = field(default_factory=dict)
    
    def to_prometheus(self) -> str:
        """Convert the metric to Prometheus format."""
        pass

@dataclass
class Counter(Metric):
    """A counter metric that only increases."""
    value: int = 0
    
    def inc(self, amount: int = 1) -> None:
        """Increment the counter by the given amount."""
        self.value += amount
    
    def to_prometheus(self) -> str:
        """Convert to Prometheus format."""
        labels = ",".join([f'{k}="{v}"' for k, v in self.labels.items()])
        labels = f"{{{labels}}}" if labels else ""
        
        output = []
        if self.description:
            output.append(f"# HELP {self.name} {self.description}")
        output.append(f"# TYPE {self.name} {self.metric_type.value}")
        output.append(f"{self.name}{labels} {self.value}")
        
        return "\n".join(output)

@dataclass
class Gauge(Metric):
    """A gauge metric that can go up and down."""
    value: float = 0.0
    
    def set(self, value: float) -> None:
        """Set the gauge to the given value."""
        self.value = value
    
    def inc(self, amount: float = 1.0) -> None:
        """Increment the gauge by the given amount."""
        self.value += amount
    
    def dec(self, amount: float = 1.0) -> None:
        """Decrement the gauge by the given amount."""
        self.value -= amount
    
    def to_prometheus(self) -> str:
        """Convert to Prometheus format."""
        labels = ",".join([f'{k}="{v}"' for k, v in self.labels.items()])
        labels = f"{{{labels}}}" if labels else ""
        
        output = []
        if self.description:
            output.append(f"# HELP {self.name} {self.description}")
        output.append(f"# TYPE {self.name} {self.metric_type.value}")
        output.append(f"{self.name}{labels} {self.value}")
        
        return "\n".join(output)

@dataclass
class Histogram(Metric):
    """A histogram metric for observing distributions."""
    buckets: List[float] = field(default_factory=lambda: [.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10])
    counts: List[int] = field(init=False)
    sum_value: float = 0.0
    
    def __post_init__(self):
        self.counts = [0] * (len(self.buckets) + 1)
    
    def observe(self, value: float) -> None:
        """Observe a value in the histogram."""
        self.sum_value += value
        for i, upper_bound in enumerate(self.buckets):
            if value <= upper_bound:
                self.counts[i] += 1
                return
        self.counts[-1] += 1
    
    def to_prometheus(self) -> str:
        """Convert to Prometheus format."""
        labels = ",".join([f'{k}="{v}"' for k, v in self.labels.items()])
        labels = f"{{{labels}}}" if labels else ""
        
        output = []
        if self.description:
            output.append(f"# HELP {self.name} {self.description}")
        output.append(f"# TYPE {self.name} {self.metric_type.value}")
        
        # Output bucket counts
        cumulative = 0
        for i, upper_bound in enumerate(self.buckets):
            cumulative += self.counts[i]
            output.append(f'{self.name}_bucket{{le="{upper_bound}",{labels[1:]} {cumulative}')
        
        # Output the +Inf bucket
        cumulative += self.counts[-1]
        output.append(f'{self.name}_bucket{{le="+Inf"{labels[1:]} {cumulative}')
        
        # Output sum and count
        output.append(f'{self.name}_sum{labels} {self.sum_value}')
        output.append(f'{self.name}_count{labels} {cumulative}')
        
        return "\n".join(output)

class MetricsCollector:
    """Collects and manages metrics for the P2P network."""
    
    def __init__(self):
        self.metrics: Dict[str, Metric] = {}
        self.start_time = time.time()
        
        # Register default metrics
        self.register_default_metrics()
    
    def register_default_metrics(self) -> None:
        """Register default metrics."""
        # Network metrics
        self.register_metric(
            Counter(
                "p2p_messages_sent_total",
                MetricType.COUNTER,
                "Total number of messages sent"
            )
        )
        
        self.register_metric(
            Counter(
                "p2p_messages_received_total",
                MetricType.COUNTER,
                "Total number of messages received"
            )
        )
        
        self.register_metric(
            Gauge(
                "p2p_peers_connected",
                MetricType.GAUGE,
                "Number of currently connected peers"
            )
        )
        
        self.register_metric(
            Histogram(
                "p2p_message_latency_seconds",
                MetricType.HISTOGRAM,
                "Message round-trip latency in seconds"
            )
        )
        
        # System metrics
        self.register_metric(
            Gauge(
                "p2p_uptime_seconds",
                MetricType.GAUGE,
                "Uptime of the P2P node in seconds"
            )
        )
    
    def register_metric(self, metric: Metric) -> None:
        """Register a new metric."""
        if metric.name in self.metrics:
            raise ValueError(f"Metric {metric.name} already registered")
        self.metrics[metric.name] = metric
    
    def get_metric(self, name: str) -> Optional[Metric]:
        """Get a registered metric by name."""
        return self.metrics.get(name)
    
    def update_uptime(self) -> None:
        """Update the uptime metric."""
        uptime = self.get_metric("p2p_uptime_seconds")
        if isinstance(uptime, Gauge):
            uptime.set(time.time() - self.start_time)
    
    def to_prometheus(self) -> str:
        """Export all metrics in Prometheus text format."""
        self.update_uptime()
        return "\n\n".join(metric.to_prometheus() for metric in self.metrics.values())
    
    def to_dict(self) -> Dict[str, Any]:
        """Export metrics as a dictionary."""
        self.update_uptime()
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "metrics": {
                name: {
                    "type": metric.metric_type.value,
                    "value": metric.value if hasattr(metric, 'value') else None,
                    "description": metric.description,
                    "labels": metric.labels
                }
                for name, metric in self.metrics.items()
            }
        }
    
    def to_json(self) -> str:
        """Export metrics as a JSON string."""
        return json.dumps(self.to_dict(), indent=2)

# Global metrics collector instance
metrics = MetricsCollector()

def get_metrics() -> MetricsCollector:
    """Get the global metrics collector instance."""
    return metrics
