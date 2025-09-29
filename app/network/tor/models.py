"""
Database models for Tor metrics storage.
"""

from sqlalchemy import JSON, Column, DateTime, Float, Integer, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class CircuitMetricsModel(Base):
    """Database model for circuit metrics."""

    __tablename__ = "circuit_metrics"

    id = Column(String, primary_key=True)
    circuit_id = Column(String, index=True)
    purpose = Column(String, index=True)
    isolation_group = Column(String, index=True)
    created_at = Column(DateTime, index=True)
    last_used = Column(DateTime, index=True)
    bytes_sent = Column(Integer, default=0)
    bytes_received = Column(Integer, default=0)
    request_count = Column(Integer, default=0)
    error_count = Column(Integer, default=0)
    avg_latency = Column(Float)
    state_changes = Column(JSON)
    metadata_ = Column("metadata", JSON)  # For future extensibility

    def to_dict(self):
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "circuit_id": self.circuit_id,
            "purpose": self.purpose,
            "isolation_group": self.isolation_group,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "request_count": self.request_count,
            "error_count": self.error_count,
            "avg_latency": self.avg_latency,
            "state_changes": self.state_changes or {},
        }


class MetricsAggregate(Base):
    """Pre-aggregated metrics for faster queries."""

    __tablename__ = "metrics_aggregates"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, index=True)
    time_window = Column(Integer)  # in seconds
    circuit_count = Column(Integer)
    request_count = Column(Integer)
    error_count = Column(Integer)
    bytes_sent = Column(Integer)
    bytes_received = Column(Integer)
    avg_latency = Column(Float)
    purpose = Column(String, index=True, nullable=True)  # NULL for all purposes
    isolation_group = Column(String, index=True, nullable=True)  # NULL for all groups

    def to_dict(self):
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "time_window": self.time_window,
            "circuit_count": self.circuit_count,
            "request_count": self.request_count,
            "error_count": self.error_count,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "avg_latency": self.avg_latency,
            "purpose": self.purpose,
            "isolation_group": self.isolation_group,
        }
