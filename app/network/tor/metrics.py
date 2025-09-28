"""
Metrics storage and aggregation for Tor circuits.
"""
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

from sqlalchemy import create_engine, func, or_
from sqlalchemy.orm import sessionmaker, Session as DBSession

from .models import Base, CircuitMetricsModel, MetricsAggregate

logger = logging.getLogger(__name__)

class MetricsStorage:
    """Handles persistence of Tor metrics data."""
    
    def __init__(self, db_url: str = None):
        """Initialize metrics storage.
        
        Args:
            db_url: SQLAlchemy database URL. If None, uses SQLite in the user's data directory.
        """
        if db_url is None:
            from app.config import DATA_DIR
            db_path = Path(DATA_DIR) / 'tor_metrics.db'
            db_path.parent.mkdir(parents=True, exist_ok=True)
            db_url = f'sqlite:///{db_path}'
        
        self.engine = create_engine(db_url)
        self.Session = sessionmaker(bind=self.engine)
        
        # Create tables if they don't exist
        Base.metadata.create_all(self.engine)
        
        logger.info(f"Initialized metrics storage at {db_url}")
    
    def save_circuit_metrics(self, metrics: Dict[str, Any]) -> None:
        """Save circuit metrics to the database.
        
        Args:
            metrics: Dictionary containing circuit metrics
        """
        with self.Session() as session:
            # Convert timestamps to datetime
            created_at = datetime.fromtimestamp(metrics['created_at'])
            last_used = datetime.fromtimestamp(metrics['last_used'])
            
            # Convert state changes
            state_changes = {
                state: datetime.fromtimestamp(ts)
                for state, ts in metrics.get('state_changes', {}).items()
            }
            
            # Create or update metrics
            db_metrics = session.query(CircuitMetricsModel).get(metrics['circuit_id'])
            if db_metrics is None:
                db_metrics = CircuitMetricsModel(
                    id=metrics['circuit_id'],
                    circuit_id=metrics['circuit_id'],
                    purpose=metrics['purpose'],
                    isolation_group=metrics['isolation_group'],
                    created_at=created_at,
                    last_used=last_used,
                    bytes_sent=metrics['bytes_sent'],
                    bytes_received=metrics['bytes_received'],
                    request_count=metrics['request_count'],
                    error_count=metrics.get('error_count', 0),
                    avg_latency=metrics.get('avg_latency'),
                    state_changes=state_changes,
                    metadata_={}
                )
                session.add(db_metrics)
            else:
                # Update existing metrics
                db_metrics.last_used = last_used
                db_metrics.bytes_sent = metrics['bytes_sent']
                db_metrics.bytes_received = metrics['bytes_received']
                db_metrics.request_count = metrics['request_count']
                db_metrics.error_count = metrics.get('error_count', 0)
                db_metrics.avg_latency = metrics.get('avg_latency')
                db_metrics.state_changes = state_changes
            
            session.commit()
    
    def save_metrics_aggregate(self, metrics: Dict[str, Any]) -> None:
        """Save aggregated metrics to the database.
        
        Args:
            metrics: Dictionary containing aggregated metrics
        """
        with self.Session() as session:
            aggregate = MetricsAggregate(
                timestamp=datetime.fromtimestamp(metrics['timestamp']),
                time_window=metrics['time_window'],
                circuit_count=metrics['circuit_count'],
                request_count=metrics['total_requests'],
                error_count=metrics['total_errors'],
                bytes_sent=metrics['total_bytes_sent'],
                bytes_received=metrics['total_bytes_received'],
                avg_latency=metrics['avg_latency'],
                purpose=metrics.get('purpose'),
                isolation_group=metrics.get('isolation_group')
            )
            session.add(aggregate)
            session.commit()
    
    def get_circuit_metrics(
        self,
        circuit_id: str = None,
        purpose: str = None,
        isolation_group: str = None,
        start_time: datetime = None,
        end_time: datetime = None,
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """Get circuit metrics with optional filtering.
        
        Args:
            circuit_id: Filter by circuit ID
            purpose: Filter by purpose
            isolation_group: Filter by isolation group
            start_time: Filter by start time
            end_time: Filter by end time
            limit: Maximum number of results to return
            
        Returns:
            List of circuit metrics dictionaries
        """
        with self.Session() as session:
            query = session.query(CircuitMetricsModel)
            
            if circuit_id:
                query = query.filter(CircuitMetricsModel.circuit_id == circuit_id)
            if purpose:
                query = query.filter(CircuitMetricsModel.purpose == purpose)
            if isolation_group:
                query = query.filter(CircuitMetricsModel.isolation_group == isolation_group)
            if start_time:
                query = query.filter(CircuitMetricsModel.last_used >= start_time)
            if end_time:
                query = query.filter(CircuitMetricsModel.last_used <= end_time)
                
            results = query.order_by(CircuitMetricsModel.last_used.desc()).limit(limit).all()
            return [m.to_dict() for m in results]
    
    def get_metrics_summary(
        self,
        time_window: int = 300,
        purpose: str = None,
        isolation_group: str = None,
        start_time: datetime = None,
        end_time: datetime = None
    ) -> Dict[str, Any]:
        """Get a summary of metrics for the specified time period.
        
        Args:
            time_window: Time window in seconds
            purpose: Filter by purpose
            isolation_group: Filter by isolation group
            start_time: Start time for the summary
            end_time: End time for the summary
            
        Returns:
            Dictionary containing metrics summary
        """
        if end_time is None:
            end_time = datetime.utcnow()
        if start_time is None:
            start_time = end_time - timedelta(hours=24)
        
        time_span = end_time - start_time
        time_span_seconds = max(time_span.total_seconds(), 1)  # Avoid division by zero
        
        with self.Session() as session:
            # Get circuit metrics
            circuit_query = session.query(
                func.count(CircuitMetricsModel.id).label('circuit_count'),
                func.sum(CircuitMetricsModel.request_count).label('total_requests'),
                func.sum(CircuitMetricsModel.error_count).label('total_errors'),
                func.sum(CircuitMetricsModel.bytes_sent).label('total_bytes_sent'),
                func.sum(CircuitMetricsModel.bytes_received).label('total_bytes_received'),
                func.avg(CircuitMetricsModel.avg_latency).label('avg_latency')
            ).filter(
                CircuitMetricsModel.last_used >= start_time,
                CircuitMetricsModel.last_used <= end_time
            )
            
            if purpose is not None:
                circuit_query = circuit_query.filter(CircuitMetricsModel.purpose == purpose)
            if isolation_group is not None:
                circuit_query = circuit_query.filter(
                    CircuitMetricsModel.isolation_group == isolation_group
                )
            
            circuit_metrics = circuit_query.one()
            
            # Calculate rates
            total_requests = circuit_metrics.total_requests or 0
            total_errors = circuit_metrics.total_errors or 0
            total_bytes_sent = circuit_metrics.total_bytes_sent or 0
            total_bytes_received = circuit_metrics.total_bytes_received or 0
            
            return {
                'time_window': time_window,
                'time_span_seconds': time_span_seconds,
                'circuit_count': circuit_metrics.circuit_count or 0,
                'total_requests': total_requests,
                'total_errors': total_errors,
                'total_bytes_sent': total_bytes_sent,
                'total_bytes_received': total_bytes_received,
                'avg_latency': float(circuit_metrics.avg_latency) if circuit_metrics.avg_latency is not None else None,
                'request_rate': total_requests / time_span_seconds if time_span_seconds > 0 else 0,
                'error_rate': (total_errors / total_requests * 100) if total_requests > 0 else 0,
                'throughput_up': total_bytes_sent / time_span_seconds if time_span_seconds > 0 else 0,
                'throughput_down': total_bytes_received / time_span_seconds if time_span_seconds > 0 else 0,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat()
            }
    
    def cleanup_old_metrics(self, max_age_days: int = 30) -> int:
        """Remove metrics older than the specified number of days.
        
        Args:
            max_age_days: Maximum age in days to keep
            
        Returns:
            int: Number of records deleted
        """
        cutoff = datetime.utcnow() - timedelta(days=max_age_days)
        
        with self.Session() as session:
            # Delete old circuit metrics
            circuit_count = session.query(CircuitMetricsModel)\
                .filter(CircuitMetricsModel.last_used < cutoff)\
                .delete(synchronize_session=False)
            
            # Delete old aggregates
            aggregate_count = session.query(MetricsAggregate)\
                .filter(MetricsAggregate.timestamp < cutoff)\
                .delete(synchronize_session=False)
            
            session.commit()
            
            logger.info(
                f"Cleaned up {circuit_count} circuit metrics and "
                f"{aggregate_count} aggregates older than {cutoff}"
            )
            
            return circuit_count + aggregate_count
