"""
Model monitoring service for tracking model performance and predictions.
"""
from datetime import datetime
from typing import Dict, Any, List, Optional
import logging
import json
from pathlib import Path
import numpy as np
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

class PredictionRecord(BaseModel):
    """Record of a single prediction."""
    model_name: str
    model_version: str
    input_data: Dict[str, Any]
    prediction: Any
    confidence: Optional[float] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = {}

class PerformanceMetrics(BaseModel):
    """Model performance metrics."""
    model_name: str
    model_version: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metrics: Dict[str, float] = {}
    num_predictions: int = 0
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class ModelMonitor:
    """Monitor model predictions and performance."""
    
    def __init__(self, storage_path: str = "monitoring"):
        """Initialize the model monitor."""
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # In-memory storage for recent predictions
        self.recent_predictions: List[PredictionRecord] = []
        self.max_recent_predictions = 1000
        
        # Performance metrics
        self.performance_metrics: Dict[str, PerformanceMetrics] = {}
    
    def log_prediction(
        self,
        model_name: str,
        model_version: str,
        input_data: Dict[str, Any],
        prediction: Any,
        confidence: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log a prediction."""
        record = PredictionRecord(
            model_name=model_name,
            model_version=model_version,
            input_data=input_data,
            prediction=prediction,
            confidence=confidence,
            metadata=metadata or {}
        )
        
        # Add to recent predictions
        self.recent_predictions.append(record)
        if len(self.recent_predictions) > self.max_recent_predictions:
            self.recent_predictions.pop(0)
        
        # Save to disk
        self._save_prediction(record)
    
    def update_metrics(
        self,
        model_name: str,
        model_version: str,
        metrics: Dict[str, float],
        increment_count: bool = True
    ) -> None:
        """Update performance metrics for a model."""
        key = f"{model_name}:{model_version}"
        
        if key not in self.performance_metrics:
            self.performance_metrics[key] = PerformanceMetrics(
                model_name=model_name,
                model_version=model_version,
                metrics=metrics.copy(),
                num_predictions=1 if increment_count else 0
            )
        else:
            # Update existing metrics
            existing = self.performance_metrics[key]
            for k, v in metrics.items():
                if k in existing.metrics:
                    # For numeric metrics, calculate a running average
                    if isinstance(v, (int, float)) and isinstance(existing.metrics[k], (int, float)):
                        existing.metrics[k] = (existing.metrics[k] * existing.num_predictions + v) / \
                                            (existing.num_predictions + (1 if increment_count else 0))
                else:
                    existing.metrics[k] = v
            
            if increment_count:
                existing.num_predictions += 1
            
            existing.timestamp = datetime.utcnow()
        
        # Save metrics to disk
        self._save_metrics()
    
    def get_metrics(
        self,
        model_name: str,
        model_version: Optional[str] = None
    ) -> List[PerformanceMetrics]:
        """Get performance metrics for a model."""
        if model_version:
            key = f"{model_name}:{model_version}"
            return [self.performance_metrics[key]] if key in self.performance_metrics else []
        else:
            return [
                metrics for key, metrics in self.performance_metrics.items()
                if key.startswith(f"{model_name}:")
            ]
    
    def detect_drift(
        self,
        model_name: str,
        model_version: str,
        reference_metrics: Dict[str, float],
        threshold: float = 0.1
    ) -> Dict[str, Any]:
        """Detect drift in model performance."""
        key = f"{model_name}:{model_version}"
        if key not in self.performance_metrics:
            return {"drift_detected": False, "reason": "No metrics available"}
        
        current_metrics = self.performance_metrics[key].metrics
        drift_metrics = {}
        
        for metric_name, ref_value in reference_metrics.items():
            if metric_name in current_metrics:
                current_value = current_metrics[metric_name]
                if isinstance(ref_value, (int, float)) and isinstance(current_value, (int, float)):
                    change = abs((current_value - ref_value) / ref_value)
                    drift_metrics[metric_name] = {
                        "current": current_value,
                        "reference": ref_value,
                        "change": change,
                        "drift_detected": change > threshold
                    }
        
        drift_detected = any(
            m.get("drift_detected", False)
            for m in drift_metrics.values()
        )
        
        return {
            "drift_detected": drift_detected,
            "metrics": drift_metrics,
            "threshold": threshold
        }
    
    def _save_prediction(self, record: PredictionRecord) -> None:
        """Save prediction to disk."""
        try:
            date_str = record.timestamp.strftime("%Y-%m-%d")
            log_dir = self.storage_path / "predictions" / record.model_name / record.model_version / date_str
            log_dir.mkdir(parents=True, exist_ok=True)
            
            # Create a unique filename
            timestamp_str = record.timestamp.strftime("%H%M%S")
            filename = f"{timestamp_str}_{record.timestamp.timestamp()}.json"
            
            with open(log_dir / filename, 'w') as f:
                f.write(record.json())
        except Exception as e:
            logger.error(f"Failed to save prediction: {str(e)}")
    
    def _save_metrics(self) -> None:
        """Save metrics to disk."""
        try:
            metrics_dir = self.storage_path / "metrics"
            metrics_dir.mkdir(parents=True, exist_ok=True)
            
            for key, metrics in self.performance_metrics.items():
                filename = f"{key.replace(':', '_')}.json"
                with open(metrics_dir / filename, 'w') as f:
                    f.write(metrics.json())
        except Exception as e:
            logger.error(f"Failed to save metrics: {str(e)}")

# Global monitor instance
monitor = ModelMonitor()
