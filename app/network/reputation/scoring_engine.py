"""
Scoring Engine for Peer Reputation System.
Implements the core scoring algorithm for peer reputation.
"""

import math
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Callable, Any

from ...core.config import settings

@dataclass
class ScoreWeights:
    """Weights for different scoring factors."""
    uptime: float = 0.25
    response_time: float = 0.2
    success_rate: float = 0.25
    bandwidth: float = 0.15
    stability: float = 0.15
    
    def validate(self):
        """Ensure weights sum to 1.0."""
        total = sum([
            self.uptime,
            self.response_time,
            self.success_rate,
            self.bandwidth,
            self.stability
        ])
        if not math.isclose(total, 1.0, rel_tol=1e-5):
            raise ValueError(f"Score weights must sum to 1.0, got {total}")

@dataclass
class PeerMetrics:
    """Metrics collected for peer scoring."""
    uptime: float = 0.0  # 0.0 to 1.0
    response_time: float = 0.0  # in seconds
    success_rate: float = 0.0  # 0.0 to 1.0
    bandwidth: float = 0.0  # in MB/s
    stability: float = 0.0  # 0.0 to 1.0
    last_updated: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            'uptime': self.uptime,
            'response_time': self.response_time,
            'success_rate': self.success_rate,
            'bandwidth': self.bandwidth,
            'stability': self.stability,
            'last_updated': self.last_updated
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PeerMetrics':
        """Create metrics from dictionary."""
        return cls(**data)

class ScoringEngine:
    """Calculates and manages peer scores."""
    
    def __init__(
        self,
        weights: Optional[ScoreWeights] = None,
        decay_rate: float = 0.95,  # Score decay per day
        min_score: float = 0.0,
        max_score: float = 1000.0,
        initial_score: float = 100.0
    ):
        self.weights = weights or ScoreWeights()
        self.weights.validate()
        self.decay_rate = decay_rate
        self.min_score = min_score
        self.max_score = max_score
        self.initial_score = initial_score
        self.scores: Dict[str, float] = {}
        self.metrics: Dict[str, PeerMetrics] = {}
        self.last_updated: Dict[str, float] = {}
        
    def update_metrics(self, peer_id: str, metrics: PeerMetrics):
        """Update metrics for a peer."""
        self.metrics[peer_id] = metrics
        self.last_updated[peer_id] = time.time()
        self._update_score(peer_id)
        
    def _update_score(self, peer_id: str):
        """Recalculate score for a peer."""
        if peer_id not in self.metrics:
            self.scores[peer_id] = self.initial_score
            return
            
        metrics = self.metrics[peer_id]
        
        # Apply decay to existing score
        current_score = self.scores.get(peer_id, self.initial_score)
        decay = self._calculate_decay(peer_id)
        decayed_score = current_score * decay
        
        # Calculate new score components
        score = (
            (metrics.uptime * self.weights.uptime) +
            ((1.0 - min(metrics.response_time, 10.0) / 10.0) * self.weights.response_time) +
            (metrics.success_rate * self.weights.success_rate) +
            (min(metrics.bandwidth / 100.0, 1.0) * self.weights.bandwidth) +
            (metrics.stability * self.weights.stability)
        ) * 100.0  # Scale to 0-100 range
        
        # Apply weighted update
        weight = 0.3  # Weight for new metrics vs history
        new_score = (score * weight) + (decayed_score * (1 - weight))
        
        # Clamp score to valid range
        self.scores[peer_id] = max(self.min_score, min(self.max_score, new_score))
        
    def _calculate_decay(self, peer_id: str) -> float:
        """Calculate score decay since last update."""
        if peer_id not in self.last_updated:
            return 1.0
            
        days_since_update = (time.time() - self.last_updated[peer_id]) / 86400.0
        return math.pow(self.decay_rate, days_since_update)
    
    def get_score(self, peer_id: str) -> float:
        """Get current score for a peer, with decay applied."""
        if peer_id in self.scores:
            decay = self._calculate_decay(peer_id)
            return max(self.min_score, self.scores[peer_id] * decay)
        return self.initial_score
    
    def get_metrics(self, peer_id: str) -> Optional[PeerMetrics]:
        """Get current metrics for a peer."""
        return self.metrics.get(peer_id)
    
    def get_peer_rankings(self) -> List[Tuple[str, float]]:
        """Get list of peers sorted by score (highest first)."""
        return sorted(
            [(peer_id, self.get_score(peer_id)) for peer_id in self.scores],
            key=lambda x: x[1],
            reverse=True
        )
    
    def penalize_peer(self, peer_id: str, penalty: float, reason: str = ""):
        """Apply a penalty to a peer's score."""
        current = self.get_score(peer_id)
        self.scores[peer_id] = max(self.min_score, current - penalty)
        logger.warning(f"Penalized peer {peer_id}: -{penalty} points. Reason: {reason}")
    
    def reward_peer(self, peer_id: str, reward: float, reason: str = ""):
        """Apply a reward to a peer's score."""
        current = self.get_score(peer_id)
        self.scores[peer_id] = min(self.max_score, current + reward)
        logger.info(f"Rewarded peer {peer_id}: +{reward} points. Reason: {reason}")
    
    def reset_peer(self, peer_id: str):
        """Reset a peer's score to initial value."""
        self.scores[peer_id] = self.initial_score
        self.metrics.pop(peer_id, None)
        self.last_updated.pop(peer_id, None)
        logger.info(f"Reset score for peer {peer_id}")

# Example usage:
if __name__ == "__main__":
    # Initialize scoring engine
    weights = ScoreWeights(
        uptime=0.3,
        response_time=0.25,
        success_rate=0.25,
        bandwidth=0.1,
        stability=0.1
    )
    engine = ScoringEngine(weights=weights)
    
    # Update metrics for a peer
    metrics = PeerMetrics(
        uptime=0.99,
        response_time=0.15,
        success_rate=0.95,
        bandwidth=50.0,
        stability=0.9
    )
    engine.update_metrics("peer123", metrics)
    
    # Get peer score
    score = engine.get_score("peer123")
    print(f"Peer score: {score:.2f}")
    
    # Get rankings
    for rank, (peer_id, score) in enumerate(engine.get_peer_rankings(), 1):
        print(f"#{rank}: {peer_id} - {score:.2f}")
