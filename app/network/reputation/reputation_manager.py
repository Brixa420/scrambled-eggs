"""
Reputation Manager for Scrambled Eggs P2P Network.
Handles reputation data storage, propagation, and querying.
"""

import asyncio
import json
import logging
import time
from dataclasses import asdict
from typing import Dict, List, Optional, Set, Tuple, Any, Callable, Awaitable

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from ...core.crypto import CryptoEngine
from ..p2p.protocols import Message, MessageType

logger = logging.getLogger(__name__)

class ReputationRecord:
    """Represents a reputation record for a peer."""
    
    def __init__(
        self,
        peer_id: str,
        score: float,
        metrics: Dict[str, float],
        timestamp: float,
        signature: Optional[bytes] = None,
        signer_id: Optional[str] = None
    ):
        self.peer_id = peer_id
        self.score = score
        self.metrics = metrics
        self.timestamp = timestamp
        self.signature = signature
        self.signer_id = signer_id
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert record to dictionary."""
        return {
            'peer_id': self.peer_id,
            'score': self.score,
            'metrics': self.metrics,
            'timestamp': self.timestamp,
            'signature': self.signature.hex() if self.signature else None,
            'signer_id': self.signer_id
        }
        
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ReputationRecord':
        """Create record from dictionary."""
        signature = bytes.fromhex(data['signature']) if data.get('signature') else None
        return cls(
            peer_id=data['peer_id'],
            score=data['score'],
            metrics=data['metrics'],
            timestamp=data['timestamp'],
            signature=signature,
            signer_id=data.get('signer_id')
        )
    
    def sign(self, private_key: ed25519.Ed25519PrivateKey) -> bytes:
        """Sign the reputation record."""
        data = json.dumps({
            'peer_id': self.peer_id,
            'score': self.score,
            'metrics': self.metrics,
            'timestamp': self.timestamp
        }, sort_keys=True).encode()
        
        self.signature = private_key.sign(data)
        return self.signature
    
    def verify(self, public_key: ed25519.Ed25519PublicKey) -> bool:
        """Verify the signature of this record."""
        if not self.signature:
            return False
            
        data = json.dumps({
            'peer_id': self.peer_id,
            'score': self.score,
            'metrics': self.metrics,
            'timestamp': self.timestamp
        }, sort_keys=True).encode()
        
        try:
            public_key.verify(self.signature, data)
            return True
        except Exception as e:
            logger.warning(f"Signature verification failed: {e}")
            return False

class ReputationManager:
    """Manages peer reputation data and propagation."""
    
    def __init__(
        self,
        node_id: str,
        private_key: Optional[ed25519.Ed25519PrivateKey] = None,
        storage_path: Optional[str] = None,
        gossip_interval: float = 300.0,  # 5 minutes
        max_records: int = 1000,
        max_gossip_peers: int = 10
    ):
        self.node_id = node_id
        self.private_key = private_key or ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.storage_path = storage_path
        self.gossip_interval = gossip_interval
        self.max_records = max_records
        self.max_gossip_peers = max_gossip_peers
        
        # In-memory storage
        self.records: Dict[str, Dict[str, ReputationRecord]] = {}
        self.peer_scores: Dict[str, float] = {}
        self.known_peers: Set[str] = set()
        
        # Gossip state
        self._gossip_task: Optional[asyncio.Task] = None
        self._running = False
        
    async def start(self):
        """Start the reputation manager."""
        if self._running:
            return
            
        self._running = True
        
        # Load persisted data
        await self._load_data()
        
        # Start background tasks
        self._gossip_task = asyncio.create_task(self._gossip_loop())
        
        logger.info("Reputation manager started")
        
    async def stop(self):
        """Stop the reputation manager."""
        if not self._running:
            return
            
        self._running = False
        
        # Cancel background tasks
        if self._gossip_task and not self._gossip_task.done():
            self._gossip_task.cancel()
            try:
                await self._gossip_task
            except asyncio.CancelledError:
                pass
                
        # Save data
        await self._save_data()
        
        logger.info("Reputation manager stopped")
        
    async def _load_data(self):
        """Load reputation data from storage."""
        if not self.storage_path:
            return
            
        try:
            with open(self.storage_path, 'r') as f:
                data = json.load(f)
                
            # Load records
            for peer_id, records in data.get('records', {}).items():
                self.records[peer_id] = {
                    r['signer_id']: ReputationRecord.from_dict(r)
                    for r in records
                }
                
            # Update scores
            self._update_scores()
            
        except FileNotFoundError:
            logger.info("No existing reputation data found, starting fresh")
        except Exception as e:
            logger.error(f"Error loading reputation data: {e}")
            
    async def _save_data(self):
        """Save reputation data to storage."""
        if not self.storage_path:
            return
            
        try:
            # Convert records to serializable format
            serialized = {
                'records': {
                    peer_id: [r.to_dict() for r in records.values()]
                    for peer_id, records in self.records.items()
                },
                'timestamp': time.time()
            }
            
            # Save to file
            with open(self.storage_path, 'w') as f:
                json.dump(serialized, f, indent=2)
                
        except Exception as e:
            logger.error(f"Error saving reputation data: {e}")
            
    def _update_scores(self):
        """Update aggregated scores from records."""
        for peer_id, records in self.records.items():
            if not records:
                continue
                
            # Calculate weighted average score
            total_weight = 0.0
            weighted_sum = 0.0
            
            for record in records.values():
                # Weight more recent records higher
                age = (time.time() - record.timestamp) / 86400.0  # in days
                weight = 1.0 / (1.0 + age)  # Decay with age
                
                weighted_sum += record.score * weight
                total_weight += weight
                
            if total_weight > 0:
                self.peer_scores[peer_id] = weighted_sum / total_weight
                
    async def update_reputation(
        self,
        peer_id: str,
        score: float,
        metrics: Dict[str, float],
        sign: bool = True
    ) -> ReputationRecord:
        """Update reputation for a peer."""
        # Create new record
        record = ReputationRecord(
            peer_id=peer_id,
            score=score,
            metrics=metrics,
            timestamp=time.time(),
            signer_id=self.node_id
        )
        
        # Sign the record
        if sign:
            record.sign(self.private_key)
            
        # Store the record
        if peer_id not in self.records:
            self.records[peer_id] = {}
            
        self.records[peer_id][self.node_id] = record
        self._update_scores()
        
        # Save data
        await self._save_data()
        
        return record
    
    def get_reputation(self, peer_id: str) -> Optional[float]:
        """Get the current reputation score for a peer."""
        return self.peer_scores.get(peer_id)
    
    def get_records(self, peer_id: str) -> List[ReputationRecord]:
        """Get all reputation records for a peer."""
        return list(self.records.get(peer_id, {}).values())
    
    async def receive_records(self, records: List[ReputationRecord]) -> int:
        """Process received reputation records from other nodes."""
        added = 0
        
        for record in records:
            # Skip our own records
            if record.signer_id == self.node_id:
                continue
                
            # Validate signature
            # In a real implementation, we would verify the signer's public key
            
            # Store the record
            if record.peer_id not in self.records:
                self.records[record.peer_id] = {}
                
            # Only keep the most recent record from each signer
            existing = self.records[record.peer_id].get(record.signer_id)
            if not existing or existing.timestamp < record.timestamp:
                self.records[record.peer_id][record.signer_id] = record
                added += 1
                
        if added > 0:
            self._update_scores()
            await self._save_data()
            
        return added
    
    async def _gossip_loop(self):
        """Background task to gossip reputation data."""
        while self._running:
            try:
                await self._gossip_round()
                await asyncio.sleep(self.gossip_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in gossip loop: {e}")
                await asyncio.sleep(60)  # Back off on error
                
    async def _gossip_round(self):
        """Perform one round of gossip."""
        if not self.records:
            return
            
        # Select random peers to gossip with
        peers = list(self.known_peers)
        if not peers:
            return
            
        # Limit number of peers to gossip with
        gossip_peers = min(len(peers), self.max_gossip_peers)
        selected_peers = set()
        
        # Ensure we have enough peers
        while len(selected_peers) < gossip_peers and len(selected_peers) < len(peers):
            # In a real implementation, we would select peers based on network topology
            import random
            peer = random.choice(peers)
            if peer not in selected_peers and peer != self.node_id:
                selected_peers.add(peer)
                
        # Prepare records to send
        records_to_send = []
        for peer_records in self.records.values():
            records_to_send.extend(peer_records.values())
            
        # In a real implementation, we would send these records to the selected peers
        # using the P2P network's message passing system
        logger.debug(f"Would gossip {len(records_to_send)} records to {len(selected_peers)} peers")
        
    def handle_gossip_message(self, message: Message) -> Message:
        """Handle an incoming gossip message."""
        try:
            if message.type == MessageType.REPUTATION_UPDATE:
                records = [ReputationRecord.from_dict(r) for r in message.data['records']]
                added = await self.receive_records(records)
                return Message(
                    type=MessageType.REPUTATION_UPDATE_ACK,
                    data={'received': len(records), 'added': added}
                )
                
        except Exception as e:
            logger.error(f"Error handling gossip message: {e}")
            return Message(
                type=MessageType.ERROR,
                data={'error': str(e)}
            )
            
    def get_top_peers(self, limit: int = 10) -> List[Tuple[str, float]]:
        """Get top peers by reputation score."""
        return sorted(
            self.peer_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )[:limit]
