"""
Raft Consensus Algorithm Implementation

This module implements the Raft consensus algorithm for distributed consensus
in the Brixa network.
"""
import asyncio
import json
import logging
import random
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple, Any, Callable, Union

# Type aliases
NodeId = str
Term = int
LogIndex = int
Command = Any

# RPC message types
class MessageType(Enum):
    REQUEST_VOTE = "RequestVote"
    REQUEST_VOTE_RESPONSE = "RequestVoteResponse"
    APPEND_ENTRIES = "AppendEntries"
    APPEND_ENTRIES_RESPONSE = "AppendEntriesResponse"
    INSTALL_SNAPSHOT = "InstallSnapshot"
    INSTALL_SNAPSHOT_RESPONSE = "InstallSnapshotResponse"


@dataclass
class LogEntry:
    """A single entry in the Raft log."""
    term: Term
    index: LogIndex
    command: Command


@dataclass
class RaftConfig:
    """Configuration for a Raft node."""
    node_id: NodeId
    heartbeat_interval: float = 0.05  # seconds
    election_timeout_min: float = 0.15  # seconds
    election_timeout_max: float = 0.3   # seconds
    rpc_timeout: float = 0.1           # seconds
    snapshot_threshold: int = 1000      # Number of log entries before snapshotting


class RaftState(Enum):
    """Possible states of a Raft node."""
    FOLLOWER = auto()
    CANDIDATE = auto()
    LEADER = auto()


@dataclass
class RaftNode:
    """
    A node in the Raft consensus cluster.
    
    Implements the Raft consensus algorithm for managing a replicated log.
    """
    
    def __init__(self, config: RaftConfig, rpc_handler: Callable):
        """
        Initialize a Raft node.
        
        Args:
            config: Configuration for this node
            rpc_handler: Function to send RPCs to other nodes
        """
        self.config = config
        self.rpc_handler = rpc_handler
        
        # Persistent state (must be stored on disk before responding to RPCs)
        self.current_term: Term = 0
        self.voted_for: Optional[NodeId] = None
        self.log: List[LogEntry] = []
        
        # Volatile state
        self.commit_index: LogIndex = 0
        self.last_applied: LogIndex = 0
        
        # Volatile state for leaders
        self.next_index: Dict[NodeId, LogIndex] = {}
        self.match_index: Dict[NodeId, LogIndex] = {}
        
        # Node state
        self.state: RaftState = RaftState.FOLLOWER
        self.leader_id: Optional[NodeId] = None
        self.votes_received: Set[NodeId] = set()
        
        # Timers
        self.election_timeout: float = 0
        self.last_heartbeat: float = 0
        
        # Callbacks
        self.on_leader_change: Optional[Callable[[bool], None]] = None
        self.on_commit: Optional[Callable[[LogEntry], None]] = None
        
        # Initialize the election timeout
        self._reset_election_timeout()
    
    def _reset_election_timeout(self):
        """Set a new random election timeout."""
        self.election_timeout = random.uniform(
            self.config.election_timeout_min,
            self.config.election_timeout_max
        )
        self.last_heartbeat = time.monotonic()
    
    async def start(self):
        """Start the Raft node's main loop."""
        while True:
            if self.state == RaftState.LEADER:
                await self._leader_loop()
            elif self.state == RaftState.CANDIDATE:
                await self._candidate_loop()
            else:  # FOLLOWER
                await self._follower_loop()
    
    async def _follower_loop(self):
        """The main loop for follower nodes."""
        while self.state == RaftState.FOLLOWER:
            elapsed = time.monotonic() - self.last_heartbeat
            
            # Check if we should start an election
            if elapsed > self.election_timeout:
                self._become_candidate()
                return
            
            # Sleep for a short time to avoid busy-waiting
            await asyncio.sleep(min(0.01, self.election_timeout - elapsed))
    
    async def _candidate_loop(self):
        """The main loop for candidate nodes."""
        # Start an election
        self.current_term += 1
        self.voted_for = self.config.node_id
        self.votes_received = {self.config.node_id}
        
        # Request votes from other nodes
        last_log_index, last_log_term = self._get_last_log_info()
        
        for peer_id in self._get_peer_ids():
            asyncio.create_task(self._request_vote(peer_id, last_log_index, last_log_term))
        
        # Wait for election results
        while self.state == RaftState.CANDIDATE:
            elapsed = time.monotonic() - self.last_heartbeat
            
            # Check if we've won the election
            if self._has_quorum():
                self._become_leader()
                return
            
            # Check if we should start a new election
            if elapsed > self.election_timeout:
                self._reset_election_timeout()
                return  # Will start a new election on next iteration
            
            await asyncio.sleep(0.01)
    
    async def _leader_loop(self):
        """The main loop for leader nodes."""
        # Initialize leader state
        last_log_index = len(self.log)
        for peer_id in self._get_peer_ids():
            self.next_index[peer_id] = last_log_index + 1
            self.match_index[peer_id] = 0
        
        # Send initial empty AppendEntries RPCs (heartbeat)
        self._broadcast_heartbeat()
        
        # Main leader loop
        while self.state == RaftState.LEADER:
            # Send heartbeats periodically
            elapsed = time.monotonic() - self.last_heartbeat
            if elapsed >= self.config.heartbeat_interval:
                self._broadcast_heartbeat()
            
            # Check for committed entries
            self._update_commit_index()
            
            # Apply committed entries to the state machine
            await self._apply_committed_entries()
            
            await asyncio.sleep(0.01)
    
    def _has_quorum(self) -> bool:
        """Check if we have a quorum of votes."""
        total_nodes = len(self._get_peer_ids()) + 1  # +1 for self
        return len(self.votes_received) > (total_nodes // 2)
    
    def _get_peer_ids(self) -> List[NodeId]:
        """Get the IDs of all other nodes in the cluster."""
        # In a real implementation, this would come from configuration
        return []
    
    def _get_last_log_info(self) -> Tuple[LogIndex, Term]:
        """Get the index and term of the last log entry."""
        if not self.log:
            return (0, 0)
        last_entry = self.log[-1]
        return (last_entry.index, last_entry.term)
    
    def _become_candidate(self):
        """Transition to candidate state and start a new election."""
        self.state = RaftState.CANDIDATE
        self.leader_id = None
        self._reset_election_timeout()
    
    def _become_leader(self):
        """Transition to leader state."""
        self.state = RaftState.LEADER
        self.leader_id = self.config.node_id
        
        # Notify the application that we've become the leader
        if self.on_leader_change:
            self.on_leader_change(True)
    
    def _become_follower(self, term: Term, leader_id: Optional[NodeId] = None):
        """Transition to follower state."""
        was_leader = self.state == RaftState.LEADER
        self.state = RaftState.FOLLOWER
        self.current_term = term
        self.leader_id = leader_id
        self.voted_for = None
        self.votes_received.clear()
        self._reset_election_timeout()
        
        # Notify the application if we were the leader and are stepping down
        if was_leader and self.on_leader_change:
            self.on_leader_change(False)
    
    async def _request_vote(self, peer_id: NodeId, last_log_index: LogIndex, last_log_term: Term):
        """Send a RequestVote RPC to a peer."""
        request = {
            "type": MessageType.REQUEST_VOTE,
            "term": self.current_term,
            "candidate_id": self.config.node_id,
            "last_log_index": last_log_index,
            "last_log_term": last_log_term,
        }
        
        try:
            response = await asyncio.wait_for(
                self.rpc_handler(peer_id, request),
                timeout=self.config.rpc_timeout
            )
            await self._handle_vote_response(peer_id, response)
        except (asyncio.TimeoutError, Exception) as e:
            logging.warning(f"RequestVote RPC to {peer_id} failed: {e}")
    
    async def _handle_vote_response(self, peer_id: NodeId, response: Dict):
        """Handle a response to a RequestVote RPC."""
        if self.state != RaftState.CANDIDATE:
            return
        
        # Update term if we see a newer one
        if response["term"] > self.current_term:
            self._become_follower(response["term"])
            return
        
        # Only process the vote if we're still in the same term
        if response["term"] == self.current_term and response["vote_granted"]:
            self.votes_received.add(peer_id)
    
    def _broadcast_heartbeat(self):
        """Send heartbeats to all followers."""
        self.last_heartbeat = time.monotonic()
        
        for peer_id in self._get_peer_ids():
            asyncio.create_task(self._send_append_entries(peer_id))
    
    async def _send_append_entries(self, peer_id: NodeId):
        """Send an AppendEntries RPC to a follower."""
        next_idx = self.next_index.get(peer_id, 1)
        prev_log_index = next_idx - 1
        prev_log_term = 0
        
        # Find the previous log term
        if prev_log_index > 0:
            for entry in reversed(self.log):
                if entry.index == prev_log_index:
                    prev_log_term = entry.term
                    break
        
        # Get the entries to send
        entries = []
        if next_idx <= len(self.log):
            entries = [
                {"term": entry.term, "index": entry.index, "command": entry.command}
                for entry in self.log[next_idx - 1:]
            ]
        
        request = {
            "type": MessageType.APPEND_ENTRIES,
            "term": self.current_term,
            "leader_id": self.config.node_id,
            "prev_log_index": prev_log_index,
            "prev_log_term": prev_log_term,
            "entries": entries,
            "leader_commit": self.commit_index,
        }
        
        try:
            response = await asyncio.wait_for(
                self.rpc_handler(peer_id, request),
                timeout=self.config.rpc_timeout
            )
            await self._handle_append_entries_response(peer_id, response)
        except (asyncio.TimeoutError, Exception) as e:
            logging.warning(f"AppendEntries RPC to {peer_id} failed: {e}")
    
    async def _handle_append_entries_response(self, peer_id: NodeId, response: Dict):
        """Handle a response to an AppendEntries RPC."""
        # Update term if we see a newer one
        if response["term"] > self.current_term:
            self._become_follower(response["term"])
            return
        
        if self.state != RaftState.LEADER or response["term"] != self.current_term:
            return
        
        if response["success"]:
            # Update match index and next index for this follower
            new_index = response["match_index"]
            self.match_index[peer_id] = new_index
            self.next_index[peer_id] = new_index + 1
        else:
            # Decrement next index and retry
            if self.next_index[peer_id] > 1:
                self.next_index[peer_id] -= 1
                asyncio.create_task(self._send_append_entries(peer_id))
    
    def _update_commit_index(self):
        """Update the commit index based on match indices."""
        if self.state != RaftState.LEADER:
            return
        
        # Get all match indices, including the leader's
        match_indices = list(self.match_index.values()) + [len(self.log)]
        match_indices.sort(reverse=True)
        
        # Find the highest index that's replicated on a majority of nodes
        quorum_index = match_indices[len(match_indices) // 2]
        
        # Only update commit index if the entry is from the current term
        if quorum_index > self.commit_index and self.log[quorum_index - 1].term == self.current_term:
            self.commit_index = quorum_index
    
    async def _apply_committed_entries(self):
        """Apply committed entries to the state machine."""
        while self.last_applied < self.commit_index:
            self.last_applied += 1
            entry = self.log[self.last_applied - 1]
            
            # Apply the entry to the state machine
            if self.on_commit:
                self.on_commit(entry)
    
    # Public API
    
    async def submit_command(self, command: Command) -> bool:
        """
        Submit a command to be replicated to the cluster.
        
        Args:
            command: The command to submit
            
        Returns:
            bool: True if the command was accepted, False otherwise
        """
        if self.state != RaftState.LEADER:
            return False
        
        # Create a new log entry
        entry = LogEntry(
            term=self.current_term,
            index=len(self.log) + 1,
            command=command
        )
        
        # Append to local log
        self.log.append(entry)
        
        # Replicate to followers
        self._broadcast_heartbeat()
        
        return True
    
    async def handle_rpc(self, message: Dict) -> Dict:
        """
        Handle an incoming RPC message.
        
        Args:
            message: The incoming RPC message
            
        Returns:
            Dict: The response to send back
        """
        message_type = message.get("type")
        
        # Update term if we see a newer one
        if "term" in message and message["term"] > self.current_term:
            self._become_follower(message["term"])
        
        # Handle the message based on its type
        if message_type == MessageType.REQUEST_VOTE:
            return await self._handle_request_vote(message)
        elif message_type == MessageType.APPEND_ENTRIES:
            return await self._handle_append_entries(message)
        else:
            return {"term": self.current_term, "success": False, "error": "unknown message type"}
    
    async def _handle_request_vote(self, request: Dict) -> Dict:
        """Handle a RequestVote RPC."""
        # Check if the request is from an old term
        if request["term"] < self.current_term:
            return {"term": self.current_term, "vote_granted": False}
        
        # If we see a newer term, become a follower
        if request["term"] > self.current_term:
            self._become_follower(request["term"])
        
        # Check if we've already voted for someone else this term
        if self.voted_for is not None and self.voted_for != request["candidate_id"]:
            return {"term": self.current_term, "vote_granted": False}
        
        # Check if the candidate's log is at least as up-to-date as ours
        last_log_index, last_log_term = self._get_last_log_info()
        if (request["last_log_term"] < last_log_term or 
            (request["last_log_term"] == last_log_term and 
             request["last_log_index"] < last_log_index)):
            return {"term": self.current_term, "vote_granted": False}
        
        # Grant the vote
        self.voted_for = request["candidate_id"]
        self._reset_election_timeout()
        
        return {"term": self.current_term, "vote_granted": True}
    
    async def _handle_append_entries(self, request: Dict) -> Dict:
        """Handle an AppendEntries RPC."""
        # Check if the request is from an old term
        if request["term"] < self.current_term:
            return {"term": self.current_term, "success": False}
        
        # If we see a newer term, become a follower
        if request["term"] > self.current_term:
            self._become_follower(request["term"], request["leader_id"])
        
        # Reset election timeout since we heard from the leader
        self._reset_election_timeout()
        
        # Check if the previous log entry matches
        if request["prev_log_index"] > 0:
            if (len(self.log) < request["prev_log_index"] or 
                (request["prev_log_index"] > 0 and 
                 self.log[request["prev_log_index"] - 1].term != request["prev_log_term"])):
                return {"term": self.current_term, "success": False, "match_index": len(self.log)}
        
        # Append any new entries
        if request["entries"]:
            # Delete any conflicting entries
            if len(self.log) > request["prev_log_index"]:
                self.log = self.log[:request["prev_log_index"]]
            
            # Append new entries
            for entry_data in request["entries"]:
                entry = LogEntry(
                    term=entry_data["term"],
                    index=entry_data["index"],
                    command=entry_data["command"]
                )
                self.log.append(entry)
        
        # Update commit index
        if request["leader_commit"] > self.commit_index:
            self.commit_index = min(request["leader_commit"], len(self.log))
            
            # Apply committed entries
            await self._apply_committed_entries()
        
        return {
            "term": self.current_term,
            "success": True,
            "match_index": len(self.log)
        }
