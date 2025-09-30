"""
Stream management for the decentralized video platform.
Handles multiple video streams, peer connections, and quality adaptation.
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Callable, Awaitable

from aiortc import RTCPeerConnection, RTCSessionDescription, RTCDataChannel

from ..network.bandwidth import BandwidthMonitor, TrafficShaper, QoSManager
from .stream import VideoStream, StreamQuality, StreamStats

logger = logging.getLogger(__name__)

@dataclass
class StreamInfo:
    """Information about a video stream."""
    stream_id: str
    title: str
    description: str
    owner: str
    created_at: float
    viewers: Set[str] = field(default_factory=set)
    is_live: bool = False
    metadata: Dict = field(default_factory=dict)

class StreamManager:
    """Manages multiple video streams and their distribution."""
    
    def __init__(
        self,
        p2p_network,
        bandwidth_monitor: Optional[BandwidthMonitor] = None,
        traffic_shaper: Optional[TrafficShaper] = None,
        qos_manager: Optional[QoSManager] = None
    ):
        self.p2p_network = p2p_network
        self.bandwidth_monitor = bandwidth_monitor or BandwidthMonitor()
        self.traffic_shaper = traffic_shaper or TrafficShaper(self.bandwidth_monitor)
        self.qos_manager = qos_manager or QoSManager(self.bandwidth_monitor, self.traffic_shaper)
        
        self.streams: Dict[str, VideoStream] = {}
        self.stream_info: Dict[str, StreamInfo] = {}
        self.peer_streams: Dict[str, Set[str]] = {}  # peer_id -> set of stream_ids
        
        # Register message handlers
        self.p2p_network.register_message_handler("stream_offer", self._handle_stream_offer)
        self.p2p_network.register_message_handler("stream_answer", self._handle_stream_answer)
        self.p2p_network.register_message_handler("stream_ice_candidate", self._handle_ice_candidate)
        self.p2p_network.register_message_handler("stream_quality_change", self._handle_quality_change)
        
        # Start monitoring network conditions
        self._monitor_task = asyncio.create_task(self._monitor_network_conditions())
    
    async def create_stream(
        self,
        stream_id: str,
        title: str,
        description: str = "",
        owner: str = "",
        metadata: Optional[Dict] = None
    ) -> str:
        """Create a new video stream.
        
        Args:
            stream_id: Unique identifier for the stream
            title: Stream title
            description: Optional description
            owner: Owner's identifier
            metadata: Additional metadata
            
        Returns:
            str: Stream ID
        """
        if stream_id in self.streams:
            raise ValueError(f"Stream {stream_id} already exists")
        
        # Create peer connection for the stream
        pc = RTCPeerConnection()
        
        # Create video stream
        stream = VideoStream(
            stream_id=stream_id,
            peer_connection=pc,
            bandwidth_monitor=self.bandwidth_monitor,
            traffic_shaper=self.traffic_shaper,
            qos_manager=self.qos_manager,
            on_quality_change=self._on_stream_quality_change
        )
        
        # Store stream and info
        self.streams[stream_id] = stream
        self.stream_info[stream_id] = StreamInfo(
            stream_id=stream_id,
            title=title,
            description=description,
            owner=owner,
            created_at=time.time(),
            metadata=metadata or {}
        )
        
        logger.info(f"Created stream: {stream_id}")
        return stream_id
    
    async def start_stream(
        self,
        stream_id: str,
        video_source: str,
        is_live: bool = True
    ) -> None:
        """Start a video stream.
        
        Args:
            stream_id: ID of the stream to start
            video_source: Source of the video (file path or device)
            is_live: Whether this is a live stream
        """
        if stream_id not in self.streams:
            raise ValueError(f"Stream {stream_id} not found")
        
        stream = self.streams[stream_id]
        await stream.start(video_source)
        
        # Update stream info
        self.stream_info[stream_id].is_live = is_live
        self.stream_info[stream_id].metadata['started_at'] = time.time()
        
        logger.info(f"Started stream: {stream_id}")
    
    async def stop_stream(self, stream_id: str) -> None:
        """Stop a video stream."""
        if stream_id not in self.streams:
            return
        
        stream = self.streams[stream_id]
        await stream.stop()
        
        # Update stream info
        self.stream_info[stream_id].is_live = False
        self.stream_info[stream_id].metadata['stopped_at'] = time.time()
        
        # Notify viewers
        await self._notify_viewers(stream_id, "stream_ended", {"stream_id": stream_id})
        
        logger.info(f"Stopped stream: {stream_id}")
    
    async def add_viewer(self, stream_id: str, peer_id: str) -> None:
        """Add a viewer to a stream."""
        if stream_id not in self.streams:
            raise ValueError(f"Stream {stream_id} not found")
        
        # Add to stream viewers
        self.stream_info[stream_id].viewers.add(peer_id)
        
        # Update peer streams mapping
        if peer_id not in self.peer_streams:
            self.peer_streams[peer_id] = set()
        self.peer_streams[peer_id].add(stream_id)
        
        logger.info(f"Added viewer {peer_id} to stream {stream_id}")
    
    async def remove_viewer(self, stream_id: str, peer_id: str) -> None:
        """Remove a viewer from a stream."""
        if stream_id in self.stream_info:
            self.stream_info[stream_id].viewers.discard(peer_id)
        
        if peer_id in self.peer_streams:
            self.peer_streams[peer_id].discard(stream_id)
            if not self.peer_streams[peer_id]:
                del self.peer_streams[peer_id]
        
        logger.info(f"Removed viewer {peer_id} from stream {stream_id}")
    
    async def get_stream_info(self, stream_id: str) -> Optional[StreamInfo]:
        """Get information about a stream."""
        return self.stream_info.get(stream_id)
    
    async def list_streams(self) -> List[StreamInfo]:
        """Get a list of all streams."""
        return list(self.stream_info.values())
    
    async def _on_stream_quality_change(self, stream_id: str, quality: StreamQuality) -> None:
        """Handle stream quality changes."""
        logger.info(f"Stream {stream_id} quality changed to {quality}")
        
        # Notify viewers of quality change
        await self._notify_viewers(stream_id, "stream_quality_change", {
            "stream_id": stream_id,
            "quality": quality.value
        })
    
    async def _notify_viewers(self, stream_id: str, message_type: str, payload: Dict) -> None:
        """Send a message to all viewers of a stream."""
        if stream_id not in self.stream_info:
            return
        
        viewers = self.stream_info[stream_id].viewers.copy()
        for viewer_id in viewers:
            try:
                await self.p2p_network.send_message(
                    viewer_id,
                    message_type,
                    payload
                )
            except Exception as e:
                logger.error(f"Failed to notify viewer {viewer_id}: {e}")
                # Remove disconnected viewer
                await self.remove_viewer(stream_id, viewer_id)
    
    async def _monitor_network_conditions(self) -> None:
        """Monitor network conditions and adjust streams accordingly."""
        while True:
            try:
                # Get current network conditions
                stats = self.bandwidth_monitor.get_stats()
                
                # Adjust streams based on conditions
                for stream_id, stream in self.streams.items():
                    if not stream.is_active():
                        continue
                    
                    # Get current stream stats
                    stream_stats = stream.get_stats()
                    
                    # Adjust quality if needed
                    if self._needs_quality_adjustment(stream_stats, stats):
                        new_quality = self._determine_optimal_quality(stream_stats, stats)
                        await stream.set_quality(new_quality)
                
                await asyncio.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                logger.error(f"Error in network monitoring: {e}")
                await asyncio.sleep(5)
    
    def _needs_quality_adjustment(self, stream_stats: StreamStats, network_stats: Dict) -> bool:
        """Determine if stream quality needs adjustment based on network conditions."""
        # TODO: Implement more sophisticated quality adjustment logic
        return False
    
    def _determine_optimal_quality(self, stream_stats: StreamStats, network_stats: Dict) -> StreamQuality:
        """Determine the optimal stream quality based on network conditions."""
        # TODO: Implement quality selection logic
        return StreamQuality.MEDIUM
    
    # WebRTC signal handling
    
    async def _handle_stream_offer(self, peer_id: str, message: Dict) -> None:
        """Handle incoming WebRTC offer for a stream."""
        stream_id = message.get('stream_id')
        if not stream_id or stream_id not in self.streams:
            logger.warning(f"Invalid stream offer for unknown stream: {stream_id}")
            return
        
        try:
            # Add viewer to stream
            await self.add_viewer(stream_id, peer_id)
            
            # Handle WebRTC offer
            offer = RTCSessionDescription(
                sdp=message['sdp'],
                type=message['type']
            )
            
            stream = self.streams[stream_id]
            await stream.peer_connection.setRemoteDescription(offer)
            
            # Create and send answer
            answer = await stream.peer_connection.createAnswer()
            await stream.peer_connection.setLocalDescription(answer)
            
            await self.p2p_network.send_message(peer_id, "stream_answer", {
                'stream_id': stream_id,
                'sdp': stream.peer_connection.localDescription.sdp,
                'type': stream.peer_connection.localDescription.type
            })
            
        except Exception as e:
            logger.error(f"Error handling stream offer: {e}")
            await self.remove_viewer(stream_id, peer_id)
    
    async def _handle_stream_answer(self, peer_id: str, message: Dict) -> None:
        """Handle WebRTC answer from a viewer."""
        stream_id = message.get('stream_id')
        if not stream_id or stream_id not in self.streams:
            return
        
        try:
            answer = RTCSessionDescription(
                sdp=message['sdp'],
                type=message['type']
            )
            
            stream = self.streams[stream_id]
            await stream.peer_connection.setRemoteDescription(answer)
            
        except Exception as e:
            logger.error(f"Error handling stream answer: {e}")
            await self.remove_viewer(stream_id, peer_id)
    
    async def _handle_ice_candidate(self, peer_id: str, message: Dict) -> None:
        """Handle ICE candidate from a peer."""
        stream_id = message.get('stream_id')
        if not stream_id or stream_id not in self.streams:
            return
        
        try:
            candidate = message['candidate']
            sdp_mid = message.get('sdpMid')
            sdp_mline_index = message.get('sdpMLineIndex')
            
            stream = self.streams[stream_id]
            await stream.peer_connection.addIceCandidate({
                'candidate': candidate,
                'sdpMid': sdp_mid,
                'sdpMLineIndex': sdp_mline_index
            })
            
        except Exception as e:
            logger.error(f"Error handling ICE candidate: {e}")
    
    async def _handle_quality_change(self, peer_id: str, message: Dict) -> None:
        """Handle quality change request from a viewer."""
        stream_id = message.get('stream_id')
        quality_str = message.get('quality')
        
        if not stream_id or not quality_str or stream_id not in self.streams:
            return
        
        try:
            quality = StreamQuality(quality_str)
            stream = self.streams[stream_id]
            await stream.set_quality(quality)
            
        except (ValueError, KeyError) as e:
            logger.error(f"Invalid quality change request: {e}")
    
    async def close(self) -> None:
        """Clean up resources."""
        # Stop monitoring
        if hasattr(self, '_monitor_task') and not self._monitor_task.done():
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        
        # Stop all streams
        for stream_id in list(self.streams.keys()):
            await self.stop_stream(stream_id)
        
        # Clear data
        self.streams.clear()
        self.stream_info.clear()
        self.peer_streams.clear()
        
        logger.info("Stream manager stopped")
