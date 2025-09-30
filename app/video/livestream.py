"""
Live streaming module for the decentralized video platform.
Handles real-time video streaming with DVR functionality.
"""

import asyncio
import logging
import os
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Deque, Dict, List, Optional, Set, Tuple, Callable, Awaitable

from ..network.p2p import P2PNetwork
from .transcoder import VideoTranscoder, VideoFormat, TranscodingProfile

logger = logging.getLogger(__name__)

class StreamState(Enum):
    """State of a live stream."""
    CREATED = "created"
    STARTING = "starting"
    LIVE = "live"
    PAUSED = "paused"
    STOPPED = "stopped"
    ERROR = "error"

@dataclass
class StreamSegment:
    """Represents a segment of a live stream."""
    sequence: int
    timestamp: float
    duration: float
    data: bytes
    is_keyframe: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class StreamViewer:
    """Represents a viewer of a live stream."""
    peer_id: str
    quality: str = "auto"
    buffer_size: int = 10  # Number of segments to buffer
    last_seen: float = field(default_factory=lambda: time.time())
    
    def update_last_seen(self) -> None:
        """Update the last seen timestamp."""
        self.last_seen = time.time()

class DVRBuffer:
    """Circular buffer for DVR functionality."""
    
    def __init__(self, max_duration: float = 3600):
        """
        Initialize the DVR buffer.
        
        Args:
            max_duration: Maximum duration in seconds to keep in the buffer
        """
        self.max_duration = max_duration
        self.segments: Deque[StreamSegment] = deque()
        self._lock = asyncio.Lock()
        self._start_time: Optional[float] = None
        self._end_time: Optional[float] = None
        self._sequence = 0
    
    @property
    def duration(self) -> float:
        """Get the current duration of the buffer."""
        if not self._start_time or not self._end_time:
            return 0.0
        return self._end_time - self._start_time
    
    @property
    def start_time(self) -> Optional[float]:
        """Get the start time of the buffer."""
        return self._start_time
    
    @property
    def end_time(self) -> Optional[float]:
        """Get the end time of the buffer."""
        return self._end_time
    
    async def add_segment(self, data: bytes, duration: float, is_keyframe: bool = False) -> int:
        """
        Add a segment to the buffer.
        
        Args:
            data: Segment data
            duration: Duration of the segment in seconds
            is_keyframe: Whether this is a keyframe segment
            
        Returns:
            The sequence number of the added segment
        """
        async with self._lock:
            timestamp = time.time()
            
            # Update start and end times
            if self._start_time is None:
                self._start_time = timestamp
            self._end_time = timestamp
            
            # Create and add the segment
            segment = StreamSegment(
                sequence=self._sequence,
                timestamp=timestamp,
                duration=duration,
                data=data,
                is_keyframe=is_keyframe
            )
            self.segments.append(segment)
            self._sequence += 1
            
            # Remove old segments if we're over the max duration
            await self._cleanup()
            
            return segment.sequence
    
    async def get_segments_since(
        self,
        timestamp: Optional[float] = None,
        sequence: Optional[int] = None,
        max_duration: Optional[float] = None
    ) -> List[StreamSegment]:
        """
        Get segments since a specific timestamp or sequence number.
        
        Args:
            timestamp: Get segments since this timestamp
            sequence: Get segments after this sequence number
            max_duration: Maximum duration of segments to return
            
        Returns:
            List of matching segments
        """
        async with self._lock:
            if not self.segments:
                return []
                
            # If no reference point is given, return all segments
            if timestamp is None and sequence is None:
                return list(self.segments)
            
            # Find the first segment that matches the criteria
            start_idx = 0
            if timestamp is not None:
                # Find the first segment with timestamp > reference
                for i, seg in enumerate(self.segments):
                    if seg.timestamp > timestamp:
                        start_idx = i
                        break
            elif sequence is not None:
                # Find the first segment with sequence > reference
                for i, seg in enumerate(self.segments):
                    if seg.sequence > sequence:
                        start_idx = i
                        break
            
            # Get all segments from the start index
            result = list(self.segments)[start_idx:]
            
            # Apply max duration filter if specified
            if max_duration is not None and result:
                end_time = result[-1].timestamp
                result = [
                    seg for seg in result
                    if (end_time - seg.timestamp) <= max_duration
                ]
            
            return result
    
    async def get_latest_segment(self) -> Optional[StreamSegment]:
        """Get the most recent segment."""
        async with self._lock:
            if not self.segments:
                return None
            return self.segments[-1]
    
    async def clear(self) -> None:
        """Clear the buffer."""
        async with self._lock:
            self.segments.clear()
            self._start_time = None
            self._end_time = None
    
    async def _cleanup(self) -> None:
        """Remove old segments that exceed the max duration."""
        if not self.segments or self._start_time is None or self._end_time is None:
            return
            
        while self.duration > self.max_duration and len(self.segments) > 1:
            # Keep at least one segment to maintain timing
            removed = self.segments.popleft()
            self._start_time = self.segments[0].timestamp

class LiveStream:
    """Manages a single live stream with DVR capabilities."""
    
    def __init__(
        self,
        stream_id: str,
        owner_id: str,
        p2p_network: P2PNetwork,
        storage_dir: str = "./streams",
        dvr_enabled: bool = True,
        dvr_duration: float = 3600,  # 1 hour
        transcoding_profiles: Optional[Dict[str, TranscodingProfile]] = None
    ):
        """
        Initialize a live stream.
        
        Args:
            stream_id: Unique identifier for the stream
            owner_id: ID of the stream owner
            p2p_network: P2P network instance for distribution
            storage_dir: Base directory for stream storage
            dvr_enabled: Whether DVR functionality is enabled
            dvr_duration: Maximum DVR duration in seconds
            transcoding_profiles: Custom transcoding profiles
        """
        self.stream_id = stream_id
        self.owner_id = owner_id
        self.p2p_network = p2p_network
        self.state = StreamState.CREATED
        self.created_at = time.time()
        self.last_activity = self.created_at
        self._lock = asyncio.Lock()
        
        # DVR configuration
        self.dvr_enabled = dvr_enabled
        self.dvr_buffer = DVRBuffer(max_duration=dvr_duration)
        
        # Storage and transcoding
        self.storage_dir = Path(storage_dir) / stream_id
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        self.transcoder = VideoTranscoder(output_dir=str(self.storage_dir / "transcoded"))
        self.transcoding_profiles = transcoding_profiles or self.transcoder.DEFAULT_PROFILES
        
        # Track viewers
        self.viewers: Dict[str, StreamViewer] = {}  # peer_id -> StreamViewer
        self._viewer_tasks: Dict[str, asyncio.Task] = {}
        
        # Background tasks
        self._background_tasks: Set[asyncio.Task] = set()
        self._running = False
    
    async def start(self) -> bool:
        """Start the live stream."""
        if self._running:
            return True
            
        self._running = True
        self.state = StreamState.STARTING
        
        # Start background tasks
        self._background_tasks.update({
            asyncio.create_task(self._monitor_stream()),
            asyncio.create_task(self._cleanup_old_segments())
        })
        
        self.state = StreamState.LIVE
        self.last_activity = time.time()
        logger.info(f"Live stream {self.stream_id} started")
        return True
    
    async def stop(self) -> None:
        """Stop the live stream."""
        if not self._running:
            return
            
        self._running = False
        self.state = StreamState.STOPPED
        
        # Cancel background tasks
        for task in self._background_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        if self._background_tasks:
            await asyncio.wait(self._background_tasks, return_when=asyncio.ALL_COMPLETED)
        
        # Clean up
        await self._cleanup()
        logger.info(f"Live stream {self.stream_id} stopped")
    
    async def add_viewer(self, peer_id: str, quality: str = "auto") -> bool:
        """Add a viewer to the stream."
        
        Args:
            peer_id: ID of the viewing peer
            quality: Preferred quality level (e.g., '360p', '720p')
            
        Returns:
            bool: True if viewer was added, False otherwise
        """
        async with self._lock:
            if peer_id in self.viewers:
                return True
                
            self.viewers[peer_id] = StreamViewer(peer_id=peer_id, quality=quality)
            
            # Start a task to handle this viewer
            self._viewer_tasks[peer_id] = asyncio.create_task(
                self._handle_viewer(peer_id)
            )
            
            logger.info(f"Viewer {peer_id} joined stream {self.stream_id} (quality: {quality})")
            return True
    
    async def remove_viewer(self, peer_id: str) -> None:
        """Remove a viewer from the stream."""
        async with self._lock:
            if peer_id not in self.viewers:
                return
                
            # Cancel the viewer's task
            if peer_id in self._viewer_tasks:
                self._viewer_tasks[peer_id].cancel()
                del self._viewer_tasks[peer_id]
            
            # Remove the viewer
            del self.viewers[peer_id]
            logger.info(f"Viewer {peer_id} left stream {self.stream_id}")
    
    async def push_segment(self, data: bytes, duration: float, is_keyframe: bool = False) -> bool:
        """
        Push a video segment to the stream.
        
        Args:
            data: Segment data
            duration: Duration of the segment in seconds
            is_keyframe: Whether this is a keyframe segment
            
        Returns:
            bool: True if the segment was added successfully
        """
        if not self._running or self.state != StreamState.LIVE:
            return False
            
        try:
            # Add to DVR buffer if enabled
            if self.dvr_enabled:
                await self.dvr_buffer.add_segment(
                    data=data,
                    duration=duration,
                    is_keyframe=is_keyframe
                )
            
            # Update last activity
            self.last_activity = time.time()
            return True
            
        except Exception as e:
            logger.error(f"Failed to add segment to stream {self.stream_id}: {e}")
            return False
    
    async def get_stream_info(self) -> Dict[str, Any]:
        """Get information about the stream."""
        return {
            "stream_id": self.stream_id,
            "owner_id": self.owner_id,
            "state": self.state.value,
            "created_at": self.created_at,
            "last_activity": self.last_activity,
            "viewer_count": len(self.viewers),
            "dvr_enabled": self.dvr_enabled,
            "dvr_duration": self.dvr_buffer.duration if self.dvr_enabled else 0,
            "available_qualities": list(self.transcoding_profiles.keys())
        }
    
    async def _handle_viewer(self, peer_id: str) -> None:
        """Handle a viewer's connection to the stream."""
        try:
            # Get the viewer's quality preference
            viewer = self.viewers.get(peer_id)
            if not viewer:
                return
                
            quality = viewer.quality
            if quality == "auto":
                # Auto-detect quality based on network conditions
                # In a real implementation, this would use network metrics
                quality = "720p"  # Default to 720p
            
            # Get the appropriate transcoding profile
            profile = self.transcoding_profiles.get(quality)
            if not profile:
                logger.warning(f"Invalid quality {quality} for viewer {peer_id}, using default")
                profile = next(iter(self.transcoding_profiles.values()))
            
            # Send stream info to the viewer
            await self._send_stream_info(peer_id, profile)
            
            # Start streaming segments
            last_sequence = -1
            
            while self._running and peer_id in self.viewers:
                # Get new segments
                segments = await self.dvr_buffer.get_segments_since(sequence=last_sequence)
                
                if not segments:
                    # No new segments, wait a bit
                    await asyncio.sleep(0.1)
                    continue
                
                # Send each segment
                for segment in segments:
                    if not self._running or peer_id not in self.viewers:
                        break
                        
                    # In a real implementation, we would transcode the segment here
                    # For now, we'll just send the raw data
                    await self._send_segment(
                        peer_id=peer_id,
                        segment=segment,
                        profile=profile
                    )
                    
                    last_sequence = segment.sequence
                    viewer.update_last_seen()
                
                # Small delay to prevent busy-waiting
                await asyncio.sleep(0.01)
                
        except asyncio.CancelledError:
            # Viewer disconnected
            pass
        except Exception as e:
            logger.error(f"Error handling viewer {peer_id}: {e}")
        finally:
            # Clean up
            await self.remove_viewer(peer_id)
    
    async def _send_stream_info(self, peer_id: str, profile: TranscodingProfile) -> None:
        """Send stream information to a viewer."""
        # In a real implementation, this would send the stream's SDP offer/answer
        # and other metadata needed to start playback
        stream_info = {
            "type": "stream_info",
            "stream_id": self.stream_id,
            "quality": profile.name,
            "width": profile.width,
            "height": profile.height,
            "video_codec": profile.video_codec.value,
            "audio_codec": profile.audio_codec.value,
            "bitrate": profile.video_bitrate,
            "fps": profile.framerate,
            "dvr_enabled": self.dvr_enabled,
            "dvr_duration": self.dvr_buffer.duration if self.dvr_enabled else 0
        }
        
        await self.p2p_network.send_message(
            peer_id=peer_id,
            message_type="stream_info",
            payload=stream_info
        )
    
    async def _send_segment(
        self,
        peer_id: str,
        segment: StreamSegment,
        profile: TranscodingProfile
    ) -> None:
        """Send a video segment to a viewer."""
        # In a real implementation, this would:
        # 1. Transcode the segment to the target quality if needed
        # 2. Package it in the appropriate container format
        # 3. Send it over the network
        
        # For now, we'll just send a simplified message
        segment_info = {
            "type": "segment",
            "stream_id": self.stream_id,
            "sequence": segment.sequence,
            "timestamp": segment.timestamp,
            "duration": segment.duration,
            "is_keyframe": segment.is_keyframe,
            "size": len(segment.data)
        }
        
        await self.p2p_network.send_message(
            peer_id=peer_id,
            message_type="video_segment",
            payload=segment_info
        )
    
    async def _monitor_stream(self) -> None:
        """Monitor the stream for inactivity and other conditions."""
        while self._running:
            try:
                # Check for stream inactivity
                if self.state == StreamState.LIVE and (time.time() - self.last_activity) > 300:  # 5 minutes
                    logger.warning(f"Stream {self.stream_id} inactive for too long, stopping")
                    await self.stop()
                    break
                
                # Update stream stats periodically
                await asyncio.sleep(30)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in stream monitoring: {e}")
                await asyncio.sleep(5)  # Prevent tight loop on errors
    
    async def _cleanup_old_segments(self) -> None:
        """Clean up old segments from disk."""
        while self._running:
            try:
                # In a real implementation, this would remove old segments from disk
                # to free up space, while ensuring we keep enough for DVR functionality
                
                await asyncio.sleep(60)  # Check every minute
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error cleaning up segments: {e}")
                await asyncio.sleep(30)  # Wait before retrying
    
    async def _cleanup(self) -> None:
        """Clean up resources."""
        # Remove all viewers
        for peer_id in list(self.viewers.keys()):
            await self.remove_viewer(peer_id)
        
        # Clear DVR buffer
        if self.dvr_enabled:
            await self.dvr_buffer.clear()
        
        # In a real implementation, we might want to keep some segments
        # for VOD or archive purposes
        
        logger.info(f"Cleaned up resources for stream {self.stream_id}")

class LiveStreamManager:
    """Manages multiple live streams."""
    
    def __init__(
        self,
        p2p_network: P2PNetwork,
        storage_dir: str = "./streams",
        max_streams: int = 100,
        default_dvr_duration: float = 3600  # 1 hour
    ):
        self.p2p_network = p2p_network
        self.storage_dir = Path(storage_dir)
        self.max_streams = max_streams
        self.default_dvr_duration = default_dvr_duration
        
        self.streams: Dict[str, LiveStream] = {}
        self._lock = asyncio.Lock()
        self._running = False
    
    async def start(self) -> None:
        """Start the stream manager."""
        if self._running:
            return
            
        self._running = True
        
        # Register message handlers
        self.p2p_network.register_message_handler(
            "stream_publish",
            self._handle_publish_request
        )
        self.p2p_network.register_message_handler(
            "stream_subscribe",
            self._handle_subscribe_request
        )
        
        logger.info("Live stream manager started")
    
    async def stop(self) -> None:
        """Stop the stream manager and all streams."""
        if not self._running:
            return
            
        self._running = False
        
        # Stop all streams
        async with self._lock:
            for stream in list(self.streams.values()):
                await stream.stop()
            self.streams.clear()
        
        logger.info("Live stream manager stopped")
    
    async def create_stream(
        self,
        stream_id: str,
        owner_id: str,
        dvr_enabled: bool = True,
        dvr_duration: Optional[float] = None
    ) -> Optional[LiveStream]:
        """Create a new live stream."""
        async with self._lock:
            if len(self.streams) >= self.max_streams:
                logger.warning(f"Maximum number of streams ({self.max_streams}) reached")
                return None
                
            if stream_id in self.streams:
                logger.warning(f"Stream {stream_id} already exists")
                return self.streams[stream_id]
            
            # Create the stream
            stream = LiveStream(
                stream_id=stream_id,
                owner_id=owner_id,
                p2p_network=self.p2p_network,
                storage_dir=str(self.storage_dir),
                dvr_enabled=dvr_enabled,
                dvr_duration=dvr_duration or self.default_dvr_duration
            )
            
            # Start the stream
            if await stream.start():
                self.streams[stream_id] = stream
                logger.info(f"Created stream {stream_id} (owner: {owner_id})")
                return stream
            
            return None
    
    async def get_stream(self, stream_id: str) -> Optional[LiveStream]:
        """Get a stream by ID."""
        async with self._lock:
            return self.streams.get(stream_id)
    
    async def remove_stream(self, stream_id: str) -> bool:
        """Remove a stream."""
        async with self._lock:
            if stream_id not in self.streams:
                return False
                
            stream = self.streams[stream_id]
            await stream.stop()
            del self.streams[stream_id]
            
            logger.info(f"Removed stream {stream_id}")
            return True
    
    async def list_streams(self) -> List[Dict[str, Any]]:
        """List all active streams."""
        async with self._lock:
            return [
                await stream.get_stream_info()
                for stream in self.streams.values()
            ]
    
    async def _handle_publish_request(
        self,
        sender_id: str,
        message: Dict[str, Any]
    ) -> None:
        """Handle a stream publish request."""
        try:
            stream_id = message.get("stream_id")
            if not stream_id:
                logger.warning("Publish request missing stream_id")
                return
                
            # Check if the stream exists
            stream = await self.get_stream(stream_id)
            if not stream:
                # Create a new stream
                stream = await self.create_stream(
                    stream_id=stream_id,
                    owner_id=sender_id,
                    dvr_enabled=message.get("dvr_enabled", True),
                    dvr_duration=message.get("dvr_duration")
                )
                
                if not stream:
                    logger.error(f"Failed to create stream {stream_id}")
                    return
            
            # Send success response
            await self.p2p_network.send_message(
                peer_id=sender_id,
                message_type="publish_accepted",
                payload={
                    "stream_id": stream_id,
                    "status": "ready"
                }
            )
            
        except Exception as e:
            logger.error(f"Error handling publish request: {e}")
            # Send error response
            await self.p2p_network.send_message(
                peer_id=sender_id,
                message_type="publish_rejected",
                payload={
                    "stream_id": message.get("stream_id", "unknown"),
                    "reason": str(e)
                }
            )
    
    async def _handle_subscribe_request(
        self,
        sender_id: str,
        message: Dict[str, Any]
    ) -> None:
        """Handle a stream subscribe request."""
        try:
            stream_id = message.get("stream_id")
            if not stream_id:
                logger.warning("Subscribe request missing stream_id")
                return
                
            # Get the stream
            stream = await self.get_stream(stream_id)
            if not stream:
                logger.warning(f"Stream {stream_id} not found")
                await self.p2p_network.send_message(
                    peer_id=sender_id,
                    message_type="subscribe_rejected",
                    payload={
                        "stream_id": stream_id,
                        "reason": "not_found"
                    }
                )
                return
            
            # Add the viewer
            quality = message.get("quality", "auto")
            if await stream.add_viewer(sender_id, quality):
                await self.p2p_network.send_message(
                    peer_id=sender_id,
                    message_type="subscribe_accepted",
                    payload={
                        "stream_id": stream_id,
                        "status": "ready"
                    }
                )
            else:
                await self.p2p_network.send_message(
                    peer_id=sender_id,
                    message_type="subscribe_rejected",
                    payload={
                        "stream_id": stream_id,
                        "reason": "internal_error"
                    }
                )
            
        except Exception as e:
            logger.error(f"Error handling subscribe request: {e}")
            # Send error response
            await self.p2p_network.send_message(
                peer_id=sender_id,
                message_type="subscribe_rejected",
                payload={
                    "stream_id": message.get("stream_id", "unknown"),
                    "reason": str(e)
                }
            )
