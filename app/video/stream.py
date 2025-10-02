"""
Video streaming module for the decentralized video platform.
Handles real-time video streaming using WebRTC and adaptive bitrate.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Callable, Awaitable

from aiortc import RTCPeerConnection, RTCSessionDescription, RTCDataChannel, MediaStreamTrack
from aiortc.contrib.media import MediaPlayer, MediaRelay

from ..network.bandwidth import BandwidthMonitor, TrafficShaper, QoSManager

logger = logging.getLogger(__name__)

class StreamQuality(Enum):
    """Video stream quality levels."""
    LOW = "240p"
    MEDIUM = "480p"
    HIGH = "720p"
    HD = "1080p"
    UHD = "4k"

@dataclass
class StreamStats:
    """Stream statistics and metrics."""
    quality: StreamQuality
    bitrate: int  # in kbps
    resolution: tuple[int, int]
    frame_rate: float
    packets_lost: int = 0
    jitter: float = 0.0
    rtt: float = 0.0
    timestamp: float = field(default_factory=lambda: time.time())

class VideoStream:
    """Manages a single video stream with adaptive quality."""
    
    def __init__(
        self,
        stream_id: str,
        peer_connection: RTCPeerConnection,
        bandwidth_monitor: BandwidthMonitor,
        traffic_shaper: TrafficShaper,
        qos_manager: QoSManager,
        on_quality_change: Optional[Callable[[StreamQuality], None]] = None
    ):
        self.stream_id = stream_id
        self.peer_connection = peer_connection
        self.bandwidth_monitor = bandwidth_monitor
        self.traffic_shaper = traffic_shaper
        self.qos_manager = qos_manager
        self.on_quality_change = on_quality_change
        
        self._current_quality = StreamQuality.MEDIUM
        self._stats: Dict[str, StreamStats] = {}
        self._media_player: Optional[MediaPlayer] = None
        self._relay = MediaRelay()
        self._is_active = False
        
        # Set up data channel for control messages
        self._control_channel: Optional[RTCDataChannel] = None
        self._setup_data_channels()
    
    def _setup_data_channels(self) -> None:
        """Set up WebRTC data channels for control messages."""
        @self.peer_connection.on("datachannel")
        def on_datachannel(channel: RTCDataChannel) -> None:
            if channel.label == "control":
                self._control_channel = channel
                channel.on("message")(self._on_control_message)
    
    async def _on_control_message(self, message: str) -> None:
        """Handle incoming control messages."""
        try:
            data = json.loads(message)
            if data.get("type") == "quality_change":
                new_quality = StreamQuality(data["quality"])
                await self.set_quality(new_quality)
        except Exception as e:
            logger.error(f"Error handling control message: {e}")
    
    async def set_quality(self, quality: StreamQuality) -> None:
        """Change the stream quality."""
        if quality == self._current_quality:
            return
            
        self._current_quality = quality
        logger.info(f"Stream {self.stream_id} quality changed to {quality.value}")
        
        # Notify the other end of quality change
        if self._control_channel and self._control_channel.readyState == "open":
            message = {
                "type": "quality_change",
                "quality": quality.value,
                "stream_id": self.stream_id
            }
            self._control_channel.send(json.dumps(message))
        
        # Update QoS settings
        self.qos_manager.update_stream_quality(self.stream_id, quality)
        
        # Notify quality change callback if set
        if self.on_quality_change:
            self.on_quality_change(quality)
    
    async def start(self, video_source: str) -> None:
        """Start streaming video from the specified source."""
        if self._is_active:
            logger.warning(f"Stream {self.stream_id} is already active")
            return
            
        self._is_active = True
        
        # Configure media player with adaptive settings
        options = {
            "video_size": self._get_resolution(),
            "framerate": 30,
            "rtbufsize": "4M",
            "fflags": "nobuffer",
            "flags": "low_delay"
        }
        
        try:
            self._media_player = MediaPlayer(
                video_source,
                format="dshow" if 'video=' in video_source else None,
                options=options
            )
            
            # Add tracks to peer connection
            if self._media_player.video:
                self.peer_connection.addTrack(
                    self._relay.subscribe(self._media_player.video)
                )
            
            logger.info(f"Started streaming {self.stream_id} at {self._current_quality.value}")
            
            # Start monitoring stream quality
            asyncio.create_task(self._monitor_stream_quality())
            
        except Exception as e:
            logger.error(f"Failed to start stream {self.stream_id}: {e}")
            self._is_active = False
            raise
    
    async def stop(self) -> None:
        """Stop the video stream."""
        if not self._is_active:
            return
            
        self._is_active = False
        
        if self._media_player:
            if hasattr(self._media_player, 'stop'):
                self._media_player.stop()
            self._media_player = None
        
        logger.info(f"Stopped streaming {self.stream_id}")
    
    def _get_resolution(self) -> str:
        """Get resolution string based on current quality."""
        resolutions = {
            StreamQuality.LOW: "426x240",
            StreamQuality.MEDIUM: "854x480",
            StreamQuality.HIGH: "1280x720",
            StreamQuality.HD: "1920x1080",
            StreamQuality.UHD: "3840x2160"
        }
        return resolutions.get(self._current_quality, "854x480")
    
    async def _monitor_stream_quality(self) -> None:
        """Monitor network conditions and adjust stream quality."""
        while self._is_active:
            try:
                # Get current network conditions
                stats = await self.peer_connection.getStats()
                bandwidth = self.bandwidth_monitor.get_available_bandwidth()
                
                # Calculate metrics
                current_stats = self._calculate_stream_stats(stats)
                self._stats[time.time()] = current_stats
                
                # Adjust quality based on conditions
                await self._adjust_quality(bandwidth, current_stats)
                
                # Clean up old stats
                self._cleanup_old_stats()
                
                await asyncio.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                logger.error(f"Error in stream quality monitoring: {e}")
                await asyncio.sleep(5)
    
    def _calculate_stream_stats(self, stats: dict) -> StreamStats:
        """Calculate stream statistics from WebRTC stats."""n        # This is a simplified implementation
        # In a real implementation, you would parse the stats object
        # and calculate actual metrics
        return StreamStats(
            quality=self._current_quality,
            bitrate=2000,  # Example value
            resolution=(1280, 720),  # Example value
            frame_rate=30.0,  # Example value
            packets_lost=0,  # Example value
            jitter=0.0,  # Example value
            rtt=0.0  # Example value
        )
    
    async def _adjust_quality(self, available_bandwidth: float, current_stats: StreamStats) -> None:
        """Adjust stream quality based on available bandwidth and current stats."""
        if available_bandwidth < 1000:  # Less than 1 Mbps
            new_quality = StreamQuality.LOW
        elif available_bandwidth < 2500:  # Less than 2.5 Mbps
            new_quality = StreamQuality.MEDIUM
        elif available_bandwidth < 5000:  # Less than 5 Mbps
            new_quality = StreamQuality.HIGH
        elif available_bandwidth < 10000:  # Less than 10 Mbps
            new_quality = StreamQuality.HD
        else:
            new_quality = StreamQuality.UHD
        
        if new_quality != self._current_quality:
            await self.set_quality(new_quality)
