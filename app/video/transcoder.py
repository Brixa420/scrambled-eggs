"""
Video transcoding module for the decentralized video platform.
Handles format conversion, resolution scaling, and bitrate adaptation.
"""

import asyncio
import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .storage import VideoMetadata

logger = logging.getLogger(__name__)

class VideoFormat(Enum):
    """Supported video formats."""
    MP4 = "mp4"
    WEBM = "webm"
    HLS = "hls"
    DASH = "dash"

class VideoCodec(Enum):
    """Supported video codecs."""
    H264 = "libx264"
    H265 = "libx265"
    VP9 = "libvpx-vp9"
    AV1 = "libaom-av1"

class AudioCodec(Enum):
    """Supported audio codecs."""
    AAC = "aac"
    OPUS = "libopus"
    VORBIS = "libvorbis"

@dataclass
class TranscodingProfile:
    """Configuration for video transcoding."""
    name: str
    width: int
    height: int
    video_bitrate: str  # e.g., "1M" for 1 Mbps
    video_codec: VideoCodec
    audio_bitrate: str  # e.g., "128k"
    audio_codec: AudioCodec
    framerate: int = 30
    keyint: int = 60  # Keyframe interval in frames
    preset: str = "medium"  # Encoding speed/quality tradeoff
    format: VideoFormat = VideoFormat.MP4
    
    def to_ffmpeg_args(self) -> List[str]:
        """Convert to FFmpeg command-line arguments."""
        args = [
            "-c:v", self.video_codec.value,
            "-b:v", self.video_bitrate,
            "-vf", f"scale={self.width}:{self.height}:force_original_aspect_ratio=decrease,pad={self.width}:{self.height}:(ow-iw)/2:(oh-ih)/2",
            "-r", str(self.framerate),
            "-g", str(self.keyint),
            "-preset", self.preset,
            "-c:a", self.audio_codec.value,
            "-b:a", self.audio_bitrate,
            "-movflags", "+faststart"  # For MP4 streaming
        ]
        
        # Add codec-specific options
        if self.video_codec == VideoCodec.H264:
            args.extend(["-profile:v", "high", "-level", "4.0"])
        elif self.video_codec == VideoCodec.VP9:
            args.extend(["-deadline", "realtime", "-cpu-used", "4"])
            
        return args

class VideoTranscoder:
    """Handles video transcoding to multiple formats and qualities."""
    
    # Default transcoding profiles
    DEFAULT_PROFILES = {
        "240p": TranscodingProfile(
            name="240p",
            width=426,
            height=240,
            video_bitrate="400k",
            video_codec=VideoCodec.H264,
            audio_bitrate="64k",
            audio_codec=AudioCodec.AAC
        ),
        "360p": TranscodingProfile(
            name="360p",
            width=640,
            height=360,
            video_bitrate="800k",
            video_codec=VideoCodec.H264,
            audio_bitrate="96k",
            audio_codec=AudioCodec.AAC
        ),
        "720p": TranscodingProfile(
            name="720p",
            width=1280,
            height=720,
            video_bitrate="2M",
            video_codec=VideoCodec.H264,
            audio_bitrate="128k",
            audio_codec=AudioCodec.AAC
        ),
        "1080p": TranscodingProfile(
            name="1080p",
            width=1920,
            height=1080,
            video_bitrate="4M",
            video_codec=VideoCodec.H265,
            audio_bitrate="192k",
            audio_codec=AudioCodec.AAC
        )
    }
    
    def __init__(self, output_dir: str = "./transcoded"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.profiles = self.DEFAULT_PROFILES.copy()
    
    async def transcode(
        self,
        input_path: str,
        video_id: str,
        profiles: Optional[Dict[str, TranscodingProfile]] = None,
        delete_source: bool = False
    ) -> Dict[str, str]:
        """
        Transcode a video to multiple formats and qualities.
        
        Args:
            input_path: Path to the input video file
            video_id: Unique identifier for the video
            profiles: Dictionary of transcoding profiles to use
            delete_source: Whether to delete the source file after transcoding
            
        Returns:
            Dictionary mapping profile names to output file paths
        """
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        profiles = profiles or self.profiles
        output_files = {}
        
        # Create a temporary directory for intermediate files
        temp_dir = self.output_dir / video_id / "temp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # First, extract metadata from the source video
            metadata = await self._extract_metadata(input_path)
            
            # Process each profile
            tasks = []
            for profile_name, profile in profiles.items():
                output_path = self.output_dir / video_id / f"{profile_name}.{profile.format.value}"
                output_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Skip if output already exists and is newer than source
                if output_path.exists() and os.path.getmtime(output_path) > os.path.getmtime(input_path):
                    logger.info(f"Skipping {profile_name} - already exists and up to date")
                    output_files[profile_name] = str(output_path)
                    continue
                
                # Create a task for each profile
                task = asyncio.create_task(
                    self._transcode_single(
                        input_path, 
                        output_path, 
                        profile,
                        metadata
                    )
                )
                tasks.append((profile_name, task))
            
            # Wait for all transcoding tasks to complete
            for profile_name, task in tasks:
                try:
                    output_path = await task
                    output_files[profile_name] = str(output_path)
                except Exception as e:
                    logger.error(f"Failed to transcode {profile_name}: {e}")
            
            # Generate HLS/DASH manifests if needed
            if any(p.format == VideoFormat.HLS for p in profiles.values()):
                hls_manifest = await self._create_hls_manifest(video_id, output_files)
                output_files["hls_manifest"] = hls_manifest
                
            if any(p.format == VideoFormat.DASH for p in profiles.values()):
                dash_manifest = await self._create_dash_manifest(video_id, output_files)
                output_files["dash_manifest"] = dash_manifest
            
            # Clean up
            if delete_source:
                try:
                    os.remove(input_path)
                except OSError as e:
                    logger.warning(f"Failed to delete source file: {e}")
            
            return output_files
            
        finally:
            # Clean up temporary files
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    async def _transcode_single(
        self,
        input_path: str,
        output_path: str,
        profile: TranscodingProfile,
        metadata: Dict
    ) -> str:
        """Transcode a single video with the given profile."""
        logger.info(f"Transcoding to {output_path} with profile {profile.name}")
        
        ffmpeg_cmd = [
            "ffmpeg",
            "-y",  # Overwrite output files
            "-i", input_path,
            *profile.to_ffmpeg_args(),
            "-f", profile.format.value,
            str(output_path)
        ]
        
        # Run FFmpeg
        process = await asyncio.create_subprocess_exec(
            *ffmpeg_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Monitor progress
        progress_task = asyncio.create_task(
            self._monitor_progress(process, os.path.getsize(input_path))
        )
        
        # Wait for completion
        stdout, stderr = await process.communicate()
        progress_task.cancel()
        
        if process.returncode != 0:
            error_msg = stderr.decode().strip()
            logger.error(f"FFmpeg error: {error_msg}")
            raise RuntimeError(f"FFmpeg failed with return code {process.returncode}")
        
        return str(output_path)
    
    async def _extract_metadata(self, input_path: str) -> Dict:
        """Extract metadata from a video file using FFprobe."""
        cmd = [
            "ffprobe",
            "-v", "error",
            "-show_entries", "stream=width,height,duration,bit_rate,codec_name",
            "-show_entries", "format=duration,size,bit_rate",
            "-print_format", "json",
            input_path
        ]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            error_msg = stderr.decode().strip()
            raise RuntimeError(f"FFprobe error: {error_msg}")
        
        return json.loads(stdout)
    
    async def _create_hls_manifest(
        self,
        video_id: str,
        output_files: Dict[str, str]
    ) -> str:
        """Create an HLS manifest for adaptive streaming."""
        master_playlist = self.output_dir / video_id / "playlist.m3u8"
        
        with open(master_playlist, "w") as f:
            f.write("#EXTM3U\n")
            
            # Sort profiles from lowest to highest quality
            for profile_name in sorted(self.profiles.keys()):
                if profile_name in output_files:
                    profile = self.profiles[profile_name]
                    f.write(
                        f"#EXT-X-STREAM-INF:BANDWIDTH={self._bitrate_to_bps(profile.video_bitrate)},RESOLUTION={profile.width}x{profile.height}\n"
                        f"{profile_name}.m3u8\n"
                    )
        
        return str(master_playlist)
    
    async def _create_dash_manifest(
        self,
        video_id: str,
        output_files: Dict[str, str]
    ) -> str:
        """Create a DASH manifest for adaptive streaming."""
        # This is a simplified example - in practice, you'd use a library like MP4Box
        manifest_path = self.output_dir / video_id / "manifest.mpd"
        
        # In a real implementation, this would generate a proper MPD manifest
        with open(manifest_path, "w") as f:
            f.write("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")
            f.write("<MPD xmlns=\"urn:mpeg:dash:schema:mpd:2011\" profiles=\"urn:mpeg:dash:profile:full:2011\">\n")
            # Add periods, adaptation sets, and representations here
            f.write("</MPD>")
        
        return str(manifest_path)
    
    @staticmethod
    async def _monitor_progress(process: asyncio.subprocess.Process, total_size: int) -> None:
        """Monitor transcoding progress."""
        while True:
            # In a real implementation, you'd parse FFmpeg's progress output
            # This is a simplified version that just shows a heartbeat
            logger.info("Transcoding in progress...")
            await asyncio.sleep(5)
    
    @staticmethod
    def _bitrate_to_bps(bitrate_str: str) -> int:
        """Convert bitrate string (e.g., '1M', '128k') to bits per second."""
        if bitrate_str.endswith('k'):
            return int(bitrate_str[:-1]) * 1000
        elif bitrate_str.endswith('M'):
            return int(bitrate_str[:-1]) * 1000000
        return int(bitrate_str)
