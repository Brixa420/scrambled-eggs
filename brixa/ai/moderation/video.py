"""
Video content moderation using frame sampling and image analysis.
"""
import asyncio
import logging
import os
import tempfile
from typing import Dict, List, Optional, Any, Union
from pathlib import Path

from .base import ContentModerator, ModerationResult, ModerationAction, ContentType
from .image import ImageModerator

logger = logging.getLogger(__name__)

class VideoModerator(ContentModerator):
    """Moderates video content by analyzing key frames."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the video moderator."""
        self.image_moderator = ImageModerator(config)
        self.frame_interval = config.get('frame_interval', 10)  # Analyze every 10th frame by default
        self.max_frames = config.get('max_frames', 30)  # Maximum number of frames to analyze
        super().__init__(config)
    
    @property
    def content_type(self):
        return ContentType.VIDEO
    
    def _setup(self) -> None:
        """Set up video moderation components."""
        try:
            # Ensure required dependencies are available
            try:
                import cv2
                self.cv2 = cv2
            except ImportError:
                logger.warning("OpenCV not installed. Video moderation will be limited.")
                self.cv2 = None
                
            # Set up image moderator for frame analysis
            self.image_moderator = ImageModerator(
                self.config.get('image_config', {})
            )
            
        except Exception as e:
            logger.error(f"Error setting up video moderator: {e}")
            raise
    
    async def moderate(self, video_data: Union[str, bytes], 
                      context: Optional[Dict] = None) -> ModerationResult:
        """
        Moderate the given video content.
        
        Args:
            video_data: Path to video file or video bytes
            context: Additional context (e.g., user info, content metadata)
            
        Returns:
            ModerationResult with the decision and details
        """
        if self.cv2 is None:
            return ModerationResult(
                action=ModerationAction.FLAG,
                confidence=0.0,
                reasons=["Video moderation requires OpenCV (cv2) to be installed"]
            )
        
        try:
            # Save video to temp file if it's bytes
            temp_file = None
            if isinstance(video_data, bytes):
                temp_file = tempfile.NamedTemporaryFile(suffix='.mp4', delete=False)
                temp_file.write(video_data)
                temp_file.close()
                video_path = temp_file.name
            else:
                video_path = str(video_data)
            
            # Extract and analyze frames
            frame_results = await self._analyze_video_frames(video_path)
            
            # Clean up temp file if created
            if temp_file:
                try:
                    os.unlink(temp_file.name)
                except Exception as e:
                    logger.warning(f"Error deleting temp file: {e}")
            
            # Process results from all frames
            return self._process_frame_results(frame_results, context)
            
        except Exception as e:
            logger.error(f"Error in video moderation: {e}", exc_info=True)
            return ModerationResult(
                action=ModerationAction.FLAG,
                confidence=0.0,
                reasons=[f"Error processing video: {str(e)}"]
            )
    
    async def _analyze_video_frames(self, video_path: str) -> List[Dict]:
        """Extract and analyze frames from video."""
        if not os.path.exists(video_path):
            raise FileNotFoundError(f"Video file not found: {video_path}")
        
        cap = self.cv2.VideoCapture(video_path)
        if not cap.isOpened():
            raise ValueError(f"Could not open video: {video_path}")
        
        try:
            total_frames = int(cap.get(self.cv2.CAP_PROP_FRAME_COUNT))
            fps = cap.get(self.cv2.CAP_PROP_FPS)
            duration = total_frames / fps if fps > 0 else 0
            
            logger.info(f"Analyzing video: {total_frames} frames, {fps:.2f} FPS, {duration:.2f}s")
            
            # Calculate frame interval based on video length
            frame_interval = max(1, int(fps * 2))  # Sample every 2 seconds by default
            if self.frame_interval > 0:
                frame_interval = min(frame_interval, self.frame_interval)
            
            frame_count = 0
            analyzed_frames = 0
            frame_results = []
            
            while True:
                ret, frame = cap.read()
                if not ret:
                    break
                
                # Only process frames at the specified interval
                if frame_count % frame_interval == 0 and analyzed_frames < self.max_frames:
                    # Convert frame to PIL Image for consistency with image moderator
                    frame_rgb = self.cv2.cvtColor(frame, self.cv2.COLOR_BGR2RGB)
                    pil_image = Image.fromarray(frame_rgb)
                    
                    # Analyze frame
                    result = await self.image_moderator.moderate(pil_image)
                    
                    # Store frame analysis results
                    frame_results.append({
                        'frame_number': frame_count,
                        'timestamp': frame_count / fps if fps > 0 else 0,
                        'result': result,
                        'action': result.action,
                        'confidence': result.confidence,
                        'reasons': result.reasons
                    })
                    
                    analyzed_frames += 1
                    
                    # Early exit if we've found severe violations
                    if result.action in (ModerationAction.BLOCK, ModerationAction.QUARANTINE) and \
                       result.confidence >= 0.9:
                        logger.info(f"Early termination at frame {frame_count} due to policy violation")
                        break
                
                frame_count += 1
                
                # Early exit if we've analyzed enough frames
                if analyzed_frames >= self.max_frames:
                    break
            
            return frame_results
            
        finally:
            cap.release()
    
    def _process_frame_results(self, frame_results: List[Dict], 
                             context: Optional[Dict] = None) -> ModerationResult:
        """Process results from frame analysis and make final decision."""
        if not frame_results:
            return ModerationResult(
                action=ModerationAction.ALLOW,
                confidence=1.0,
                reasons=["No frames analyzed"]
            )
        
        # Count actions from frame results
        action_counts = {
            ModerationAction.BLOCK: 0,
            ModerationAction.QUARANTINE: 0,
            ModerationAction.FLAG: 0,
            ModerationAction.ALLOW: 0
        }
        
        # Track all violations and their timestamps
        all_violations = []
        
        for frame in frame_results:
            action = frame['action']
            action_counts[action] += 1
            
            # Collect violations
            if action != ModerationAction.ALLOW:
                all_violations.append({
                    'frame': frame['frame_number'],
                    'timestamp': frame['timestamp'],
                    'action': action.name,
                    'confidence': frame['confidence'],
                    'reasons': frame['reasons']
                })
        
        # Calculate violation ratios
        total_frames = len(frame_results)
        block_ratio = action_counts[ModerationAction.BLOCK] / total_frames
        quarantine_ratio = action_counts[ModerationAction.QUARANTINE] / total_frames
        flag_ratio = action_counts[ModerationAction.FLAG] / total_frames
        
        # Determine overall action based on frame analysis
        if block_ratio > 0.1:  # More than 10% of frames have BLOCK violations
            action = ModerationAction.BLOCK
            confidence = min(1.0, block_ratio * 1.5)  # Scale confidence based on ratio
        elif quarantine_ratio > 0.2:  # More than 20% of frames have QUARANTINE violations
            action = ModerationAction.QUARANTINE
            confidence = min(1.0, quarantine_ratio * 1.2)
        elif flag_ratio > 0.3:  # More than 30% of frames have FLAG violations
            action = ModerationAction.FLAG
            confidence = min(1.0, flag_ratio)
        else:
            action = ModerationAction.ALLOW
            confidence = 1.0
        
        # Prepare reasons
        reasons = []
        if action != ModerationAction.ALLOW:
            reasons.append(f"Found {len(all_violations)} policy violations in {total_frames} analyzed frames")
        else:
            reasons.append("No policy violations detected in sampled frames")
        
        return ModerationResult(
            action=action,
            confidence=confidence,
            reasons=reasons,
            metadata={
                'analyzed_frames': total_frames,
                'violations': all_violations,
                'block_frames': action_counts[ModerationAction.BLOCK],
                'quarantine_frames': action_counts[ModerationAction.QUARANTINE],
                'flag_frames': action_counts[ModerationAction.FLAG]
            }
        )
    
    async def extract_thumbnail(self, video_path: str, output_path: str = None, 
                              time_sec: float = 5.0) -> Optional[str]:
        """
        Extract a thumbnail from the video at the specified time.
        
        Args:
            video_path: Path to the video file
            output_path: Path to save the thumbnail (optional)
            time_sec: Timestamp in seconds to extract thumbnail from
            
        Returns:
            Path to the saved thumbnail or None if extraction failed
        """
        if self.cv2 is None:
            logger.warning("OpenCV not available for thumbnail extraction")
            return None
            
        cap = self.cv2.VideoCapture(video_path)
        if not cap.isOpened():
            logger.error(f"Could not open video: {video_path}")
            return None
            
        try:
            # Get total frames and FPS
            total_frames = int(cap.get(self.cv2.CAP_PROP_FRAME_COUNT))
            fps = cap.get(self.cv2.CAP_PROP_FPS)
            
            if fps <= 0 or total_frames == 0:
                logger.error(f"Invalid video properties - FPS: {fps}, Total Frames: {total_frames}")
                return None
            
            # Calculate frame number for the requested time
            target_frame = int(time_sec * fps)
            
            # Set the frame position
            cap.set(self.cv2.CAP_PROP_POS_FRAMES, min(target_frame, total_frames - 1))
            
            # Read the frame
            ret, frame = cap.read()
            if not ret:
                logger.error("Failed to read frame from video")
                return None
            
            # Generate output path if not provided
            if not output_path:
                video_dir = os.path.dirname(video_path)
                video_name = os.path.splitext(os.path.basename(video_path))[0]
                output_path = os.path.join(video_dir, f"{video_name}_thumbnail.jpg")
            
            # Save the frame as an image
            output_path = str(Path(output_path).with_suffix('.jpg'))
            self.cv2.imwrite(output_path, frame, [self.cv2.IMWRITE_JPEG_QUALITY, 90])
            
            return output_path
            
        except Exception as e:
            logger.error(f"Error extracting thumbnail: {e}", exc_info=True)
            return None
            
        finally:
            cap.release()
