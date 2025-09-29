"""
File Preview Generator for Brixa Network

This module generates previews for various file types including:
- Images (thumbnail generation)
- Documents (text extraction and preview)
- Audio/Video (metadata extraction and thumbnail)
- Archives (file listing)
"""
import os
import io
import mimetypes
from pathlib import Path
from typing import Dict, Optional, Tuple, Union, BinaryIO
from PIL import Image, ImageOps
import PyPDF2
from docx import Document
import PyPDF2
import fitz  # PyMuPDF
import cv2
import numpy as np
from moviepy.editor import VideoFileClip
import librosa
import soundfile as sf
from pydub import AudioSegment
import zipfile
import tarfile
import tempfile
import logging

logger = logging.getLogger(__name__)

# Configure mimetypes
mimetypes.init()

class FilePreviewGenerator:
    """Generates previews for different file types."""
    
    def __init__(self, temp_dir: str = "temp/previews"):
        """Initialize the preview generator.
        
        Args:
            temp_dir: Directory to store temporary preview files
        """
        self.temp_dir = Path(temp_dir)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        
        # Supported file types and their handlers
        self.handlers = {
            'image': self._generate_image_preview,
            'pdf': self._generate_pdf_preview,
            'document': self._generate_document_preview,
            'video': self._generate_video_preview,
            'audio': self._generate_audio_preview,
            'archive': self._generate_archive_preview,
            'text': self._generate_text_preview
        }
    
    async def generate_preview(
        self, 
        file_path: Union[str, Path], 
        output_path: Optional[Union[str, Path]] = None,
        size: Tuple[int, int] = (256, 256),
        quality: int = 85
    ) -> Optional[Path]:
        """Generate a preview for the given file.
        
        Args:
            file_path: Path to the input file
            output_path: Path to save the preview (default: auto-generated)
            size: Preview image dimensions (width, height)
            quality: JPEG quality (1-100)
            
        Returns:
            Path to the generated preview file or None if generation failed
        """
        file_path = Path(file_path)
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return None
            
        # Determine file type and appropriate handler
        file_type = self._get_file_type(file_path)
        handler = self.handlers.get(file_type)
        
        if not handler:
            logger.warning(f"No preview handler for file type: {file_type}")
            return None
        
        # Set default output path if not provided
        if output_path is None:
            output_path = self.temp_dir / f"{file_path.stem}_preview.jpg"
        else:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            # Generate the preview
            preview_path = await handler(file_path, output_path, size, quality)
            if preview_path and preview_path.exists():
                logger.info(f"Generated preview: {preview_path}")
                return preview_path
        except Exception as e:
            logger.error(f"Error generating preview for {file_path}: {e}", exc_info=True)
        
        return None
    
    def _get_file_type(self, file_path: Path) -> str:
        """Determine the file type and return the appropriate handler key."""
        mime_type, _ = mimetypes.guess_type(file_path)
        if not mime_type:
            # Try to determine by extension
            ext = file_path.suffix.lower()
            if ext in ('.txt', '.md', '.json', '.yaml', '.yml', '.csv'):
                return 'text'
            return 'unknown'
        
        if mime_type.startswith('image/'):
            return 'image'
        elif mime_type == 'application/pdf':
            return 'pdf'
        elif mime_type in ('application/msword', 
                          'application/vnd.openxmlformats-officedocument.wordprocessingml.document'):
            return 'document'
        elif mime_type.startswith('video/'):
            return 'video'
        elif mime_type.startswith('audio/'):
            return 'audio'
        elif mime_type in ('application/zip', 'application/x-tar', 'application/x-gzip',
                          'application/x-bzip2', 'application/x-xz'):
            return 'archive'
        elif mime_type.startswith('text/'):
            return 'text'
        
        return 'unknown'
    
    async def _generate_image_preview(
        self, 
        file_path: Path, 
        output_path: Path,
        size: Tuple[int, int],
        quality: int
    ) -> Path:
        """Generate a thumbnail for an image file."""
        with Image.open(file_path) as img:
            # Convert to RGB if necessary (for PNG with transparency)
            if img.mode in ('RGBA', 'P'):
                img = img.convert('RGB')
                
            # Create thumbnail
            img.thumbnail(size, Image.Resampling.LANCZOS)
            
            # Add a white background for transparent images
            if img.mode in ('RGBA', 'LA') or (img.mode == 'P' and 'transparency' in img.info):
                background = Image.new('RGB', img.size, (255, 255, 255))
                background.paste(img, mask=img.split()[-1])  # Paste using alpha channel as mask
                img = background
            
            # Save the preview
            img.save(output_path, 'JPEG', quality=quality, optimize=True)
            
        return output_path
    
    async def _generate_pdf_preview(
        self, 
        file_path: Path, 
        output_path: Path,
        size: Tuple[int, int],
        quality: int
    ) -> Path:
        """Generate a preview for a PDF file."""
        # Convert first page to image using PyMuPDF
        doc = fitz.open(file_path)
        page = doc.load_page(0)  # First page
        pix = page.get_pixmap()
        
        # Convert to PIL Image
        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        
        # Create thumbnail
        img.thumbnail(size, Image.Resampling.LANCZOS)
        img.save(output_path, 'JPEG', quality=quality, optimize=True)
        
        return output_path
    
    async def _generate_document_preview(
        self, 
        file_path: Path, 
        output_path: Path,
        size: Tuple[int, int],
        quality: int
    ) -> Path:
        """Generate a preview for a document (DOCX, etc.)."""
        # For now, just create a generic document icon with the filename
        # In a real implementation, you would extract text or convert to PDF first
        from PIL import ImageDraw, ImageFont
        
        # Create a blank image with a document icon
        img = Image.new('RGB', size, (240, 240, 240))
        draw = ImageDraw.Draw(img)
        
        # Add document icon (simplified)
        doc_icon = [
            "  #####  ",
            " #     # ",
            "#       #",
            "#       #",
            "#       #",
            "#       #",
            "#       #",
            " #####  "
        ]
        
        # Draw document icon
        for y, line in enumerate(doc_icon):
            for x, char in enumerate(line):
                if char == '#':
                    px = (size[0] - len(line) * 10) // 2 + x * 10
                    py = (size[1] - len(doc_icon) * 10) // 2 + y * 10 - 20
                    draw.rectangle([px, py, px+8, py+8], fill=(100, 150, 200))
        
        # Add filename
        try:
            font = ImageFont.load_default()
            text = file_path.stem[:20] + '...' if len(file_path.stem) > 20 else file_path.stem
            text_bbox = draw.textbbox((0, 0), text, font=font)
            text_width = text_bbox[2] - text_bbox[0]
            text_height = text_bbox[3] - text_bbox[1]
            
            text_x = (size[0] - text_width) // 2
            text_y = size[1] - text_height - 10
            
            draw.text((text_x, text_y), text, fill=(0, 0, 0), font=font)
        except Exception as e:
            logger.warning(f"Error adding text to preview: {e}")
        
        img.save(output_path, 'JPEG', quality=quality)
        return output_path
    
    async def _generate_video_preview(
        self, 
        file_path: Path, 
        output_path: Path,
        size: Tuple[int, int],
        quality: int
    ) -> Path:
        """Generate a thumbnail for a video file."""
        # Extract a frame from the middle of the video
        cap = cv2.VideoCapture(str(file_path))
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        frame_pos = max(0, min(total_frames // 2, total_frames - 1))
        
        cap.set(cv2.CAP_PROP_POS_FRAMES, frame_pos)
        ret, frame = cap.read()
        cap.release()
        
        if not ret:
            raise ValueError("Could not read video frame")
        
        # Convert BGR to RGB
        frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        img = Image.fromarray(frame_rgb)
        
        # Create thumbnail
        img.thumbnail(size, Image.Resampling.LANCZOS)
        img.save(output_path, 'JPEG', quality=quality, optimize=True)
        
        return output_path
    
    async def _generate_audio_preview(
        self, 
        file_path: Path, 
        output_path: Path,
        size: Tuple[int, int],
        quality: int
    ) -> Path:
        """Generate a waveform image for an audio file."""
        try:
            # Load audio file
            y, sr = librosa.load(file_path, sr=None, mono=True)
            
            # Create a waveform image
            plt.figure(figsize=(size[0]/100, size[1]/100), dpi=100)
            plt.axis('off')
            plt.margins(0)
            plt.tight_layout(pad=0)
            
            # Plot waveform
            plt.plot(y, color='blue', linewidth=1)
            
            # Save to bytes buffer
            buf = io.BytesIO()
            plt.savefig(buf, format='png', bbox_inches='tight', pad_inches=0, dpi=100)
            plt.close()
            
            # Open the image and save as JPEG
            img = Image.open(buf)
            img = img.convert('RGB')
            img.save(output_path, 'JPEG', quality=quality, optimize=True)
            
            return output_path
            
        except Exception as e:
            logger.warning(f"Error generating audio preview: {e}")
            # Fall back to a generic audio icon
            return await self._generate_generic_preview('audio', output_path, size, quality)
    
    async def _generate_archive_preview(
        self, 
        file_path: Path, 
        output_path: Path,
        size: Tuple[int, int],
        quality: int
    ) -> Path:
        """Generate a preview for an archive file."""
        try:
            # List contents of the archive
            file_list = []
            
            if file_path.suffix.lower() == '.zip':
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    file_list = zip_ref.namelist()
            elif file_path.suffix.lower() in ('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2'):
                mode = 'r:gz' if file_path.suffix.lower().endswith('gz') else \
                       'r:bz2' if file_path.suffix.lower().endswith('bz2') else 'r'
                with tarfile.open(file_path, mode) as tar_ref:
                    file_list = tar_ref.getnames()
            
            # Create a preview with the file list
            from PIL import ImageDraw, ImageFont
            
            img = Image.new('RGB', size, (240, 240, 240))
            draw = ImageDraw.Draw(img)
            
            # Add archive icon (simplified)
            for y, line in enumerate([
                "  #####  ",
                " #     # ",
                "#  ###  #",
                "# #   # #",
                "#  ###  #",
                " #     # ",
                "  #####  "
            ]):
                for x, char in enumerate(line):
                    if char == '#':
                        px = (size[0] - len(line) * 10) // 2 + x * 10
                        py = (size[1] - len(line) * 10) // 2 + y * 10 - 30
                        draw.rectangle([px, py, px+8, py+8], fill=(200, 150, 100))
            
            # Add file count
            try:
                font = ImageFont.load_default()
                text = f"{len(file_list)} files"
                text_bbox = draw.textbbox((0, 0), text, font=font)
                text_width = text_bbox[2] - text_bbox[0]
                text_x = (size[0] - text_width) // 2
                text_y = size[1] - 40
                
                draw.text((text_x, text_y), text, fill=(0, 0, 0), font=font)
            except Exception as e:
                logger.warning(f"Error adding text to archive preview: {e}")
            
            img.save(output_path, 'JPEG', quality=quality)
            return output_path
            
        except Exception as e:
            logger.warning(f"Error generating archive preview: {e}")
            return await self._generate_generic_preview('archive', output_path, size, quality)
    
    async def _generate_text_preview(
        self, 
        file_path: Path, 
        output_path: Path,
        size: Tuple[int, int],
        quality: int
    ) -> Path:
        """Generate a preview for a text file."""
        try:
            # Read first few lines of the text file
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = [f.readline().strip() for _ in range(10)]
            
            # Create a preview image with the text
            from PIL import ImageDraw, ImageFont
            
            # Create a white background
            img = Image.new('RGB', size, (255, 255, 255))
            draw = ImageDraw.Draw(img)
            
            try:
                # Try to load a nice font, fall back to default if not available
                try:
                    font = ImageFont.truetype("Arial.ttf", 12)
                except IOError:
                    font = ImageFont.load_default()
                
                # Draw text lines
                y = 10
                for i, line in enumerate(lines):
                    if not line:
                        continue
                    # Truncate long lines
                    if len(line) > 50:
                        line = line[:47] + "..."
                    draw.text((10, y), line, fill=(0, 0, 0), font=font)
                    y += 15
                    
                    # Stop if we're running out of space
                    if y > size[1] - 20:
                        if i < len(lines) - 1:
                            draw.text((10, y), "...", fill=(100, 100, 100), font=font)
                        break
                
            except Exception as e:
                logger.warning(f"Error rendering text preview: {e}")
                # Fall back to a simple text preview
                draw.text((10, 10), f"Text file: {file_path.name}", fill=(0, 0, 0))
            
            img.save(output_path, 'JPEG', quality=quality)
            return output_path
            
        except Exception as e:
            logger.error(f"Error generating text preview: {e}")
            return await self._generate_generic_preview('text', output_path, size, quality)
    
    async def _generate_generic_preview(
        self, 
        file_type: str,
        output_path: Path,
        size: Tuple[int, int],
        quality: int
    ) -> Path:
        """Generate a generic file icon preview."""
        from PIL import ImageDraw, ImageFont
        
        # Colors based on file type
        colors = {
            'audio': (100, 150, 200),
            'video': (200, 100, 150),
            'archive': (200, 150, 100),
            'document': (150, 200, 150),
            'text': (200, 200, 150),
            'unknown': (180, 180, 180)
        }
        
        color = colors.get(file_type, colors['unknown'])
        
        # Create a blank image with a colored background
        img = Image.new('RGB', size, (240, 240, 240))
        draw = ImageDraw.Draw(img)
        
        # Draw a file icon
        icon_size = min(size) // 2
        x = (size[0] - icon_size) // 2
        y = (size[1] - icon_size) // 2 - 20
        
        # Draw file shape
        draw.rectangle([x, y, x + icon_size, y + icon_size], fill=color, outline=(200, 200, 200))
        
        # Draw file fold
        fold_size = icon_size // 4
        points = [
            (x + icon_size - fold_size, y),
            (x + icon_size, y + fold_size),
            (x + icon_size - fold_size, y + fold_size),
            (x + icon_size - fold_size, y)
        ]
        draw.polygon(points, fill=(220, 220, 220), outline=(200, 200, 200))
        
        # Add file type text
        try:
            font = ImageFont.load_default()
            text = file_type.upper()
            text_bbox = draw.textbbox((0, 0), text, font=font)
            text_width = text_bbox[2] - text_bbox[0]
            text_height = text_bbox[3] - text_bbox[1]
            
            text_x = (size[0] - text_width) // 2
            text_y = y + icon_size + 10
            
            draw.text((text_x, text_y), text, fill=(100, 100, 100), font=font)
        except Exception:
            pass
        
        img.save(output_path, 'JPEG', quality=quality)
        return output_path

# Example usage
if __name__ == "__main__":
    import asyncio
    
    async def main():
        preview_gen = FilePreviewGenerator()
        
        # Example files (replace with actual file paths)
        files_to_preview = [
            "example.jpg",
            "document.pdf",
            "presentation.pptx",
            "video.mp4",
            "audio.mp3",
            "archive.zip"
        ]
        
        for file_path in files_to_preview:
            if os.path.exists(file_path):
                output_path = f"preview_{os.path.splitext(file_path)[0]}.jpg"
                preview = await preview_gen.generate_preview(file_path, output_path)
                if preview:
                    print(f"Generated preview: {preview}")
    
    asyncio.run(main())
