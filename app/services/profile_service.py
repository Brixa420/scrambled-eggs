"""
Profile management service for handling user profiles and avatars.
"""

import logging
import uuid
from io import BytesIO
from pathlib import Path
from typing import Optional, Tuple

from fastapi import HTTPException, UploadFile, status
from PIL import Image

# Configure logging
logger = logging.getLogger(__name__)


class ProfileService:
    """Service for managing user profiles and profile pictures."""

    def __init__(self, upload_folder: str = "uploads/profiles"):
        """Initialize the profile service.

        Args:
            upload_folder: Base directory for profile uploads
        """
        self.upload_folder = Path(upload_folder)
        self.avatar_sizes = {"small": (64, 64), "medium": (128, 128), "large": (256, 256)}
        self.banner_sizes = {"small": (400, 120), "large": (1200, 360)}
        self.allowed_image_types = {"image/jpeg", "image/png", "image/webp"}
        self.max_file_size = 5 * 1024 * 1024  # 5MB

        # Create upload directories if they don't exist
        self.avatar_folder = self.upload_folder / "avatars"
        self.banner_folder = self.upload_folder / "banners"
        self.avatar_folder.mkdir(parents=True, exist_ok=True)
        self.banner_folder.mkdir(parents=True, exist_ok=True)

    async def validate_image(
        self, file: UploadFile, max_width: Optional[int] = None, max_height: Optional[int] = None
    ) -> Tuple[Image.Image, str]:
        """Validate and process an uploaded image.

        Args:
            file: Uploaded file
            max_width: Optional max width for the image
            max_height: Optional max height for the image

        Returns:
            Tuple of (PIL Image, file extension)
        """
        # Check file type
        if file.content_type not in self.allowed_image_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File type {file.content_type} not allowed. Use JPEG, PNG, or WebP.",
            )

        # Check file size
        contents = await file.read()
        if len(contents) > self.max_file_size:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File too large. Max size is {self.max_file_size/1024/1024}MB",
            )

        try:
            # Open image with PIL
            image = Image.open(BytesIO(contents))

            # Convert to RGB if needed (for PNG with transparency)
            if image.mode in ("RGBA", "P"):
                image = image.convert("RGB")

            # Resize if dimensions are provided
            if max_width and max_height:
                image.thumbnail((max_width, max_height), Image.Resampling.LANCZOS)

            return image, "jpg" if file.content_type == "image/jpeg" else "png"

        except Exception as e:
            logger.error(f"Error processing image: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid image file"
            )

    async def upload_avatar(
        self, user_id: int, file: UploadFile, crop_data: Optional[dict] = None
    ) -> str:
        """Upload and process a user avatar.

        Args:
            user_id: ID of the user
            file: Uploaded avatar file
            crop_data: Optional crop data {x, y, width, height}

        Returns:
            URL of the uploaded avatar
        """
        # Process the image
        image, ext = await self.validate_image(file, 1024, 1024)

        # Apply crop if provided
        if crop_data:
            image = image.crop(
                (
                    crop_data["x"],
                    crop_data["y"],
                    crop_data["x"] + crop_data["width"],
                    crop_data["y"] + crop_data["height"],
                )
            )

        # Generate unique filename
        filename = f"{user_id}_{uuid.uuid4().hex}.{ext}"

        # Save different sizes
        for size_name, (width, height) in self.avatar_sizes.items():
            # Create size directory if it doesn't exist
            size_dir = self.avatar_folder / size_name
            size_dir.mkdir(exist_ok=True)

            # Resize and save
            resized = image.copy()
            resized.thumbnail((width, height), Image.Resampling.LANCZOS)
            resized.save(size_dir / filename, quality=85)

        # Return the relative path
        return f"/uploads/profiles/avatars/medium/{filename}"

    async def upload_banner(self, user_id: int, file: UploadFile) -> str:
        """Upload and process a user banner.

        Args:
            user_id: ID of the user
            file: Uploaded banner file

        Returns:
            URL of the uploaded banner
        """
        # Process the image
        image, ext = await self.validate_image(file, 2000, 600)

        # Generate unique filename
        filename = f"{user_id}_{uuid.uuid4().hex}.{ext}"

        # Save different sizes
        for size_name, (width, height) in self.banner_sizes.items():
            # Create size directory if it doesn't exist
            size_dir = self.banner_folder / size_name
            size_dir.mkdir(exist_ok=True)

            # Resize and save (crop to maintain aspect ratio)
            resized = image.copy()
            resized.thumbnail(
                (width * 2, height * 2), Image.Resampling.LANCZOS
            )  # For better quality

            # Center crop
            left = (resized.width - width) / 2
            top = (resized.height - height) / 2
            right = (resized.width + width) / 2
            bottom = (resized.height + height) / 2

            cropped = resized.crop((left, top, right, bottom))
            cropped.save(size_dir / filename, quality=85)

        # Return the relative path
        return f"/uploads/profiles/banners/large/{filename}"

    def delete_old_avatar(self, user_id: int):
        """Delete old avatar files for a user."""
        try:
            for size_dir in self.avatar_folder.glob("*"):
                if size_dir.is_dir():
                    for file in size_dir.glob(f"{user_id}_*"):
                        try:
                            file.unlink()
                        except OSError:
                            pass
        except Exception as e:
            logger.error(f"Error deleting old avatar for user {user_id}: {str(e)}")

    def delete_old_banner(self, user_id: int):
        """Delete old banner files for a user."""
        try:
            for size_dir in self.banner_folder.glob("*"):
                if size_dir.is_dir():
                    for file in size_dir.glob(f"{user_id}_*"):
                        try:
                            file.unlink()
                        except OSError:
                            pass
        except Exception as e:
            logger.error(f"Error deleting old banner for user {user_id}: {str(e)}")


# Global instance
profile_service = ProfileService()
