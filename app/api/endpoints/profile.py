"""
API endpoints for user profiles and avatars.
"""

from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.core.security import get_current_user
from app.db.session import get_db
from app.models.user import User
from app.schemas.profile import (
    AvatarUploadResponse,
    BannerUploadResponse,
    ProfileResponse,
    ProfileUpdate,
)
from app.services.profile_service import profile_service

router = APIRouter()


@router.get("/me", response_model=ProfileResponse)
async def get_my_profile(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    """Get the current user's profile."""
    return current_user


@router.put("/me", response_model=ProfileResponse)
async def update_my_profile(
    profile_data: ProfileUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update the current user's profile."""
    # Update basic profile fields
    update_data = profile_data.dict(exclude_unset=True, exclude_none=True)

    # Handle password change if requested
    if "new_password" in update_data and update_data["new_password"]:
        if not update_data.get("current_password"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is required to change password",
            )
        if not current_user.verify_password(update_data["current_password"]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect current password"
            )
        current_user.set_password(update_data["new_password"])
        update_data.pop("new_password")
        update_data.pop("current_password")

    # Update user fields
    for field, value in update_data.items():
        if hasattr(current_user, field):
            setattr(current_user, field, value)

    db.add(current_user)
    db.commit()
    db.refresh(current_user)

    return current_user


@router.post("/me/avatar", response_model=AvatarUploadResponse)
async def upload_avatar(
    file: UploadFile = File(...),
    x: Optional[float] = Form(None),
    y: Optional[float] = Form(None),
    width: Optional[float] = Form(None),
    height: Optional[float] = Form(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Upload a new avatar for the current user."""
    # Prepare crop data if all values are provided
    crop_data = None
    if all(v is not None for v in [x, y, width, height]):
        crop_data = {"x": int(x), "y": int(y), "width": int(width), "height": int(height)}

    try:
        # Delete old avatar files
        profile_service.delete_old_avatar(current_user.id)

        # Upload new avatar
        avatar_url = await profile_service.upload_avatar(current_user.id, file, crop_data)

        # Update user's avatar URL
        current_user.avatar = avatar_url
        db.add(current_user)
        db.commit()
        db.refresh(current_user)

        return {"url": avatar_url}

    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/me/banner", response_model=BannerUploadResponse)
async def upload_banner(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Upload a new banner for the current user."""
    try:
        # Delete old banner files
        profile_service.delete_old_banner(current_user.id)

        # Upload new banner
        banner_url = await profile_service.upload_banner(current_user.id, file)

        # Update user's banner URL
        current_user.banner = banner_url
        db.add(current_user)
        db.commit()
        db.refresh(current_user)

        return {"url": banner_url}

    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/{user_id}", response_model=ProfileResponse)
async def get_user_profile(user_id: int, db: Session = Depends(get_db)):
    """Get a user's public profile."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user
