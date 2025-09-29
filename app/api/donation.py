from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from typing import Optional
from decimal import Decimal
import logging

from app.core.security import get_current_user
from app.models.user import User
from app.services.subscription_service import subscription_service
from app.models.subscription import SubscriptionPayment

router = APIRouter(prefix="/donations", tags=["donations"])
logger = logging.getLogger(__name__)

@router.post("/")
async def create_donation(
    streamer_id: int,
    amount: float,
    payment_method_id: str,
    message: Optional[str] = None,
    is_anonymous: bool = False,
    current_user: User = Depends(get_current_user)
):
    """
    Create a direct donation to a streamer with no profit share.
    
    Args:
        streamer_id: ID of the streamer to donate to
        amount: Donation amount in USD (minimum $1.00)
        payment_method_id: Stripe payment method ID
        message: Optional message to include with the donation
        is_anonymous: Whether to keep the donor anonymous
    """
    try:
        # Convert amount to Decimal for precise calculations
        amount_decimal = Decimal(str(amount))
        
        # Process the donation
        payment, error = await subscription_service.create_donation(
            donor_id=current_user.id,
            streamer_id=streamer_id,
            amount=amount_decimal,
            payment_method_id=payment_method_id,
            message=message,
            is_anonymous=is_anonymous
        )
        
        if error:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error
            )
            
        return {
            "status": "success",
            "payment_id": payment.id,
            "amount": float(payment.amount),
            "message": "Donation processed successfully"
        }
        
    except Exception as e:
        logger.error(f"Error processing donation: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing your donation"
        )

@router.get("/streamer/{streamer_id}")
async def get_streamer_donations(
    streamer_id: int,
    limit: int = 50,
    current_user: User = Depends(get_current_user)
):
    """
    Get recent donations for a streamer (public endpoint).
    Anonymous donations will only show the amount and message.
    """
    try:
        donations = SubscriptionPayment.query.filter_by(
            streamer_id=streamer_id,
            payment_type=SubscriptionPayment.TYPE_DONATION,
            status='succeeded'
        ).order_by(SubscriptionPayment.payment_date.desc()).limit(limit).all()
        
        return {
            "status": "success",
            "donations": [{
                "amount": float(d.amount),
                "currency": d.currency,
                "message": d.message,
                "is_anonymous": d.is_anonymous,
                "donor": None if d.is_anonymous or not d.donor else {
                    "username": d.donor.username,
                    "avatar_url": d.donor.avatar_url
                },
                "timestamp": d.payment_date.isoformat()
            } for d in donations]
        }
        
    except Exception as e:
        logger.error(f"Error fetching donations: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while fetching donations"
        )

@router.get("/my-donations")
async def get_my_donations(
    current_user: User = Depends(get_current_user)
):
    """
    Get the current user's donation history.
    """
    try:
        donations = SubscriptionPayment.query.filter_by(
            donor_id=current_user.id,
            payment_type=SubscriptionPayment.TYPE_DONATION
        ).order_by(SubscriptionPayment.payment_date.desc()).all()
        
        return {
            "status": "success",
            "donations": [{
                "id": d.id,
                "amount": float(d.amount),
                "currency": d.currency,
                "message": d.message,
                "is_anonymous": d.is_anonymous,
                "streamer": {
                    "id": d.streamer.id,
                    "username": d.streamer.username,
                    "avatar_url": d.streamer.avatar_url
                },
                "timestamp": d.payment_date.isoformat(),
                "status": d.status
            } for d in donations]
        }
        
    except Exception as e:
        logger.error(f"Error fetching donation history: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while fetching your donation history"
        )
