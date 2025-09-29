from fastapi import APIRouter, Depends, HTTPException, status, Body
from fastapi.responses import JSONResponse
from typing import List, Optional, Dict, Any
import logging
from datetime import datetime
from decimal import Decimal

from app.core.security import get_current_user, get_current_streamer
from app.models.user import User
from app.models.subscription import (
    SubscriptionPlan, 
    UserSubscription,
    SubscriptionPayment
)
from app.services.subscription_service import subscription_service
from app import db

router = APIRouter(prefix="/subscriptions", tags=["subscriptions"])
logger = logging.getLogger(__name__)

@router.post("/plans/init")
async def initialize_plans(current_user: User = Depends(get_current_user)):
    """
    Initialize default subscription plans (admin only).
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can initialize subscription plans"
        )
    
    success = await subscription_service.initialize_default_plans()
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to initialize default plans"
        )
    
    return {
        'status': 'success',
        'message': 'Default subscription plans initialized successfully'
    }

@router.get("/plans")
async def list_plans(include_inactive: bool = False):
    """
    List all available subscription plans.
    
    Args:
        include_inactive: Include inactive plans in the results (admin only)
    """
    query = SubscriptionPlan.query
    if not include_inactive:
        query = query.filter_by(is_active=True)
    
    plans = query.order_by(SubscriptionPlan.price).all()
    
    return {
        'status': 'success',
        'plans': [{
            'id': plan.id,
            'tier': plan.tier,
            'name': plan.name,
            'description': plan.description,
            'price': float(plan.price),
            'is_active': plan.is_active,
            'features': plan.default_features,
            'customization_options': getattr(plan, 'customization_options', []) if plan.tier == 'elite' else []
        } for plan in plans]
    }

@router.post("/subscribe")
async def subscribe(
    tier: str = Body(..., embed=True),
    payment_method_id: str = Body(..., embed=True),
    custom_perks: Optional[List[str]] = Body(default=None, embed=True),
    current_user: User = Depends(get_current_streamer)
):
    """
    Subscribe to a subscription tier.
    
    Args:
        tier: The subscription tier (basic, premium, elite)
        payment_method_id: Stripe payment method ID
        custom_perks: List of custom perks (for elite tier)
    """
    # Check if user already has an active subscription
    active_sub = UserSubscription.query.filter_by(
        user_id=current_user.id,
        status='active'
    ).first()
    
    if active_sub:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You already have an active subscription"
        )
    
    # Create subscription
    subscription, error = await subscription_service.create_subscription(
        user_id=current_user.id,
        plan_tier=tier,
        payment_method_id=payment_method_id,
        custom_perks=custom_perks
    )
    
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    if not subscription:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to create subscription"
        )
    
    return {
        'status': 'success',
        'subscription_id': subscription.id,
        'message': 'Subscription created successfully',
        'requires_action': False,
        'payment_intent_secret': None
    }

@router.post("/cancel-subscription")
async def cancel_subscription(
    subscription_id: int,
    current_user: User = Depends(get_current_user)
):
    """Cancel a subscription."""
    subscription = UserSubscription.query.filter_by(
        id=subscription_id,
        user_id=current_user.id
    ).first()
    
    if not subscription:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Subscription not found"
        )
    
    success = await subscription_service.cancel_subscription(
        subscription.stripe_subscription_id
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to cancel subscription"
        )
    
    return {
        'status': 'success',
        'message': 'Subscription will be canceled at the end of the billing period'
    }

@router.get("/my-subscriptions")
async def get_my_subscriptions(
    current_user: User = Depends(get_current_user)
):
    """Get current user's subscriptions."""
    subscriptions = UserSubscription.query.filter_by(
        user_id=current_user.id
    ).join(SubscriptionPlan).all()
    
    return {
        'status': 'success',
        'subscriptions': [{
            'id': sub.id,
            'plan_name': sub.plan.name,
            'status': sub.status,
            'current_period_start': sub.current_period_start.isoformat(),
            'current_period_end': sub.current_period_end.isoformat(),
            'profit_share_accepted': sub.profit_share_accepted,
            'profit_share_percent': float(sub.profit_share_percent) if sub.profit_share_accepted else 0,
            'created_at': sub.created_at.isoformat()
        } for sub in subscriptions]
    }

@router.get("/profit-share/accept")
async def accept_profit_share(
    subscription_id: int,
    current_user: User = Depends(get_current_user)
):
    """Accept the 10% profit share agreement for a subscription."""
    subscription = UserSubscription.query.filter_by(
        id=subscription_id,
        user_id=current_user.id
    ).first()
    
    if not subscription:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Subscription not found"
        )
    
    if subscription.status != 'active':
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only active subscriptions can accept profit sharing"
        )
    
    subscription.profit_share_accepted = True
    subscription.profit_share_percent = 10.0  # 10% to admin
    db.session.commit()
    
    return {
        'status': 'success',
        'message': 'Profit sharing agreement accepted',
        'profit_share_percent': 10.0
    }

# Webhook handler for Stripe events
@router.post("/webhook/stripe")
async def stripe_webhook(payload: dict):
    """Handle Stripe webhook events."""
    event = None
    
    try:
        # Verify webhook signature in production
        # event = stripe.Webhook.construct_event(
        #     payload, sig_header, endpoint_secret
        # )
        event = payload  # For development only
    except Exception as e:
        logger.error(f"Webhook signature verification failed: {str(e)}")
        return JSONResponse(
            status_code=400,
            content={"error": "Invalid signature"}
        )
    
    # Handle the event
    if event['type'] == 'invoice.payment_succeeded':
        subscription_id = event['data']['object']['subscription']
        await subscription_service.process_subscription_payment(subscription_id)
    
    elif event['type'] == 'customer.subscription.updated':
        # Handle subscription updates (e.g., cancellation, plan changes)
        pass
    
    elif event['type'] == 'customer.subscription.deleted':
        # Handle subscription cancellation
        subscription_id = event['data']['object']['id']
        subscription = UserSubscription.query.filter_by(
            stripe_subscription_id=subscription_id
        ).first()
        
        if subscription:
            subscription.status = 'canceled'
            db.session.commit()
    
    return JSONResponse(status_code=200, content={"status": "success"})
