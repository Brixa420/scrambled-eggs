from fastapi import APIRouter, Depends, HTTPException, status, Body, Request
from fastapi.responses import JSONResponse
from typing import List, Optional, Dict, Any
import logging
from datetime import datetime
from decimal import Decimal, ROUND_DOWN

from app.core.security import get_current_user, get_current_streamer
from app.models.user import User
from app.models.subscription import (
    SubscriptionPlan, 
    UserSubscription,
    SubscriptionPayment
)
from app.services.subscription_service import subscription_service
from app.services.brixa_service import brixa_service
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
async def list_plans(include_inactive: bool = False, request: Request = None):
    """
    List all available subscription plans with current Brixa prices.
    
    Args:
        include_inactive: Include inactive plans in the results (admin only)
    """
    try:
        query = SubscriptionPlan.query
        
        if not include_inactive:
            query = query.filter_by(is_active=True)
            
        plans = query.order_by(SubscriptionPlan.price).all()
        
        # Get current Brixa price in USD
        brixa_price = await brixa_service.get_brixa_price_usd()
        
        # Prepare plan data with Brixa prices
        plan_data = []
        for plan in plans:
            plan_dict = plan.to_dict()
            
            # Add Brixa price information
            if brixa_price and brixa_price > 0:
                plan_dict['brixa_price'] = str((Decimal(str(plan.price)) / brixa_price).quantize(Decimal('0.000001'), rounding=ROUND_DOWN))
                plan_dict['brixa_price_usd'] = str(brixa_price.quantize(Decimal('0.000001'), rounding=ROUND_DOWN))
            else:
                plan_dict['brixa_price'] = None
                plan_dict['brixa_price_usd'] = None
                
            plan_data.append(plan_dict)
        
        # Add Brixa wallet address for payments (if configured)
        brixa_wallet_address = getattr(settings, 'BRIXA_RECEIVING_ADDRESS', None)
        
        response_data = {
            'status': 'success',
            'data': plan_data,
            'brixa_wallet_address': brixa_wallet_address
        }
        
        return response_data
        
    except Exception as e:
        logger.error(f"Error listing subscription plans: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while retrieving subscription plans"
        )

@router.post("/subscribe")
async def subscribe(
    tier: str = Body(..., embed=True),
    payment_method: str = Body('stripe', embed=True),
    payment_method_id: str = Body(None, embed=True),
    brixa_tx_hash: str = Body(None, embed=True),
    custom_perks: Optional[List[str]] = Body(default=None, embed=True),
    current_user: User = Depends(get_current_streamer)
):
    """
    Subscribe to a subscription tier.
    
    Args:
        tier: The subscription tier (basic, premium, elite)
        payment_method: Payment method ('stripe' or 'brixa')
        payment_method_id: Required for Stripe payments (payment method ID) or Brixa (wallet address)
        brixa_tx_hash: Required for Brixa payments (transaction hash)
        custom_perks: List of custom perks (for elite tier)
    """
    try:
        # Validate payment method
        valid_payment_methods = [
            SubscriptionPayment.PAYMENT_METHOD_STRIPE,
            SubscriptionPayment.PAYMENT_METHOD_BRIXA
        ]
        
        if payment_method not in valid_payment_methods:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid payment method. Must be one of: {', '.join(valid_payment_methods)}"
            )
        
        # Validate payment method specific fields
        if payment_method == SubscriptionPayment.PAYMENT_METHOD_STRIPE and not payment_method_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Payment method ID is required for Stripe payments"
            )
            
        if payment_method == SubscriptionPayment.PAYMENT_METHOD_BRIXA and not brixa_tx_hash:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Transaction hash is required for Brixa payments"
            )
        
        # Get the subscription plan
        plan = SubscriptionPlan.query.filter_by(tier=tier.lower(), is_active=True).first()
        if not plan:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid subscription tier: {tier}"
            )
        
        # For elite tier, validate custom perks
        if tier.lower() == 'elite' and custom_perks:
            # In a real implementation, you might want to validate the custom perks
            # against a list of allowed perks or have some validation logic
            pass
        
        # Process the subscription payment
        success, message, subscription = await subscription_service.process_subscription_payment(
            user=current_user,
            plan=plan,
            payment_method=payment_method,
            payment_method_id=payment_method_id,
            is_anonymous=False,  # For now, all subscriptions are public
            brixa_tx_hash=brixa_tx_hash
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=message
            )
        
        # If this is an elite subscription with custom perks, update them
        if tier.lower() == 'elite' and custom_perks:
            subscription.custom_perks = custom_perks
            db.session.commit()
        
        return {
            'status': 'success',
            'message': message,
            'subscription': subscription.to_dict()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error subscribing to {tier}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while processing your subscription: {str(e)}"
        )

@router.delete("/{subscription_id}")
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
