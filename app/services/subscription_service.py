import stripe
import logging
from datetime import datetime, timedelta
from decimal import Decimal, ROUND_DOWN
from typing import Dict, Optional, List, Tuple, Any

from app import db
from app.models.subscription import (
    SubscriptionPlan, 
    UserSubscription, 
    SubscriptionPayment,
    SubscriptionPlan as PlanModel
)
from app.core.config import settings
from app.models.user import User
from app.services.brixa_service import brixa_service

logger = logging.getLogger(__name__)

class SubscriptionService:
    """
    Service for handling subscription and donation operations with profit sharing.
    """
    
    def __init__(self):
        self.stripe = stripe
        self.stripe.api_key = settings.STRIPE_SECRET_KEY
        self.admin_share_percent = Decimal('10.0')  # 10% to admin for subscriptions
        self.creator_share_percent = Decimal('90.0')  # 90% to creator for subscriptions
    
    async def initialize_default_plans(self) -> bool:
        """Initialize default subscription plans if they don't exist."""
        try:
            for plan_data in PlanModel.get_default_tiers():
                # Check if plan already exists
                existing = SubscriptionPlan.query.filter_by(tier=plan_data['tier']).first()
                if existing:
                    continue
                    
                # Create Stripe product and price
                product = self.stripe.Product.create(
                    name=plan_data['name'],
                    description=plan_data.get('description', '')
                )
                
                price = self.stripe.Price.create(
                    product=product.id,
                    unit_amount=int(float(plan_data['price']) * 100),  # Convert to cents
                    currency='usd',
                    recurring={'interval': 'month'}
                )
                
                # Create database record
                plan = SubscriptionPlan(
                    tier=plan_data['tier'],
                    name=plan_data['name'],
                    description=plan_data.get('description', ''),
                    price=plan_data['price'],
                    default_features=plan_data.get('default_features', []),
                    stripe_product_id=product.id,
                    stripe_price_id=price.id
                )
                
                db.session.add(plan)
            
            db.session.commit()
            return True
            
        except Exception as e:
            logger.error(f"Error initializing default plans: {str(e)}")
            db.session.rollback()
            return False
    
    async def create_subscription(
        self, 
        user_id: int, 
        plan_tier: str, 
        payment_method_id: str,
        custom_perks: List[str] = None
    ) -> Tuple[Optional[UserSubscription], str]:
        """
        Create a new subscription with the specified tier.
        
        Args:
            user_id: ID of the user subscribing
            plan_tier: Tier of the subscription plan (basic, premium, elite)
            payment_method_id: Stripe payment method ID
            custom_perks: List of custom perks selected by the streamer
            
        Returns:
            Tuple of (UserSubscription, client_secret) if successful, (None, error) otherwise
        """
        try:
            plan = SubscriptionPlan.query.filter_by(tier=plan_tier, is_active=True).first()
            if not plan:
                return None, "Invalid subscription plan"
                
            user = User.query.get(user_id)
            if not user:
                return None, "User not found"
            
            # Create or get Stripe customer
            customer_id = user.stripe_customer_id
            if not customer_id:
                customer = self.stripe.Customer.create(
                    email=user.email,
                    payment_method=payment_method_id,
                    invoice_settings={
                        'default_payment_method': payment_method_id
                    }
                )
                user.stripe_customer_id = customer.id
                customer_id = customer.id
                db.session.commit()
            
            # Create subscription in Stripe
            subscription = self.stripe.Subscription.create(
                customer=customer_id,
                items=[{'price': plan.stripe_price_id}],
                payment_behavior='default_incomplete',
                payment_settings={'save_default_payment_method': 'on_subscription'},
                expand=['latest_invoice.payment_intent'],
            )
            
            # Create database record
            user_subscription = UserSubscription(
                user_id=user_id,
                plan_id=plan.id,
                stripe_subscription_id=subscription.id,
                current_period_start=datetime.fromtimestamp(subscription.current_period_start),
                current_period_end=datetime.fromtimestamp(subscription.current_period_end),
                profit_share_accepted=True,  # Required for streamers
                profit_share_percent=self.admin_share_percent,
                custom_perks=custom_perks or []
            )
            
            db.session.add(user_subscription)
            db.session.commit()
            
            return user_subscription, None
            
        except self.stripe.error.StripeError as e:
            logger.error(f"Stripe error creating subscription: {str(e)}")
            db.session.rollback()
            return None, str(e)
        except Exception as e:
            logger.error(f"Error creating subscription: {str(e)}")
            db.session.rollback()
            return None, "An unexpected error occurred"
    
    async def create_donation(
        self,
        donor_id: int,
        streamer_id: int,
        amount: Decimal,
        payment_method_id: str,
        message: str = None,
        is_anonymous: bool = False
    ) -> Tuple[Optional[SubscriptionPayment], str]:
        """
        Process a direct donation to a streamer with no profit share.
        
        Args:
            donor_id: ID of the user making the donation
            streamer_id: ID of the streamer receiving the donation
            amount: Donation amount in USD
            payment_method_id: Stripe payment method ID
            message: Optional message from donor
            is_anonymous: Whether to keep the donor anonymous
            
        Returns:
            Tuple of (SubscriptionPayment, error_message)
        """
        try:
            if amount < Decimal('1.00'):
                return None, "Minimum donation amount is $1.00"
                
            donor = User.query.get(donor_id)
            streamer = User.query.get(streamer_id)
            
            if not donor or not streamer:
                return None, "Invalid user or streamer"
                
            # Create payment intent
            payment_intent = self.stripe.PaymentIntent.create(
                amount=int(amount * 100),  # Convert to cents
                currency='usd',
                payment_method=payment_method_id,
                confirmation_method='manual',
                confirm=True,
                metadata={
                    'donor_id': str(donor_id),
                    'streamer_id': str(streamer_id),
                    'is_anonymous': str(is_anonymous)
                },
                description=f"Donation to {streamer.username}"
            )
            
            # Record donation
            payment = SubscriptionPayment(
                payment_type=SubscriptionPayment.TYPE_DONATION,
                streamer_id=streamer_id,
                donor_id=None if is_anonymous else donor_id,
                amount=amount,
                admin_share=Decimal('0'),  # No profit share on donations
                creator_share=amount,
                currency='USD',
                stripe_payment_intent_id=payment_intent.id,
                status=payment_intent.status,
                message=message,
                is_anonymous=is_anonymous,
                payment_date=datetime.utcnow()
            )
            
            db.session.add(payment)
            db.session.commit()
            
            # Process payout to streamer
            await self._process_payout(payment)
            
            return payment, None
            
        except self.stripe.error.StripeError as e:
            logger.error(f"Stripe error processing donation: {str(e)}")
            db.session.rollback()
            return None, str(e)
        except Exception as e:
            logger.error(f"Error processing donation: {str(e)}")
            db.session.rollback()
            return None, "An unexpected error occurred"
    
    async def update_subscription_perks(
        self,
        subscription_id: int,
        streamer_id: int,
        custom_perks: List[str]
    ) -> Tuple[bool, str]:
        """
        Update custom perks for a subscription.
        
        Args:
            subscription_id: ID of the subscription to update
            streamer_id: ID of the streamer making the change
            custom_perks: List of custom perks to enable
            
        Returns:
            Tuple of (success, error_message)
        """
        try:
            subscription = UserSubscription.query.get(subscription_id)
            if not subscription:
                return False, "Subscription not found"
                
            # Verify the streamer owns this subscription
            if subscription.user_id != streamer_id:
                return False, "Unauthorized"
            
            # Get available perks for this plan
            plan = subscription.plan
            if not plan:
                return False, "Invalid subscription plan"
                
            # In a real app, you might want to validate the perks against allowed options
            subscription.custom_perks = custom_perks or []
            db.session.commit()
            
            return True, None
            
        except Exception as e:
            logger.error(f"Error updating subscription perks: {str(e)}")
            db.session.rollback()
            return False, str(e)
    
    async def _process_payout(self, payment: SubscriptionPayment) -> bool:
        """Process a single payout to the creator."""
        try:
            if payment.creator_share <= 0:
                return True
                
            creator = payment.streamer
            if not creator.stripe_account_id:
                logger.warning(f"Creator {creator.id} has no connected Stripe account")
                return False
                
            # In production, you would use Stripe Connect to transfer funds
            # This is a simplified example
            transfer = self.stripe.Transfer.create(
                amount=int(payment.creator_share * 100),  # Convert to cents
                currency=payment.currency.lower(),
                destination=creator.stripe_account_id,
                description=f"Payout for {payment.payment_type} {payment.id}",
                metadata={
                    'payment_id': str(payment.id),
                    'creator_id': str(creator.id)
                }
            )
            
            # Update payment record
            payment.payout_date = datetime.utcnow()
            payment.status = 'paid_out'
            db.session.commit()
            
            logger.info(f"Processed payout of ${payment.creator_share} to creator {creator.id}")
            return True
            
        except self.stripe.error.StripeError as e:
            logger.error(f"Stripe error processing payout: {str(e)}")
            payment.status = 'payout_failed'
            db.session.commit()
            return False
        except Exception as e:
            logger.error(f"Error processing payout: {str(e)}")
            payment.status = 'error'
            db.session.commit()
            return False
            
        except Exception as e:
            logger.error(f"Error processing payouts: {str(e)}")
            return False
    
    async def cancel_subscription(self, subscription_id: str) -> bool:
        """Cancel a subscription."""
        try:
            # Cancel in Stripe
            self.stripe.Subscription.delete(subscription_id)
            
            # Update database
            subscription = UserSubscription.query.filter_by(
                stripe_subscription_id=subscription_id
            ).first()
            
            if subscription:
                subscription.status = 'canceled'
                subscription.cancel_at_period_end = True
                subscription.updated_at = datetime.utcnow()
                db.session.commit()
            
            return True
            
        except Exception as e:
            logger.error(f"Error canceling subscription: {str(e)}")
            return False

# Singleton instance
subscription_service = SubscriptionService()
