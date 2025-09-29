from datetime import datetime
from app import db
from sqlalchemy.dialects.postgresql import JSONB

class SubscriptionPlan(db.Model):
    __tablename__ = 'subscription_plans'
    
    TIER_BASIC = 'basic'  # $5/month
    TIER_PREMIUM = 'premium'  # $10/month
    TIER_ELITE = 'elite'  # $25/month
    
    id = db.Column(db.Integer, primary_key=True)
    tier = db.Column(db.String(20), nullable=False, unique=True)  # basic, premium, elite
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Numeric(10, 2), nullable=False)  # Monthly price in USD
    default_features = db.Column(JSONB, default=list)  # Default features for this tier
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    subscriptions = db.relationship('UserSubscription', back_populates='plan')
    
    @classmethod
    def get_default_tiers(cls):
        """Return the default subscription tiers with their default features."""
        return [
            {
                'tier': cls.TIER_BASIC,
                'name': 'Basic Supporter',
                'price': 5.00,
                'default_features': [
                    'Exclusive chat badge',
                    'Custom emojis in chat',
                    'Early access to content',
                    'Subscriber-only chat'
                ]
            },
            {
                'tier': cls.TIER_PREMIUM,
                'name': 'Premium Supporter',
                'price': 10.00,
                'default_features': [
                    'All Basic perks',
                    'Custom username color',
                    'Priority in chat',
                    'Exclusive monthly content',
                    'Polls and Q&A priority'
                ]
            },
            {
                'tier': cls.TIER_ELITE,
                'name': 'Elite Supporter',
                'price': 25.00,
                'description': 'For the most dedicated fans who want the ultimate experience and personal connection with the creator.',
                'default_features': [
                    'All Premium perks',
                    'Exclusive merchandise package',
                    'Voting power on stream content and schedule',
                    'Early access to all new content',
                    'Special Discord role and access',
                    'Customizable stream alerts'
                ],
                'customization_options': [
                    'Personalized thank you video from the creator',
                    'Monthly 1-on-1 stream (30 minutes)',
                    'Behind-the-scenes content',
                    'Custom emote or badge design',
                    'Personalized stream shoutouts',
                    'Exclusive Discord channel access',
                    'Custom alert sounds',
                    'Personalized thank you message',
                    'Early access to merchandise'
                ]
            }
        ]
        
    def to_dict(self, include_features=True):
        """Convert subscription plan to dictionary."""
        data = {
            'id': self.id,
            'tier': self.tier,
            'name': self.name,
            'description': self.description,
            'price': float(self.price) if self.price else 0.0,
            'is_active': self.is_active
        }
        if include_features:
            data['features'] = self.default_features
        return data

class UserSubscription(db.Model):
    __tablename__ = 'user_subscriptions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    plan_id = db.Column(db.Integer, db.ForeignKey('subscription_plans.id'), nullable=False)
    stripe_subscription_id = db.Column(db.String(100))
    status = db.Column(db.String(20), default='active')  # active, canceled, past_due, etc.
    current_period_start = db.Column(db.DateTime)
    current_period_end = db.Column(db.DateTime)
    cancel_at_period_end = db.Column(db.Boolean, default=False)
    profit_share_accepted = db.Column(db.Boolean, default=False)
    profit_share_percent = db.Column(db.Numeric(5, 2), default=10.0)  # 10% to admin
    custom_perks = db.Column(JSONB, default=list)  # Streamer-customized perks for this subscription
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', back_populates='subscriptions')
    plan = db.Column('SubscriptionPlan', back_populates='subscriptions')
    payments = db.relationship('SubscriptionPayment', back_populates='subscription')
    
    def get_features(self):
        """Get combined features from plan and any custom perks."""
        features = self.plan.default_features.copy() if self.plan.default_features else []
        if self.custom_perks:
            features.extend([p for p in self.custom_perks if p not in features])
        return features
    
    def to_dict(self):
        """Convert subscription to dictionary with all relevant data."""
        return {
            'id': self.id,
            'plan_id': self.plan_id,
            'plan_name': self.plan.name if self.plan else None,
            'tier': self.plan.tier if self.plan else None,
            'price': float(self.plan.price) if self.plan else 0.0,
            'status': self.status,
            'current_period_start': self.current_period_start.isoformat() if self.current_period_start else None,
            'current_period_end': self.current_period_end.isoformat() if self.current_period_end else None,
            'cancel_at_period_end': self.cancel_at_period_end,
            'profit_share_accepted': self.profit_share_accepted,
            'profit_share_percent': float(self.profit_share_percent) if self.profit_share_percent else 0.0,
            'features': self.get_features(),
            'custom_perks': self.custom_perks or [],
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class SubscriptionPayment(db.Model):
    """Represents a payment for a subscription or direct donation."""
    __tablename__ = 'subscription_payments'
    
    TYPE_SUBSCRIPTION = 'subscription'
    TYPE_DONATION = 'donation'
    
    id = db.Column(db.Integer, primary_key=True)
    payment_type = db.Column(db.String(20), default=TYPE_SUBSCRIPTION)  # subscription or donation
    subscription_id = db.Column(db.Integer, db.ForeignKey('user_subscriptions.id', ondelete='SET NULL'), nullable=True)
    streamer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Who receives the payment
    donor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Who made the payment
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    admin_share = db.Column(db.Numeric(10, 2), default=0)  # 0 for donations, 10% for subscriptions
    creator_share = db.Column(db.Numeric(10, 2), nullable=False)
    currency = db.Column(db.String(3), default='USD')
    stripe_payment_intent_id = db.Column(db.String(100))
    status = db.Column(db.String(20), default='pending')  # pending, succeeded, failed, etc.
    message = db.Column(db.Text, nullable=True)  # Optional message from donor
    is_anonymous = db.Column(db.Boolean, default=False)  # For donations
    payment_date = db.Column(db.DateTime, default=datetime.utcnow)
    payout_date = db.Column(db.DateTime)
    
    # Relationships
    subscription = db.relationship('UserSubscription', back_populates='payments')
    streamer = db.relationship('User', foreign_keys=[streamer_id], backref='earnings')
    donor = db.relationship('User', foreign_keys=[donor_id], backref='donations')
    
    def to_dict(self):
        """Convert payment to dictionary."""
        return {
            'id': self.id,
            'type': self.payment_type,
            'amount': float(self.amount) if self.amount else 0.0,
            'currency': self.currency,
            'status': self.status,
            'is_anonymous': self.is_anonymous,
            'message': self.message,
            'payment_date': self.payment_date.isoformat() if self.payment_date else None,
            'payout_date': self.payout_date.isoformat() if self.payout_date else None,
            'streamer_id': self.streamer_id,
            'donor': None if self.is_anonymous or not self.donor else {
                'id': self.donor.id,
                'username': self.donor.username,
                'avatar_url': self.donor.avatar_url
            },
            'subscription': None if not self.subscription else {
                'id': self.subscription.id,
                'plan_name': self.subscription.plan.name if self.subscription.plan else None
            }
        }

# Add relationships to User model
try:
    from app.models.user import User
    User.subscriptions = db.relationship('UserSubscription', back_populates='user')
except ImportError:
    pass
