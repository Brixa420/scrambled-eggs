// Subscription tier configuration
export const SUBSCRIPTION_TIERS = {
  BASIC: 'basic',
  PREMIUM: 'premium',
  ELITE: 'elite'
};

// Default subscription features by tier
export const DEFAULT_FEATURES = {
  [SUBSCRIPTION_TIERS.BASIC]: [
    'Ad-free viewing',
    'Custom emojis',
    'Access to subscriber-only chat',
    'Subscriber badge'
  ],
  [SUBSCRIPTION_TIERS.PREMIUM]: [
    'All Basic tier features',
    'Exclusive subscriber streams',
    'Custom chat colors',
    'Priority customer support',
    'Early access to new features'
  ],
  [SUBSCRIPTION_TIERS.ELITE]: [
    'All Premium tier features',
    'Exclusive merchandise discounts',
    'VIP status in chat',
    'Exclusive content access'
  ]
};

// Customization options for Elite tier
export const ELITE_CUSTOMIZATION_OPTIONS = [
  'Personalized thank you video',
  'Monthly 1-on-1 stream (30 minutes)',
  'Behind-the-scenes content',
  'Exclusive merchandise package',
  'Voting power on stream content and schedule'
];

// Pricing configuration
export const PRICING = {
  [SUBSCRIPTION_TIERS.BASIC]: 4.99,
  [SUBSCRIPTION_TIERS.PREMIUM]: 9.99,
  [SUBSCRIPTION_TIERS.ELITE]: 24.99
};

// Stripe configuration
export const STRIPE_CONFIG = {
  // These are the default styles for Stripe Elements
  elementStyles: {
    base: {
      color: '#32325d',
      fontFamily: '"Helvetica Neue", Helvetica, sans-serif',
      fontSmoothing: 'antialiased',
      fontSize: '16px',
      '::placeholder': {
        color: '#aab7c4'
      }
    },
    invalid: {
      color: '#fa755a',
      iconColor: '#fa755a'
    }
  },
  // Element options
  elementOptions: {
    hidePostalCode: false,
    style: {
      base: {
        fontSize: '16px',
        color: '#424770',
        '::placeholder': {
          color: '#aab7c4'
        }
      },
      invalid: {
        color: '#9e2146'
      }
    }
  }
};

// Donation configuration
export const DONATION_CONFIG = {
  minAmount: 1, // Minimum donation amount in USD
  maxAmount: 1000, // Maximum donation amount in USD
  presetAmounts: [5, 10, 25, 50, 100], // Common donation amounts
  defaultMessage: 'Thanks for the amazing content!', // Default donation message
  feePercentage: 2.9, // Stripe fee percentage
  feeFixed: 0.30 // Stripe fixed fee per transaction
};

// Subscription statuses
export const SUBSCRIPTION_STATUS = {
  ACTIVE: 'active',
  CANCELED: 'canceled',
  PAST_DUE: 'past_due',
  UNPAID: 'unpaid',
  INCOMPLETE: 'incomplete',
  INCOMPLETE_EXPIRED: 'incomplete_expired',
  TRIALING: 'trialing',
  ALL: ['active', 'canceled', 'past_due', 'unpaid', 'incomplete', 'incomplete_expired', 'trialing']
};

// Helper functions
export const formatCurrency = (amount, currency = 'USD') => {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: currency,
    minimumFractionDigits: 2
  }).format(amount);
};

export const getTierName = (tier) => {
  return tier.charAt(0).toUpperCase() + tier.slice(1);
};

export const getSubscriptionFeatures = (tier, customPerks = []) => {
  const features = [...DEFAULT_FEATURES[tier] || []];
  
  // Add custom perks for Elite tier
  if (tier === SUBSCRIPTION_TIERS.ELITE && customPerks.length > 0) {
    features.push(...customPerks);
  }
  
  return features;
};
