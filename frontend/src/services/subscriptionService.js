import api from './api';

export const getSubscriptionPlans = async () => {
  try {
    const response = await api.get('/api/subscriptions/plans');
    return response.data.plans;
  } catch (error) {
    console.error('Error fetching subscription plans:', error);
    throw error;
  }
};

export const getMySubscription = async () => {
  try {
    const response = await api.get('/api/subscriptions/my-subscription');
    return response.data.subscription;
  } catch (error) {
    if (error.response?.status === 404) {
      return null; // No active subscription
    }
    console.error('Error fetching subscription:', error);
    throw error;
  }
};

export const createSubscription = async (planId, paymentMethodId) => {
  try {
    const response = await api.post('/api/subscriptions/subscribe', {
      plan_id: planId,
      payment_method_id: paymentMethodId,
    });
    return response.data;
  } catch (error) {
    console.error('Error creating subscription:', error);
    throw error;
  }
};

export const updateSubscriptionPerks = async (subscriptionId, perks) => {
  try {
    const response = await api.put(`/api/subscriptions/${subscriptionId}/update-perks`, {
      custom_perks: perks,
    });
    return response.data;
  } catch (error) {
    console.error('Error updating subscription perks:', error);
    throw error;
  }
};

export const cancelSubscription = async (subscriptionId) => {
  try {
    await api.delete(`/api/subscriptions/${subscriptionId}`);
  } catch (error) {
    console.error('Error canceling subscription:', error);
    throw error;
  }
};

export const createDonation = async (streamerId, amount, paymentMethodId, message = '', isAnonymous = false) => {
  try {
    const response = await api.post('/api/donations', {
      streamer_id: streamerId,
      amount: parseFloat(amount),
      payment_method_id: paymentMethodId,
      message,
      is_anonymous: isAnonymous,
    });
    return response.data;
  } catch (error) {
    console.error('Error creating donation:', error);
    throw error;
  }
};

export const getStreamerDonations = async (streamerId, limit = 5) => {
  try {
    const response = await api.get(`/api/donations/streamer/${streamerId}?limit=${limit}`);
    return response.data.donations || [];
  } catch (error) {
    console.error('Error fetching streamer donations:', error);
    return [];
  }
};

export const createPaymentIntent = async (planId) => {
  try {
    const response = await api.post('/api/subscriptions/create-payment-intent', { planId });
    return response.data;
  } catch (error) {
    console.error('Error creating payment intent:', error);
    throw error;
  }
};

export const createDonationIntent = async (streamerId, amount) => {
  try {
    const response = await api.post('/api/donations/create-payment-intent', {
      streamer_id: streamerId,
      amount: parseFloat(amount),
    });
    return response.data;
  } catch (error) {
    console.error('Error creating donation intent:', error);
    throw error;
  }
};
