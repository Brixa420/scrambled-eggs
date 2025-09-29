import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useSnackbar } from 'notistack';
import { loadStripe } from '@stripe/stripe-js';
import {
  Container,
  Typography,
  Box,
  Button,
  CircularProgress,
  Paper,
  Tabs,
  Tab,
} from '@mui/material';
import { Elements } from '@stripe/react-stripe-js';
import SubscriptionPlans from '../components/subscriptions/SubscriptionPlans';
import SubscriptionManagement from '../components/subscriptions/SubscriptionManagement';
import { getMySubscription } from '../services/subscriptionService';

// Initialize Stripe with your publishable key
const stripePromise = loadStripe(process.env.REACT_APP_STRIPE_PUBLIC_KEY);

const SubscriptionPage = () => {
  const navigate = useNavigate();
  const { enqueueSnackbar } = useSnackbar();
  const [activeTab, setActiveTab] = useState(0);
  const [hasSubscription, setHasSubscription] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const checkSubscription = async () => {
      try {
        const subscription = await getMySubscription();
        setHasSubscription(!!subscription);
        if (subscription) {
          setActiveTab(1); // Switch to management tab if user has a subscription
        }
      } catch (error) {
        console.error('Error checking subscription:', error);
        enqueueSnackbar('Error loading subscription information', { variant: 'error' });
      } finally {
        setLoading(false);
      }
    };

    checkSubscription();
  }, [enqueueSnackbar]);

  const handleTabChange = (event, newValue) => {
    setActiveTab(newValue);
  };

  const handleSubscriptionSuccess = () => {
    setHasSubscription(true);
    setActiveTab(1); // Switch to management tab after successful subscription
    enqueueSnackbar('Subscription successful!', { variant: 'success' });
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" my={4}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      <Box mb={4} textAlign="center">
        <Typography variant="h3" component="h1" gutterBottom>
          Premium Subscriptions
        </Typography>
        <Typography variant="subtitle1" color="textSecondary">
          Unlock exclusive features and support your favorite streamers
        </Typography>
      </Box>

      <Paper sx={{ mb: 4 }}>
        <Tabs
          value={activeTab}
          onChange={handleTabChange}
          indicatorColor="primary"
          textColor="primary"
          variant="fullWidth"
        >
          <Tab label="Subscribe" disabled={loading} />
          <Tab 
            label="My Subscription" 
            disabled={!hasSubscription} 
            sx={{ display: hasSubscription ? 'block' : 'none' }} 
          />
        </Tabs>

        <Box p={3}>
          {activeTab === 0 && (
            <Elements stripe={stripePromise}>
              <SubscriptionPlans onSubscribeSuccess={handleSubscriptionSuccess} />
            </Elements>
          )}
          
          {activeTab === 1 && hasSubscription && (
            <SubscriptionManagement />
          )}
        </Box>
      </Paper>

      <Box mt={4} textAlign="center">
        <Typography variant="body2" color="textSecondary" paragraph>
          Subscriptions automatically renew each month. You can cancel at any time.
        </Typography>
        <Button 
          variant="outlined" 
          color="primary"
          onClick={() => navigate('/support')}
        >
          Need Help?
        </Button>
      </Box>
    </Container>
  );
};

export default SubscriptionPage;
