import React, { useState, useEffect } from 'react';
import { Box, Grid, Card, CardContent, Typography, Button, Divider, List, ListItem, ListItemIcon, ListItemText, CircularProgress, Alert } from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import { useSnackbar } from 'notistack';
import { loadStripe } from '@stripe/stripe-js';
import api from '../../services/api';

const stripePromise = loadStripe(process.env.REACT_APP_STRIPE_PUBLIC_KEY);

const SubscriptionPlans = ({ onSubscribe }) => {
  const [plans, setPlans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedPlan, setSelectedPlan] = useState(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const { enqueueSnackbar } = useSnackbar();

  useEffect(() => {
    const fetchPlans = async () => {
      try {
        const response = await api.get('/api/subscriptions/plans');
        setPlans(response.data.plans);
        setLoading(false);
      } catch (err) {
        console.error('Error fetching plans:', err);
        setError('Failed to load subscription plans');
        setLoading(false);
      }
    };

    fetchPlans();
  }, []);

  const handleSubscribe = async (planId) => {
    if (!selectedPlan) return;
    
    setIsSubmitting(true);
    
    try {
      // 1. Create payment intent
      const { data } = await api.post('/api/subscriptions/create-payment-intent', {
        planId: selectedPlan
      });
      
      // 2. Redirect to Stripe Checkout
      const stripe = await stripePromise;
      const { error } = await stripe.redirectToCheckout({
        sessionId: data.sessionId
      });
      
      if (error) {
        throw error;
      }
      
    } catch (err) {
      console.error('Subscription error:', err);
      enqueueSnackbar('Failed to process subscription', { variant: 'error' });
      setIsSubmitting(false);
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" my={4}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box my={4}>
        <Alert severity="error">{error}</Alert>
      </Box>
    );
  }

  return (
    <Box my={4}>
      <Typography variant="h4" component="h2" gutterBottom align="center">
        Choose Your Plan
      </Typography>
      
      <Typography variant="subtitle1" color="textSecondary" align="center" paragraph>
        Select the plan that best fits your needs
      </Typography>
      
      <Grid container spacing={4} justifyContent="center" mt={2}>
        {plans.map((plan) => (
          <Grid item key={plan.id} xs={12} sm={6} md={4}>
            <Card 
              variant={selectedPlan === plan.id ? 'elevation' : 'outlined'}
              sx={{
                height: '100%',
                display: 'flex',
                flexDirection: 'column',
                borderColor: selectedPlan === plan.id ? 'primary.main' : 'divider',
                borderWidth: selectedPlan === plan.id ? 2 : 1,
                transition: 'all 0.3s ease',
                '&:hover': {
                  transform: 'translateY(-4px)',
                  boxShadow: 3,
                },
              }}
            >
              <CardContent sx={{ flexGrow: 1 }}>
                <Box textAlign="center" mb={2}>
                  <Typography variant="h5" component="h3" gutterBottom>
                    {plan.name}
                  </Typography>
                  <Typography variant="h4" component="div" color="primary" gutterBottom>
                    ${plan.price}/month
                  </Typography>
                  <Typography variant="body2" color="textSecondary" paragraph>
                    {plan.description}
                  </Typography>
                </Box>
                
                <Divider sx={{ my: 2 }} />
                
                <List dense disablePadding>
                  {plan.features.map((feature, index) => (
                    <ListItem key={index} disableGutters>
                      <ListItemIcon sx={{ minWidth: 36 }}>
                        <CheckCircleIcon color="primary" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={feature} />
                    </ListItem>
                  ))}
                </List>
                
                {plan.customization_options && plan.customization_options.length > 0 && (
                  <Box mt={2}>
                    <Typography variant="subtitle2" color="textSecondary" gutterBottom>
                      Customization Options:
                    </Typography>
                    <List dense disablePadding>
                      {plan.customization_options.map((option, index) => (
                        <ListItem key={`option-${index}`} disableGutters>
                          <ListItemIcon sx={{ minWidth: 36 }}>
                            <CheckCircleIcon color="primary" fontSize="small" />
                          </ListItemIcon>
                          <ListItemText primary={option} />
                        </ListItem>
                      ))}
                    </List>
                  </Box>
                )}
              </CardContent>
              
              <Box p={2}>
                <Button
                  fullWidth
                  variant={selectedPlan === plan.id ? 'contained' : 'outlined'}
                  color="primary"
                  size="large"
                  onClick={() => setSelectedPlan(plan.id)}
                  disabled={isSubmitting}
                >
                  {selectedPlan === plan.id ? 'Selected' : 'Select Plan'}
                </Button>
              </Box>
            </Card>
          </Grid>
        ))}
      </Grid>
      
      <Box mt={4} display="flex" justifyContent="center">
        <Button
          variant="contained"
          color="primary"
          size="large"
          disabled={!selectedPlan || isSubmitting}
          onClick={handleSubscribe}
          startIcon={isSubmitting ? <CircularProgress size={20} color="inherit" /> : null}
        >
          {isSubmitting ? 'Processing...' : 'Subscribe Now'}
        </Button>
      </Box>
    </Box>
  );
};

export default SubscriptionPlans;
