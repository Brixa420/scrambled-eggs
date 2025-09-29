import React, { useState, useEffect } from 'react';
import { 
  Box, 
  Typography, 
  Card, 
  CardContent, 
  Button, 
  Divider, 
  List, 
  ListItem, 
  ListItemIcon, 
  ListItemText, 
  CircularProgress, 
  Alert,
  Switch,
  FormGroup,
  FormControlLabel,
  Paper,
  Chip
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import { useSnackbar } from 'notistack';
import api from '../../services/api';

const SubscriptionManagement = () => {
  const [subscription, setSubscription] = useState(null);
  const [loading, setLoading] = useState(true);
  const [updating, setUpdating] = useState(false);
  const [error, setError] = useState(null);
  const [selectedPerks, setSelectedPerks] = useState([]);
  const { enqueueSnackbar } = useSnackbar();

  useEffect(() => {
    const fetchSubscription = async () => {
      try {
        const response = await api.get('/api/subscriptions/my-subscription');
        setSubscription(response.data.subscription);
        setSelectedPerks(response.data.subscription?.custom_perks || []);
        setLoading(false);
      } catch (err) {
        console.error('Error fetching subscription:', err);
        setError('Failed to load subscription details');
        setLoading(false);
      }
    };

    fetchSubscription();
  }, []);

  const handlePerkToggle = (perk) => {
    setSelectedPerks(prev => 
      prev.includes(perk)
        ? prev.filter(p => p !== perk)
        : [...prev, perk]
    );
  };

  const handleUpdatePerks = async () => {
    if (!subscription) return;
    
    setUpdating(true);
    
    try {
      await api.put(`/api/subscriptions/${subscription.id}/update-perks`, {
        custom_perks: selectedPerks
      });
      
      setSubscription(prev => ({
        ...prev,
        custom_perks: [...selectedPerks]
      }));
      
      enqueueSnackbar('Subscription perks updated successfully', { variant: 'success' });
    } catch (err) {
      console.error('Error updating perks:', err);
      enqueueSnackbar('Failed to update subscription perks', { variant: 'error' });
    } finally {
      setUpdating(false);
    }
  };

  const handleCancelSubscription = async () => {
    if (!subscription || !window.confirm('Are you sure you want to cancel your subscription?')) {
      return;
    }
    
    try {
      await api.delete(`/api/subscriptions/${subscription.id}`);
      setSubscription(prev => ({
        ...prev,
        status: 'canceled',
        current_period_end: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days from now
      }));
      
      enqueueSnackbar('Subscription cancelled successfully', { variant: 'success' });
    } catch (err) {
      console.error('Error cancelling subscription:', err);
      enqueueSnackbar('Failed to cancel subscription', { variant: 'error' });
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

  if (!subscription) {
    return (
      <Box my={4} textAlign="center">
        <Typography variant="h6" gutterBottom>
          No active subscription found
        </Typography>
        <Button 
          variant="contained" 
          color="primary" 
          href="/subscribe"
        >
          Subscribe Now
        </Button>
      </Box>
    );
  }

  const isActive = subscription.status === 'active';
  const isElite = subscription.plan?.tier === 'elite';
  const currentPeriodEnd = new Date(subscription.current_period_end).toLocaleDateString();

  return (
    <Box my={4}>
      <Typography variant="h4" component="h2" gutterBottom>
        Your Subscription
      </Typography>
      
      <Card variant="outlined" sx={{ mb: 4 }}>
        <CardContent>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
            <Box>
              <Typography variant="h5" component="div">
                {subscription.plan?.name || 'Unknown Plan'}
              </Typography>
              <Typography variant="body2" color="textSecondary">
                {isActive 
                  ? `Renews on ${currentPeriodEnd}` 
                  : `Expires on ${currentPeriodEnd}`}
              </Typography>
            </Box>
            <Chip 
              label={subscription.status.toUpperCase()} 
              color={isActive ? 'success' : 'default'}
              variant="outlined"
            />
          </Box>
          
          <Divider sx={{ my: 2 }} />
          
          <Typography variant="subtitle1" gutterBottom>
            Included Features:
          </Typography>
          
          <List dense>
            {subscription.plan?.default_features?.map((feature, index) => (
              <ListItem key={`feature-${index}`} disableGutters>
                <ListItemIcon sx={{ minWidth: 36 }}>
                  <CheckCircleIcon color="primary" fontSize="small" />
                </ListItemIcon>
                <ListItemText primary={feature} />
              </ListItem>
            ))}
          </List>
          
          {isElite && (
            <Box mt={3}>
              <Typography variant="subtitle1" gutterBottom>
                Customize Your Elite Perks:
              </Typography>
              <Typography variant="body2" color="textSecondary" paragraph>
                Select the perks you want to offer to your subscribers.
              </Typography>
              
              <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
                <FormGroup>
                  {subscription.plan?.customization_options?.map((perk) => (
                    <FormControlLabel
                      key={perk}
                      control={
                        <Switch
                          checked={selectedPerks.includes(perk)}
                          onChange={() => handlePerkToggle(perk)}
                          color="primary"
                        />
                      }
                      label={perk}
                    />
                  ))}
                </FormGroup>
                
                <Box mt={2} display="flex" justifyContent="flex-end">
                  <Button
                    variant="contained"
                    color="primary"
                    onClick={handleUpdatePerks}
                    disabled={updating || !isActive}
                    startIcon={updating ? <CircularProgress size={20} /> : null}
                  >
                    {updating ? 'Updating...' : 'Save Changes'}
                  </Button>
                </Box>
              </Paper>
            </Box>
          )}
          
          <Divider sx={{ my: 2 }} />
          
          <Box display="flex" justifyContent="space-between" alignItems="center">
            <Typography variant="body2" color="textSecondary">
              {isActive 
                ? 'Need to make changes?'
                : 'Your subscription will remain active until the end of the billing period.'}
            </Typography>
            
            {isActive ? (
              <Button 
                color="error" 
                variant="outlined"
                onClick={handleCancelSubscription}
                disabled={updating}
              >
                Cancel Subscription
              </Button>
            ) : (
              <Button 
                variant="contained" 
                color="primary"
                href="/subscribe"
              >
                Resubscribe
              </Button>
            )}
          </Box>
        </CardContent>
      </Card>
      
      {subscription.custom_perks?.length > 0 && (
        <Box mb={4}>
          <Typography variant="h6" gutterBottom>
            Your Active Perks
          </Typography>
          <Box display="flex" flexWrap="wrap" gap={1}>
            {subscription.custom_perks.map((perk, index) => (
              <Chip 
                key={`active-perk-${index}`}
                label={perk}
                color="primary"
                variant="outlined"
              />
            ))}
          </Box>
        </Box>
      )}
    </Box>
  );
};

export default SubscriptionManagement;
