import React, { useState, useEffect } from 'react';
import { 
  Box, 
  Typography, 
  TextField, 
  Button, 
  Card, 
  CardContent, 
  FormControl, 
  InputAdornment, 
  FormControlLabel, 
  Checkbox, 
  Divider, 
  CircularProgress,
  Alert,
  Paper,
  Grid,
  IconButton
} from '@mui/material';
import { useStripe, useElements, CardElement } from '@stripe/react-stripe-js';
import { useSnackbar } from 'notistack';
import { useParams } from 'react-router-dom';
import { useTheme } from '@mui/material/styles';
import FavoriteIcon from '@mui/icons-material/Favorite';
import api from '../../services/api';

const CARD_ELEMENT_OPTIONS = {
  style: {
    base: {
      color: "#32325d",
      fontFamily: '"Helvetica Neue", Helvetica, sans-serif',
      fontSmoothing: "antialiased",
      fontSize: "16px",
      "::placeholder": {
        color: "#aab7c4",
      },
    },
    invalid: {
      color: "#fa755a",
      iconColor: "#fa755a",
    },
  },
};

const presetAmounts = [5, 10, 25, 50, 100];

const DonationForm = ({ streamer }) => {
  const stripe = useStripe();
  const elements = useElements();
  const theme = useTheme();
  const { enqueueSnackbar } = useSnackbar();
  const { username } = useParams();
  
  const [amount, setAmount] = useState('');
  const [customAmount, setCustomAmount] = useState('');
  const [message, setMessage] = useState('');
  const [isAnonymous, setIsAnonymous] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [recentDonations, setRecentDonations] = useState([]);
  const [isProcessing, setIsProcessing] = useState(false);

  useEffect(() => {
    const fetchRecentDonations = async () => {
      try {
        const response = await api.get(`/api/donations/streamer/${streamer?.id}?limit=5`);
        setRecentDonations(response.data.donations || []);
      } catch (err) {
        console.error('Error fetching recent donations:', err);
      }
    };

    if (streamer?.id) {
      fetchRecentDonations();
    }
  }, [streamer]);

  const handleAmountSelect = (selectedAmount) => {
    setAmount(selectedAmount.toString());
    setCustomAmount('');
  };

  const handleCustomAmountChange = (e) => {
    const value = e.target.value.replace(/\D/g, '');
    setCustomAmount(value);
    if (value) {
      setAmount('');
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    const donationAmount = customAmount || amount;
    if (!donationAmount || parseFloat(donationAmount) < 1) {
      setError('Please enter a valid donation amount (minimum $1)');
      return;
    }
    
    if (!stripe || !elements) {
      // Stripe.js has not yet loaded
      return;
    }
    
    setIsProcessing(true);
    setError(null);
    
    try {
      // 1. Create payment intent on the server
      const { data } = await api.post('/api/donations/create-payment-intent', {
        streamer_id: streamer.id,
        amount: parseFloat(donationAmount),
        message: message.trim(),
        is_anonymous: isAnonymous
      });
      
      // 2. Confirm the card payment
      const { error: stripeError, paymentIntent } = await stripe.confirmCardPayment(
        data.clientSecret,
        {
          payment_method: {
            card: elements.getElement(CardElement),
            billing_details: {
              name: isAnonymous ? 'Anonymous Donor' : 'Donor',
            },
          },
        }
      );
      
      if (stripeError) {
        throw new Error(stripeError.message || 'Payment failed');
      }
      
      if (paymentIntent.status === 'succeeded') {
        // Success! Add the new donation to recent donations
        setRecentDonations(prev => [{
          amount: parseFloat(donationAmount),
          message: message.trim(),
          is_anonymous: isAnonymous,
          timestamp: new Date().toISOString(),
          donor: isAnonymous ? null : { username: 'You' }
        }, ...prev].slice(0, 5));
        
        // Reset form
        setAmount('');
        setCustomAmount('');
        setMessage('');
        
        enqueueSnackbar('Donation successful! Thank you for your support!', { 
          variant: 'success',
          autoHideDuration: 5000,
        });
      }
      
    } catch (err) {
      console.error('Donation error:', err);
      setError(err.message || 'An error occurred while processing your donation');
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <Box>
      <Typography variant="h5" component="h2" gutterBottom>
        Support {streamer?.username || 'this streamer'}
      </Typography>
      
      <Grid container spacing={3}>
        <Grid item xs={12} md={8}>
          <Card variant="outlined">
            <CardContent>
              <form onSubmit={handleSubmit}>
                <Box mb={3}>
                  <Typography variant="subtitle1" gutterBottom>
                    Select an amount (USD)
                  </Typography>
                  
                  <Box display="flex" flexWrap="wrap" gap={1} mb={2}>
                    {presetAmounts.map((amt) => (
                      <Button
                        key={amt}
                        variant={amount === amt.toString() ? 'contained' : 'outlined'}
                        color="primary"
                        onClick={() => handleAmountSelect(amt)}
                        sx={{
                          minWidth: '80px',
                          borderRadius: '20px',
                          textTransform: 'none',
                          fontWeight: amount === amt.toString() ? 'bold' : 'normal',
                        }}
                      >
                        ${amt}
                      </Button>
                    ))}
                  </Box>
                  
                  <TextField
                    fullWidth
                    variant="outlined"
                    placeholder="Custom amount"
                    value={customAmount}
                    onChange={handleCustomAmountChange}
                    InputProps={{
                      startAdornment: (
                        <InputAdornment position="start">$</InputAdornment>
                      ),
                    }}
                    sx={{
                      maxWidth: '200px',
                      '& .MuiOutlinedInput-root': {
                        borderRadius: '20px',
                      },
                    }}
                  />
                </Box>
                
                <Box mb={3}>
                  <Typography variant="subtitle1" gutterBottom>
                    Add a message (optional)
                  </Typography>
                  <TextField
                    fullWidth
                    variant="outlined"
                    placeholder={`Say something nice to ${streamer?.username || 'the streamer'}...`}
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                    multiline
                    rows={3}
                    inputProps={{ maxLength: 200 }}
                  />
                  <Typography 
                    variant="caption" 
                    color="textSecondary"
                    sx={{ display: 'block', textAlign: 'right', mt: 0.5 }}
                  >
                    {message.length}/200
                  </Typography>
                </Box>
                
                <Box mb={3}>
                  <Typography variant="subtitle1" gutterBottom>
                    Payment Information
                  </Typography>
                  <Paper 
                    variant="outlined" 
                    sx={{ 
                      p: 2, 
                      backgroundColor: theme.palette.background.paper,
                      borderRadius: 1,
                    }}
                  >
                    <CardElement options={CARD_ELEMENT_OPTIONS} />
                  </Paper>
                </Box>
                
                <Box mb={3}>
                  <FormControlLabel
                    control={
                      <Checkbox 
                        checked={isAnonymous} 
                        onChange={(e) => setIsAnonymous(e.target.checked)}
                        color="primary"
                      />
                    }
                    label="Make this donation anonymous"
                  />
                </Box>
                
                {error && (
                  <Alert severity="error" sx={{ mb: 2 }}>
                    {error}
                  </Alert>
                )}
                
                <Button
                  fullWidth
                  variant="contained"
                  color="primary"
                  size="large"
                  type="submit"
                  disabled={isProcessing || (!amount && !customAmount)}
                  startIcon={
                    isProcessing ? (
                      <CircularProgress size={20} color="inherit" />
                    ) : (
                      <FavoriteIcon />
                    )
                  }
                  sx={{
                    py: 1.5,
                    borderRadius: '50px',
                    fontSize: '1.1rem',
                    textTransform: 'none',
                    fontWeight: 'bold',
                    background: `linear-gradient(45deg, ${theme.palette.primary.main} 30%, ${theme.palette.secondary.main} 90%)`,
                    '&:hover': {
                      transform: 'translateY(-2px)',
                      boxShadow: 3,
                    },
                    transition: 'all 0.3s ease',
                  }}
                >
                  {isProcessing 
                    ? 'Processing...' 
                    : `Donate $${customAmount || amount || '0'} to ${streamer?.username || 'streamer'}`}
                </Button>
                
                <Typography 
                  variant="caption" 
                  color="textSecondary"
                  display="block"
                  textAlign="center"
                  mt={1}
                >
                  Secure payment processed by Stripe
                </Typography>
              </form>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} md={4}>
          <Card variant="outlined">
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Recent Supporters
              </Typography>
              
              {recentDonations.length > 0 ? (
                <List disablePadding>
                  {recentDonations.map((donation, index) => (
                    <React.Fragment key={index}>
                      <ListItem disableGutters>
                        <Box width="100%" display="flex" justifyContent="space-between" alignItems="center">
                          <Box display="flex" alignItems="center">
                            <FavoriteIcon 
                              color="error" 
                              fontSize="small" 
                              sx={{ mr: 1, opacity: 0.8 }} 
                            />
                            <Typography variant="body2">
                              {donation.is_anonymous 
                                ? 'Anonymous' 
                                : donation.donor?.username || 'Someone'}
                            </Typography>
                          </Box>
                          <Typography variant="subtitle2" fontWeight="bold">
                            ${donation.amount.toFixed(2)}
                          </Typography>
                        </Box>
                      </ListItem>
                      {donation.message && (
                        <Typography 
                          variant="body2" 
                          color="textSecondary" 
                          sx={{
                            pl: 4,
                            fontStyle: 'italic',
                            whiteSpace: 'nowrap',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            maxWidth: '100%',
                          }}
                          title={donation.message}
                        >
                          "{donation.message}"
                        </Typography>
                      )}
                      {index < recentDonations.length - 1 && <Divider sx={{ my: 1 }} />}
                    </React.Fragment>
                  ))}
                </List>
              ) : (
                <Typography variant="body2" color="textSecondary">
                  No recent donations. Be the first to support {streamer?.username || 'this streamer'}!
                </Typography>
              )}
              
              <Divider sx={{ my: 2 }} />
              
              <Box>
                <Typography variant="body2" color="textSecondary" paragraph>
                  All donations go directly to {streamer?.username || 'the streamer'} to support their content creation.
                </Typography>
                <Typography variant="caption" color="textSecondary">
                  By donating, you agree to our Terms of Service and Privacy Policy.
                </Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default DonationForm;
