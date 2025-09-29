import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useSnackbar } from 'notistack';
import { loadStripe } from '@stripe/stripe-js';
import { Elements } from '@stripe/react-stripe-js';
import {
  Container,
  Box,
  Typography,
  CircularProgress,
  Button,
  Paper,
  Avatar,
  Divider,
  Grid,
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import DonationForm from '../components/donations/DonationForm';
import { getStreamerProfile } from '../services/userService';

// Initialize Stripe with your publishable key
const stripePromise = loadStripe(process.env.REACT_APP_STRIPE_PUBLIC_KEY);

const DonationPage = () => {
  const { username } = useParams();
  const navigate = useNavigate();
  const { enqueueSnackbar } = useSnackbar();
  const [streamer, setStreamer] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchStreamerData = async () => {
      try {
        setLoading(true);
        const data = await getStreamerProfile(username);
        setStreamer(data);
      } catch (err) {
        console.error('Error fetching streamer data:', err);
        setError('Streamer not found');
        enqueueSnackbar('Could not find this streamer', { variant: 'error' });
      } finally {
        setLoading(false);
      }
    };

    if (username) {
      fetchStreamerData();
    }
  }, [username, enqueueSnackbar]);

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" my={4}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Container maxWidth="md" sx={{ py: 4, textAlign: 'center' }}>
        <Typography variant="h5" color="error" gutterBottom>
          {error}
        </Typography>
        <Button 
          variant="contained" 
          color="primary" 
          onClick={() => navigate('/')}
          sx={{ mt: 2 }}
        >
          Go to Home
        </Button>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      <Button
        startIcon={<ArrowBackIcon />}
        onClick={() => navigate(-1)}
        sx={{ mb: 2 }}
      >
        Back
      </Button>

      <Paper elevation={0} sx={{ p: 4, mb: 4, borderRadius: 2 }}>
        <Grid container spacing={4} alignItems="center">
          <Grid item xs={12} md={3} display="flex" justifyContent="center">
            <Avatar
              src={streamer?.avatar_url}
              alt={streamer?.username}
              sx={{
                width: 150,
                height: 150,
                border: '4px solid',
                borderColor: 'primary.main',
              }}
            />
          </Grid>
          <Grid item xs={12} md={9}>
            <Typography variant="h3" component="h1" gutterBottom>
              Support {streamer?.username}
            </Typography>
            <Typography variant="body1" paragraph>
              {streamer?.bio || 'Show your support with a donation!'}
            </Typography>
            <Box display="flex" gap={2} flexWrap="wrap" mt={2}>
              <Button 
                variant="contained" 
                color="primary"
                href={`/streamer/${streamer?.username}`}
              >
                View Channel
              </Button>
              <Button 
                variant="outlined" 
                color="primary"
                href={`/subscribe/${streamer?.username}`}
              >
                Subscribe
              </Button>
            </Box>
          </Grid>
        </Grid>
      </Paper>

      <Elements stripe={stripePromise}>
        <DonationForm streamer={streamer} />
      </Elements>

      <Paper elevation={0} sx={{ p: 3, mt: 4, borderRadius: 2, bgcolor: 'background.paper' }}>
        <Typography variant="h6" gutterBottom>
          About Donations
        </Typography>
        <Typography variant="body2" color="textSecondary" paragraph>
          Your donation goes directly to {streamer?.username || 'the streamer'} to support their content creation. 
          All transactions are secure and processed by Stripe. You'll receive a receipt via email for your records.
        </Typography>
        <Typography variant="caption" color="textSecondary">
          By making a donation, you agree to our Terms of Service and Privacy Policy. 
          All donations are final and non-refundable.
        </Typography>
      </Paper>
    </Container>
  );
};

export default DonationPage;
