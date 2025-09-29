import React, { useState, useEffect } from 'react';
import {
  Box,
  Button,
  TextField,
  Typography,
  Paper,
  Alert,
  CircularProgress,
  Card,
  CardContent,
  Divider
} from '@mui/material';
import { Lock as LockIcon, Warning as WarningIcon } from '@mui/icons-material';

const BanAppealForm = ({ banReason, onSubmitted }) => {
  const [appealText, setAppealText] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [isSubmitted, setIsSubmitted] = useState(false);
  const [result, setResult] = useState(null);
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!appealText.trim()) {
      setError('Please explain why you believe the ban should be lifted.');
      return;
    }
    
    setIsSubmitting(true);
    setError(null);
    
    try {
      const response = await fetch('/api/ban-appeals/appeals', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({
          ban_reason: banReason,
          appeal_text: appealText
        })
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.detail || 'Failed to submit appeal');
      }
      
      setResult(data);
      setIsSubmitted(true);
      
      if (onSubmitted) {
        onSubmitted(data);
      }
      
    } catch (err) {
      console.error('Error submitting ban appeal:', err);
      setError(err.message || 'Failed to submit appeal. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };
  
  if (isSubmitted) {
    return (
      <Box textAlign="center" p={4}>
        <Box mb={3}>
          {result.appeal_status === 'approved' ? (
            <>
              <LockIcon color="success" sx={{ fontSize: 64, mb: 2 }} />
              <Typography variant="h5" gutterBottom>
                Ban Appeal Approved!
              </Typography>
              <Typography color="text.secondary">
                Your account has been reinstated. Welcome back!
              </Typography>
            </>
          ) : result.appeal_status === 'rejected' ? (
            <>
              <WarningIcon color="error" sx={{ fontSize: 64, mb: 2 }} />
              <Typography variant="h5" gutterBottom>
                Appeal Denied
              </Typography>
              <Typography color="text.secondary">
                Your ban appeal has been reviewed and denied.
              </Typography>
            </>
          ) : (
            <>
              <LockIcon color="info" sx={{ fontSize: 64, mb: 2 }} />
              <Typography variant="h5" gutterBottom>
                Appeal Submitted
              </Typography>
              <Typography color="text.secondary" paragraph>
                Your appeal is being processed. You will be notified of the decision.
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Status: <strong>{result.appeal_status.replace('_', ' ').toUpperCase()}</strong>
              </Typography>
            </>
          )}
        </Box>
        <Button 
          variant="contained" 
          color="primary" 
          onClick={() => window.location.reload()}
        >
          Continue
        </Button>
      </Box>
    );
  }
  
  return (
    <Paper elevation={3} sx={{ p: 3, maxWidth: 600, mx: 'auto' }}>
      <Box textAlign="center" mb={3}>
        <LockIcon color="error" sx={{ fontSize: 48, mb: 1 }} />
        <Typography variant="h5" gutterBottom>
          Submit Ban Appeal
        </Typography>
        <Typography color="text.secondary" paragraph>
          Please explain why you believe your ban should be lifted.
        </Typography>
        
        {banReason && (
          <Alert 
            severity="warning" 
            sx={{ 
              textAlign: 'left',
              mb: 3,
              '& .MuiAlert-message': { width: '100%' }
            }}
          >
            <Typography variant="subtitle2" gutterBottom>
              Ban Reason:
            </Typography>
            {banReason}
          </Alert>
        )}
      </Box>
      
      <form onSubmit={handleSubmit}>
        <TextField
          fullWidth
          multiline
          rows={6}
          variant="outlined"
          label="Your Appeal"
          placeholder="Please explain why you believe your ban should be lifted..."
          value={appealText}
          onChange={(e) => setAppealText(e.target.value)}
          disabled={isSubmitting}
          sx={{ mb: 2 }}
          required
        />
        
        <Box sx={{ mb: 3 }}>
          <Typography variant="body2" color="text.secondary">
            Your appeal will be reviewed by our moderation team. Please be honest and provide as much detail as possible.
          </Typography>
        </Box>
        
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}
        
        <Button
          type="submit"
          variant="contained"
          color="primary"
          fullWidth
          size="large"
          disabled={isSubmitting}
        >
          {isSubmitting ? (
            <>
              <CircularProgress size={24} sx={{ mr: 1 }} />
              Submitting...
            </>
          ) : (
            'Submit Appeal'
          )}
        </Button>
      </form>
    </Paper>
  );
};

export default BanAppealForm;
