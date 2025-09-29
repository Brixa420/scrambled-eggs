import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import AgeVerification from './AgeVerification';
import {
  Box,
  Paper,
  Typography,
  Button,
  CircularProgress,
  Alert,
  useTheme
} from '@mui/material';
import { Lock as LockIcon } from '@mui/icons-material';

const ContentGuard = ({ 
  children, 
  requiredAge = 18,
  showVerification = true,
  onVerified = () => {}
}) => {
  const { currentUser } = useAuth();
  const [isVerified, setIsVerified] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [showVerificationModal, setShowVerificationModal] = useState(false);
  const theme = useTheme();

  // Check verification status when component mounts or user changes
  useEffect(() => {
    const checkVerification = async () => {
      if (!currentUser) {
        setIsLoading(false);
        return;
      }

      try {
        // Call your API to check if user is age verified
        const response = await fetch('/api/moderation/verification/status', {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`
          }
        });

        if (response.ok) {
          const data = await response.json();
          const verified = data.isVerified && 
                         data.verifiedAge >= requiredAge &&
                         (!data.verificationExpiry || new Date(data.verificationExpiry) > new Date());
          
          setIsVerified(verified);
          if (verified) {
            onVerified(data);
          }
        }
      } catch (error) {
        console.error('Error checking verification status:', error);
      } finally {
        setIsLoading(false);
      }
    };

    checkVerification();
  }, [currentUser, requiredAge, onVerified]);

  const handleVerificationSuccess = (result) => {
    setIsVerified(true);
    setShowVerificationModal(false);
    onVerified(result);
  };

  if (isLoading) {
    return (
      <Box display="flex" justifyContent="center" p={4}>
        <CircularProgress />
      </Box>
    );
  }

  if (!currentUser) {
    return (
      <Box textAlign="center" p={4}>
        <LockIcon fontSize="large" color="action" sx={{ fontSize: 64, mb: 2 }} />
        <Typography variant="h5" gutterBottom>
          Sign In Required
        </Typography>
        <Typography variant="body1" color="text.secondary" paragraph>
          You need to be signed in to view this content.
        </Typography>
        <Button 
          variant="contained" 
          color="primary"
          href="/login"
          sx={{ mt: 2 }}
        >
          Sign In
        </Button>
      </Box>
    );
  }

  if (!isVerified) {
    return (
      <>
        <Paper 
          elevation={0} 
          sx={{ 
            p: 4, 
            textAlign: 'center',
            borderRadius: 2,
            bgcolor: theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.02)'
          }}
        >
          <LockIcon fontSize="large" color="action" sx={{ fontSize: 64, mb: 2 }} />
          <Typography variant="h5" gutterBottom>
            Age-Restricted Content
          </Typography>
          <Typography variant="body1" color="text.secondary" paragraph>
            This content is for viewers {requiredAge} years of age or older.
          </Typography>
          <Typography variant="body2" color="text.secondary" paragraph>
            We use secure age verification to ensure compliance with legal requirements.
          </Typography>
          
          <Alert severity="info" sx={{ mb: 3, textAlign: 'left' }}>
            <Typography variant="subtitle2" gutterBottom>How it works:</Typography>
            <ul style={{ margin: 0, paddingLeft: '20px' }}>
              <li>Take a photo of your ID (we don't store your ID)</li>
              <li>Take a selfie to verify your identity</li>
              <li>Our AI verifies your age instantly</li>
            </ul>
          </Alert>
          
          {showVerification ? (
            <Button 
              variant="contained" 
              color="primary"
              size="large"
              onClick={() => setShowVerificationModal(true)}
              sx={{ mt: 1 }}
            >
              Verify My Age
            </Button>
          ) : (
            <Alert severity="warning" sx={{ mt: 2 }}>
              Age verification is required but currently unavailable. Please try again later.
            </Alert>
          )}
          
          <Typography variant="caption" display="block" sx={{ mt: 2, color: 'text.secondary' }}>
            Your privacy is important to us. We do not store your ID documents.
          </Typography>
        </Paper>
        
        {showVerification && (
          <AgeVerification
            open={showVerificationModal}
            onClose={() => setShowVerificationModal(false)}
            onVerified={handleVerificationSuccess}
            requiredAge={requiredAge}
          />
        )}
      </>
    );
  }

  // If user is verified, render the protected content
  return children;
};

export default ContentGuard;
