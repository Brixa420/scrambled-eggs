import React, { useState, useRef } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Typography,
  Box,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Paper,
  Avatar,
  CircularProgress,
  Alert,
  IconButton
} from '@mui/material';
import {
  CameraAlt as CameraIcon,
  CheckCircle as CheckCircleIcon,
  Close as CloseIcon,
  Warning as WarningIcon
} from '@mui/icons-material';

const STEPS = [
  'Verify Your Age',
  'Take a Photo of Your ID',
  'Take a Selfie',
  'Verification Complete'
];

const AgeVerification = ({ open, onClose, onVerified, requiredAge = 18 }) => {
  const [activeStep, setActiveStep] = useState(0);
  const [idImage, setIdImage] = useState(null);
  const [selfieImage, setSelfieImage] = useState(null);
  const [isVerifying, setIsVerifying] = useState(false);
  const [error, setError] = useState(null);
  const [verificationResult, setVerificationResult] = useState(null);
  
  const idInputRef = useRef(null);
  const selfieInputRef = useRef(null);
  
  const handleNext = () => {
    setActiveStep((prevStep) => prevStep + 1);
  };
  
  const handleBack = () => {
    setActiveStep((prevStep) => prevStep - 1);
  };
  
  const handleIdUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onloadend = () => {
        setIdImage(reader.result);
        handleNext();
      };
      reader.readAsDataURL(file);
    }
  };
  
  const handleSelfieUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onloadend = () => {
        setSelfieImage(reader.result);
        handleNext();
      };
      reader.readAsDataURL(file);
    }
  };
  
  const triggerFileInput = (ref) => {
    if (ref.current) {
      ref.current.click();
    }
  };
  
  const handleVerify = async () => {
    try {
      setIsVerifying(true);
      setError(null);
      
      // Convert base64 to blob for file upload
      const idBlob = await (await fetch(idImage)).blob();
      const selfieBlob = await (await fetch(selfieImage)).blob();
      
      const formData = new FormData();
      formData.append('document', idBlob, 'id.jpg');
      formData.append('selfie', selfieBlob, 'selfie.jpg');
      
      const response = await fetch('/api/moderation/verify-age', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: formData
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Verification failed');
      }
      
      const result = await response.json();
      setVerificationResult(result);
      
      if (result.verified && result.age >= requiredAge) {
        handleNext(); // Move to success step
        if (onVerified) onVerified(result);
      } else {
        setError(`You must be at least ${requiredAge} years old to access this content.`);
        setActiveStep(0); // Reset to first step
      }
      
    } catch (err) {
      console.error('Verification error:', err);
      setError(err.message || 'An error occurred during verification. Please try again.');
    } finally {
      setIsVerifying(false);
    }
  };
  
  const handleReset = () => {
    setIdImage(null);
    setSelfieImage(null);
    setVerificationResult(null);
    setError(null);
    setActiveStep(0);
  };
  
  const handleClose = () => {
    if (!isVerifying) {
      handleReset();
      onClose();
    }
  };
  
  const renderStepContent = (step) => {
    switch (step) {
      case 0:
        return (
          <Box sx={{ p: 2 }}>
            <Typography variant="body1" paragraph>
              To access age-restricted content, we need to verify that you are at least {requiredAge} years old.
            </Typography>
            <Typography variant="body2" color="text.secondary" paragraph>
              Your privacy is important to us. We use advanced AI to verify your age without storing your ID documents.
            </Typography>
            <Alert severity="info" sx={{ mb: 2 }}>
              You'll need a valid government-issued ID and a selfie for verification.
            </Alert>
          </Box>
        );
      
      case 1:
        return (
          <Box sx={{ p: 2, textAlign: 'center' }}>
            <input
              type="file"
              ref={idInputRef}
              onChange={handleIdUpload}
              accept="image/*"
              capture="environment"
              style={{ display: 'none' }}
            />
            
            <Typography variant="h6" gutterBottom>
              Take a photo of your ID
            </Typography>
            
            <Box
              sx={{
                border: '2px dashed',
                borderColor: 'divider',
                borderRadius: 2,
                p: 3,
                my: 2,
                cursor: 'pointer',
                '&:hover': {
                  borderColor: 'primary.main',
                  bgcolor: 'action.hover',
                },
              }}
              onClick={() => triggerFileInput(idInputRef)}
            >
              {idImage ? (
                <Box>
                  <img 
                    src={idImage} 
                    alt="ID preview" 
                    style={{ 
                      maxWidth: '100%', 
                      maxHeight: '300px',
                      borderRadius: '8px'
                    }} 
                  />
                  <Button 
                    variant="outlined" 
                    color="primary" 
                    sx={{ mt: 2 }}
                    onClick={(e) => {
                      e.stopPropagation();
                      triggerFileInput(idInputRef);
                    }}
                  >
                    Retake Photo
                  </Button>
                </Box>
              ) : (
                <Box sx={{ p: 3 }}>
                  <Avatar sx={{ width: 64, height: 64, mx: 'auto', mb: 2, bgcolor: 'action.selected' }}>
                    <CameraIcon fontSize="large" />
                  </Avatar>
                  <Typography>Tap to take a photo of your ID</Typography>
                  <Typography variant="caption" color="text.secondary">
                    Make sure all details are clearly visible
                  </Typography>
                </Box>
              )}
            </Box>
            
            <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
              We accept driver's license, passport, or national ID card
            </Typography>
          </Box>
        );
      
      case 2:
        return (
          <Box sx={{ p: 2, textAlign: 'center' }}>
            <input
              type="file"
              ref={selfieInputRef}
              onChange={handleSelfieUpload}
              accept="image/*"
              capture="user"
              style={{ display: 'none' }}
            />
            
            <Typography variant="h6" gutterBottom>
              Take a selfie
            </Typography>
            
            <Box
              sx={{
                border: '2px dashed',
                borderColor: 'divider',
                borderRadius: 2,
                p: 3,
                my: 2,
                cursor: 'pointer',
                '&:hover': {
                  borderColor: 'primary.main',
                  bgcolor: 'action.hover',
                },
              }}
              onClick={() => triggerFileInput(selfieInputRef)}
            >
              {selfieImage ? (
                <Box>
                  <img 
                    src={selfieImage} 
                    alt="Selfie preview" 
                    style={{ 
                      maxWidth: '100%', 
                      maxHeight: '300px',
                      borderRadius: '8px'
                    }} 
                  />
                  <Button 
                    variant="outlined" 
                    color="primary" 
                    sx={{ mt: 2 }}
                    onClick={(e) => {
                      e.stopPropagation();
                      triggerFileInput(selfieInputRef);
                    }}
                  >
                    Retake Selfie
                  </Button>
                </Box>
              ) : (
                <Box sx={{ p: 3 }}>
                  <Avatar sx={{ width: 64, height: 64, mx: 'auto', mb: 2, bgcolor: 'action.selected' }}>
                    <CameraIcon fontSize="large" />
                  </Avatar>
                  <Typography>Take a selfie to verify your identity</Typography>
                  <Typography variant="caption" color="text.secondary">
                    Make sure your face is clearly visible
                  </Typography>
                </Box>
              )}
            </Box>
            
            <Button
              variant="contained"
              color="primary"
              fullWidth
              size="large"
              onClick={handleVerify}
              disabled={!idImage || !selfieImage || isVerifying}
              startIcon={isVerifying ? <CircularProgress size={20} /> : null}
              sx={{ mt: 2 }}
            >
              {isVerifying ? 'Verifying...' : 'Verify My Age'}
            </Button>
            
            {error && (
              <Alert severity="error" sx={{ mt: 2 }}>
                {error}
              </Alert>
            )}
          </Box>
        );
      
      case 3:
        return (
          <Box sx={{ p: 4, textAlign: 'center' }}>
            <CheckCircleIcon 
              color="success" 
              sx={{ fontSize: 80, mb: 2 }} 
            />
            <Typography variant="h5" gutterBottom>
              Age Verified Successfully!
            </Typography>
            <Typography variant="body1" color="text.secondary" paragraph>
              Thank you for verifying your age. You can now access age-restricted content.
            </Typography>
            {verificationResult?.age && (
              <Typography variant="body2" sx={{ mt: 1 }}>
                Verified Age: <strong>{verificationResult.age} years old</strong>
              </Typography>
            )}
          </Box>
        );
      
      default:
        return null;
    }
  };
  
  const isLastStep = activeStep === STEPS.length - 1;
  
  return (
    <Dialog 
      open={open} 
      onClose={handleClose}
      maxWidth="sm"
      fullWidth
      disableEscapeKeyDown={isVerifying}
    >
      <DialogTitle sx={{ position: 'relative' }}>
        Age Verification
        {!isVerifying && (
          <IconButton
            aria-label="close"
            onClick={handleClose}
            sx={{
              position: 'absolute',
              right: 8,
              top: 8,
              color: (theme) => theme.palette.grey[500],
            }}
          >
            <CloseIcon />
          </IconButton>
        )}
      </DialogTitle>
      
      <DialogContent dividers>
        <Stepper activeStep={activeStep} orientation="vertical" sx={{ mb: 2 }}>
          {STEPS.map((label, index) => (
            <Step key={label}>
              <StepLabel
                StepIconProps={{
                  icon: 
                    index < activeStep ? (
                      <CheckCircleIcon color="primary" />
                    ) : index === activeStep ? (
                      <Box
                        sx={{
                          width: 24,
                          height: 24,
                          borderRadius: '50%',
                          bgcolor: 'primary.main',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          color: 'primary.contrastText',
                        }}
                      >
                        {index + 1}
                      </Box>
                    ) : (
                      <Box
                        sx={{
                          width: 24,
                          height: 24,
                          borderRadius: '50%',
                          border: '2px solid',
                          borderColor: 'action.disabled',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          color: 'text.disabled',
                        }}
                      >
                        {index + 1}
                      </Box>
                    ),
                }}
              >
                {label}
              </StepLabel>
              <StepContent>
                {index === activeStep && (
                  <Box sx={{ mt: 1, mb: 2 }}>
                    {renderStepContent(index)}
                  </Box>
                )}
              </StepContent>
            </Step>
          ))}
        </Stepper>
      </DialogContent>
      
      {activeStep < 2 && (
        <DialogActions sx={{ p: 2 }}>
          <Button
            onClick={activeStep === 0 ? handleClose : handleBack}
            disabled={activeStep === 0 || isVerifying}
          >
            {activeStep === 0 ? 'Cancel' : 'Back'}
          </Button>
          <Button
            variant="contained"
            onClick={activeStep === 0 ? handleNext : undefined}
            disabled={isVerifying || (activeStep === 1 && !idImage) || (activeStep === 2 && !selfieImage)}
          >
            {activeStep === 0 ? 'Continue' : 'Next'}
          </Button>
        </DialogActions>
      )}
      
      {isLastStep && (
        <DialogActions sx={{ p: 2 }}>
          <Button 
            onClick={handleClose} 
            variant="contained" 
            color="primary"
            fullWidth
          >
            Continue to Content
          </Button>
        </DialogActions>
      )}
    </Dialog>
  );
};

export default AgeVerification;
