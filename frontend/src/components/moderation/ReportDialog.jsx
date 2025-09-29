import React, { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormHelperText,
  CircularProgress,
  Typography,
  Box,
  Alert
} from '@mui/material';

const REPORT_REASONS = [
  { value: 'inappropriate', label: 'Inappropriate Content' },
  { value: 'harassment', label: 'Harassment or Bullying' },
  { value: 'violence', label: 'Violence or Harm' },
  { value: 'hate_speech', label: 'Hate Speech' },
  { value: 'spam', label: 'Spam or Scam' },
  { value: 'privacy', label: 'Privacy Violation' },
  { value: 'other', label: 'Other' },
];

const ReportDialog = ({ open, onClose, contentId, contentType = 'content' }) => {
  const [reason, setReason] = useState('');
  const [customReason, setCustomReason] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [isSuccess, setIsSuccess] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!reason) {
      setError('Please select a reason for reporting');
      return;
    }
    
    try {
      setIsSubmitting(true);
      setError(null);
      
      // Call your API to submit the report
      const response = await fetch('/api/moderation/report', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({
          content_id: contentId,
          content_type: contentType,
          reason: reason === 'other' ? customReason : reason,
          details: {
            custom_reason: reason === 'other' ? customReason : undefined
          }
        })
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to submit report');
      }
      
      setIsSuccess(true);
      setTimeout(() => {
        onClose();
        setIsSuccess(false);
      }, 2000);
      
    } catch (err) {
      console.error('Error submitting report:', err);
      setError(err.message || 'Failed to submit report. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleClose = () => {
    if (!isSubmitting) {
      onClose();
      // Reset form
      setReason('');
      setCustomReason('');
      setError(null);
      setIsSuccess(false);
    }
  };

  return (
    <Dialog 
      open={open} 
      onClose={handleClose}
      maxWidth="sm"
      fullWidth
    >
      <DialogTitle>Report {contentType}</DialogTitle>
      
      {isSuccess ? (
        <DialogContent>
          <Box textAlign="center" py={4}>
            <Typography variant="h6" color="success.main" gutterBottom>
              Report Submitted
            </Typography>
            <Typography variant="body1">
              Thank you for your report. Our team will review it shortly.
            </Typography>
          </Box>
          <DialogActions>
            <Button onClick={handleClose} color="primary">
              Close
            </Button>
          </DialogActions>
        </DialogContent>
      ) : (
        <form onSubmit={handleSubmit}>
          <DialogContent>
            {error && (
              <Alert severity="error" sx={{ mb: 2 }}>
                {error}
              </Alert>
            )}
            
            <FormControl fullWidth margin="normal" required>
              <InputLabel id="report-reason-label">Reason for reporting</InputLabel>
              <Select
                labelId="report-reason-label"
                value={reason}
                label="Reason for reporting"
                onChange={(e) => setReason(e.target.value)}
                disabled={isSubmitting}
              >
                {REPORT_REASONS.map((option) => (
                  <MenuItem key={option.value} value={option.value}>
                    {option.label}
                  </MenuItem>
                ))}
              </Select>
              <FormHelperText>
                Please select the most appropriate reason for your report
              </FormHelperText>
            </FormControl>
            
            {reason === 'other' && (
              <TextField
                fullWidth
                margin="normal"
                label="Please specify"
                value={customReason}
                onChange={(e) => setCustomReason(e.target.value)}
                disabled={isSubmitting}
                required
                multiline
                rows={3}
              />
            )}
            
            <Box mt={2}>
              <Typography variant="body2" color="text.secondary">
                Your report is anonymous, except for copyright and legal reports.
              </Typography>
            </Box>
          </DialogContent>
          
          <DialogActions sx={{ px: 3, pb: 3 }}>
            <Button 
              onClick={handleClose} 
              disabled={isSubmitting}
              color="inherit"
            >
              Cancel
            </Button>
            <Button 
              type="submit" 
              variant="contained" 
              color="primary"
              disabled={isSubmitting || !reason}
              startIcon={isSubmitting && <CircularProgress size={20} />}
            >
              {isSubmitting ? 'Submitting...' : 'Submit Report'}
            </Button>
          </DialogActions>
        </form>
      )}
    </Dialog>
  );
};

export default ReportDialog;
