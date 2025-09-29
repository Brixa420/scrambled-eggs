import React, { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  MenuItem,
  Box,
  Typography,
  Alert,
  CircularProgress,
  IconButton,
  Divider,
  Chip
} from '@mui/material';
import { Close as CloseIcon, Report as ReportIcon } from '@mui/icons-material';
import { useAuth } from '../../contexts/AuthContext';
import api from '../../services/api';

const VIOLATION_TYPES = [
  { value: 'spam', label: 'Spam or Scam' },
  { value: 'harassment', label: 'Harassment or Bullying' },
  { value: 'hate_speech', label: 'Hate Speech or Symbols' },
  { value: 'nudity', label: 'Nudity or Sexual Content' },
  { value: 'violence', label: 'Violence or Harm' },
  { value: 'illegal', label: 'Illegal Activities' },
  { value: 'intellectual_property', label: 'Intellectual Property Violation' },
  { value: 'self_harm', label: 'Self-Harm or Suicide' },
  { value: 'fake_news', label: 'False Information' },
  { value: 'other', label: 'Other' },
];

const ReportContentDialog = ({ 
  open, 
  onClose, 
  contentId, 
  contentType = 'content',
  contentPreview = ''
}) => {
  const { user } = useAuth();
  const [violationType, setViolationType] = useState('');
  const [description, setDescription] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [isSubmitted, setIsSubmitted] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!violationType) {
      setError('Please select a violation type');
      return;
    }
    
    if (!description.trim()) {
      setError('Please provide a detailed description');
      return;
    }
    
    try {
      setIsSubmitting(true);
      setError('');
      
      await api.post('/moderation/report', {
        content_id: contentId,
        content_type: contentType,
        violation_type: violationType,
        description: description.trim(),
        context: { content_preview: contentPreview }
      });
      
      setIsSubmitted(true);
    } catch (err) {
      console.error('Error submitting report:', err);
      setError(
        err.response?.data?.detail || 
        'Failed to submit report. Please try again.'
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleClose = () => {
    if (!isSubmitting) {
      // Reset form when closing
      if (isSubmitted) {
        setViolationType('');
        setDescription('');
        setIsSubmitted(false);
      }
      onClose();
    }
  };

  if (isSubmitted) {
    return (
      <Dialog open={open} onClose={handleClose} maxWidth="sm" fullWidth>
        <DialogTitle>
          <Box display="flex" justifyContent="space-between" alignItems="center">
            <Box display="flex" alignItems="center">
              <ReportIcon color="primary" sx={{ mr: 1 }} />
              <span>Report Submitted</span>
            </Box>
            <IconButton 
              edge="end" 
              color="inherit" 
              onClick={handleClose} 
              aria-label="close"
              disabled={isSubmitting}
            >
              <CloseIcon />
            </IconButton>
          </Box>
        </DialogTitle>
        <DialogContent>
          <Box textAlign="center" py={4}>
            <CheckCircleIcon 
              color="success" 
              sx={{ fontSize: 64, mb: 2 }} 
            />
            <Typography variant="h6" gutterBottom>
              Thank You for Your Report
            </Typography>
            <Typography variant="body1" color="textSecondary" paragraph>
              We've received your report and our moderation team will review it shortly.
              We appreciate your help in keeping our community safe.
            </Typography>
            {user?.isModerator && (
              <Chip 
                label="Moderator Note: This report has been prioritized" 
                color="info" 
                size="small"
                sx={{ mt: 2 }}
              />
            )}
          </Box>
        </DialogContent>
        <DialogActions sx={{ p: 2, justifyContent: 'center' }}>
          <Button 
            onClick={handleClose} 
            variant="contained" 
            color="primary"
            fullWidth
          >
            Close
          </Button>
        </DialogActions>
      </Dialog>
    );
  }

  return (
    <Dialog 
      open={open} 
      onClose={handleClose} 
      maxWidth="sm" 
      fullWidth
      component="form"
      onSubmit={handleSubmit}
    >
      <DialogTitle>
        <Box display="flex" justifyContent="space-between" alignItems="center">
          <Box display="flex" alignItems="center">
            <ReportIcon color="error" sx={{ mr: 1 }} />
            <span>Report {contentType}</span>
          </Box>
          <IconButton 
            edge="end" 
            color="inherit" 
            onClick={handleClose} 
            aria-label="close"
            disabled={isSubmitting}
          >
            <CloseIcon />
          </IconButton>
        </Box>
      </DialogTitle>
      
      <DialogContent>
        {contentPreview && (
          <Box 
            sx={{ 
              p: 2, 
              mb: 2, 
              bgcolor: 'background.paper', 
              borderRadius: 1,
              border: '1px solid',
              borderColor: 'divider'
            }}
          >
            <Typography variant="subtitle2" color="textSecondary" gutterBottom>
              Content being reported:
            </Typography>
            <Typography variant="body2" sx={{ fontStyle: 'italic' }}>
              {contentPreview.length > 200 
                ? `${contentPreview.substring(0, 200)}...` 
                : contentPreview}
            </Typography>
          </Box>
        )}
        
        {error && (
          <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>
            {error}
          </Alert>
        )}
        
        <TextField
          select
          fullWidth
          label="What's the issue?"
          value={violationType}
          onChange={(e) => setViolationType(e.target.value)}
          variant="outlined"
          margin="normal"
          required
          disabled={isSubmitting}
          SelectProps={{
            displayEmpty: true,
            renderValue: (selected) => {
              if (!selected) {
                return <em>Select a violation type</em>;
              }
              return VIOLATION_TYPES.find(t => t.value === selected)?.label || selected;
            },
          }}
        >
          <MenuItem disabled value="">
            <em>Select a violation type</em>
          </MenuItem>
          {VIOLATION_TYPES.map((type) => (
            <MenuItem key={type.value} value={type.value}>
              {type.label}
            </MenuItem>
          ))}
        </TextField>
        
        <TextField
          fullWidth
          multiline
          rows={4}
          label="Additional details"
          placeholder="Please provide as much detail as possible about the violation..."
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          variant="outlined"
          margin="normal"
          required
          disabled={isSubmitting}
          sx={{ mt: 2 }}
        />
        
        <Box mt={2}>
          <Typography variant="caption" color="textSecondary">
            Your report is anonymous, except if you're reporting an intellectual property violation.
            {user?.isModerator && (
              <span style={{ color: 'primary.main' }}> 
                As a moderator, your report will be prioritized.
              </span>
            )}
          </Typography>
        </Box>
      </DialogContent>
      
      <Divider />
      
      <DialogActions sx={{ p: 2, justifyContent: 'space-between' }}>
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
          color="error"
          disabled={isSubmitting || !violationType || !description.trim()}
          startIcon={
            isSubmitting ? (
              <CircularProgress size={20} color="inherit" />
            ) : (
              <ReportIcon />
            )
          }
        >
          {isSubmitting ? 'Submitting...' : 'Submit Report'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default ReportContentDialog;
