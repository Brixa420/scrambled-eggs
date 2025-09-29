import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Paper,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Chip,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  CircularProgress,
  Alert,
  Tabs,
  Tab,
  useTheme,
  useMediaQuery
} from '@mui/material';
import {
  Warning as WarningIcon,
  Gavel as GavelIcon,
  Block as BlockIcon,
  Info as InfoIcon,
  History as HistoryIcon,
  CheckCircle as CheckCircleIcon,
  Close as CloseIcon,
  ReportProblem as ReportProblemIcon
} from '@mui/icons-material';
import { formatDistanceToNow } from 'date-fns';
import { useAuth } from '../../contexts/AuthContext';
import api from '../../services/api';

const TabPanel = ({ children, value, index, ...other }) => {
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`moderation-tabpanel-${index}`}
      aria-labelledby={`moderation-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ p: 2 }}>
          {children}
        </Box>
      )}
    </div>
  );
};

const ModerationItem = ({ item, type, onAppealClick }) => {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('sm'));
  
  const getIcon = () => {
    switch(type) {
      case 'warning':
        return <WarningIcon color="warning" />;
      case 'suspension':
        return <GavelIcon color="secondary" />;
      case 'ban':
        return <BlockIcon color="error" />;
      default:
        return <InfoIcon color="info" />;
    }
  };
  
  const getStatusChip = (status) => {
    const statusMap = {
      active: { label: 'Active', color: 'warning' },
      expired: { label: 'Expired', color: 'default' },
      appealed: { label: 'Appealed', color: 'info' },
      revoked: { label: 'Revoked', color: 'success' },
      permanent: { label: 'Permanent', color: 'error' }
    };
    
    const statusInfo = statusMap[status] || { label: status, color: 'default' };
    
    return (
      <Chip 
        label={statusInfo.label}
        color={statusInfo.color}
        size="small"
        variant="outlined"
        sx={{ ml: 1 }}
      />
    );
  };
  
  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return `${date.toLocaleDateString()} (${formatDistanceToNow(date, { addSuffix: true })})`;
  };
  
  const canAppeal = type !== 'warning' && 
                  item.status === 'active' && 
                  !item.appeal_id &&
                  !item.is_permanent;
  
  return (
    <Paper 
      elevation={1} 
      sx={{ 
        mb: 2, 
        borderLeft: `4px solid ${
          type === 'warning' ? theme.palette.warning.main :
          type === 'suspension' ? theme.palette.secondary.main :
          theme.palette.error.main
        }`
      }}
    >
      <Box sx={{ p: 2 }}>
        <Box display="flex" justifyContent="space-between" alignItems="flex-start">
          <Box display="flex" alignItems="center" flexWrap="wrap">
            {getIcon()}
            <Box ml={1}>
              <Typography variant="subtitle1" component="div">
                {type === 'warning' && 'Warning'}
                {type === 'suspension' && 'Account Suspension'}
                {type === 'ban' && 'Account Ban'}
                {getStatusChip(
                  item.is_permanent ? 'permanent' : 
                  new Date(item.expires_at) < new Date() ? 'expired' : 'active'
                )}
                {item.appeal_id && getStatusChip('appealed')}
              </Typography>
              <Typography variant="caption" color="textSecondary">
                Issued on {formatDate(item.created_at)}
                {item.expires_at && !item.is_permanent && (
                  <span> • Expires {formatDate(item.expires_at)}</span>
                )}
              </Typography>
            </Box>
          </Box>
          
          {canAppeal && (
            <Button 
              variant="outlined" 
              size="small"
              onClick={() => onAppealClick(item)}
              disabled={!!item.appeal_id}
            >
              Appeal
            </Button>
          )}
        </Box>
        
        <Box mt={1} mb={1}>
          <Typography variant="body2">
            <strong>Reason:</strong> {item.reason || 'No reason provided'}
          </Typography>
          
          {item.moderator_notes && (
            <Typography variant="body2" sx={{ mt: 1, fontStyle: 'italic' }}>
              <strong>Moderator Note:</strong> {item.moderator_notes}
            </Typography>
          )}
          
          {item.appeal_id && item.appeal_status && (
            <Box 
              mt={1} 
              p={1} 
              bgcolor="action.hover" 
              borderRadius={1}
            >
              <Typography variant="body2">
                <strong>Your Appeal:</strong> {item.appeal_reason}
              </Typography>
              <Typography 
                variant="caption" 
                color="textSecondary"
                sx={{ display: 'flex', alignItems: 'center', mt: 0.5 }}
              >
                <span>Status: </span>
                <Chip 
                  label={item.appeal_status.replace('_', ' ')}
                  size="small"
                  color={
                    item.appeal_status === 'pending' ? 'default' :
                    item.appeal_status === 'approved' ? 'success' : 'error'
                  }
                  sx={{ ml: 1 }}
                />
                {item.appeal_decision && (
                  <span style={{ marginLeft: 8 }}>
                    {item.appeal_decision}
                  </span>
                )}
              </Typography>
            </Box>
          )}
        </Box>
      </Box>
    </Paper>
  );
};\n
const AppealDialog = ({ open, onClose, item, type, onSuccess }) => {
  const [reason, setReason] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState('');
  
  const handleSubmit = async () => {
    if (!reason.trim()) {
      setError('Please provide a reason for your appeal');
      return;
    }
    
    try {
      setIsSubmitting(true);
      setError('');
      
      await api.post('/moderation/appeals', {
        moderation_action_id: item.id,
        action_type: type,
        reason: reason.trim(),
        evidence: '' // Could be extended to support file uploads
      });
      
      onSuccess();
      onClose();
    } catch (err) {
      console.error('Error submitting appeal:', err);
      setError(
        err.response?.data?.detail || 
        'Failed to submit appeal. Please try again.'
      );
    } finally {
      setIsSubmitting(false);
    }
  };
  
  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>
        <Box display="flex" justifyContent="space-between" alignItems="center">
          <span>Appeal {type === 'suspension' ? 'Suspension' : 'Ban'}</span>
          <IconButton 
            edge="end" 
            color="inherit" 
            onClick={onClose} 
            aria-label="close"
            disabled={isSubmitting}
          >
            <CloseIcon />
          </IconButton>
        </Box>
      </DialogTitle>
      
      <DialogContent>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>
            {error}
          </Alert>
        )}
        
        <Typography variant="body1" gutterBottom>
          You are appealing your account {type} issued on {new Date(item.created_at).toLocaleDateString()}.
        </Typography>
        
        <Box my={2} p={2} bgcolor="background.paper" borderRadius={1}>
          <Typography variant="subtitle2" color="textSecondary" gutterBottom>
            Reason for {type}:
          </Typography>
          <Typography variant="body1">
            {item.reason || 'No reason provided'}
          </Typography>
        </Box>
        
        <TextField
          fullWidth
          multiline
          rows={4}
          label="Your Appeal Reason"
          placeholder="Please explain why you believe this action should be reversed..."
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          variant="outlined"
          margin="normal"
          required
          disabled={isSubmitting}
        />
        
        <Box mt={2} p={2} bgcolor="warning.light" borderRadius={1}>
          <Box display="flex" alignItems="flex-start">
            <ReportProblemIcon color="warning" sx={{ mr: 1, mt: 0.5 }} />
            <Typography variant="body2">
              <strong>Note:</strong> Please be honest and provide as much detail as possible. 
              False appeals may result in additional moderation actions.
            </Typography>
          </Box>
        </Box>
      </DialogContent>
      
      <DialogActions sx={{ p: 2 }}>
        <Button 
          onClick={onClose} 
          disabled={isSubmitting}
          color="inherit"
        >
          Cancel
        </Button>
        <Button 
          onClick={handleSubmit} 
          variant="contained" 
          color="primary"
          disabled={isSubmitting || !reason.trim()}
          startIcon={
            isSubmitting ? (
              <CircularProgress size={20} color="inherit" />
            ) : (
              <CheckCircleIcon />
            )
          }
        >
          {isSubmitting ? 'Submitting...' : 'Submit Appeal'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

const UserModerationStatus = ({ userId }) => {
  const [activeTab, setActiveTab] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [moderationData, setModerationData] = useState({
    warnings: [],
    suspensions: [],
    bans: []
  });
  const [appealDialog, setAppealDialog] = useState({
    open: false,
    item: null,
    type: ''
  });
  
  const { user } = useAuth();
  const isOwnProfile = !userId || user?.id === userId;
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('sm'));
  
  const fetchModerationData = async () => {
    try {
      setLoading(true);
      setError('');
      
      const endpoint = userId 
        ? `/moderation/user/${userId}`
        : '/moderation/me';
      
      const response = await api.get(endpoint);
      setModerationData(response.data);
    } catch (err) {
      console.error('Error fetching moderation data:', err);
      setError('Failed to load moderation history');
    } finally {
      setLoading(false);
    }
  };
  
  useEffect(() => {
    fetchModerationData();
  }, [userId]);
  
  const handleTabChange = (event, newValue) => {
    setActiveTab(newValue);
  };
  
  const handleOpenAppealDialog = (item, type) => {
    setAppealDialog({
      open: true,
      item,
      type
    });
  };
  
  const handleCloseAppealDialog = () => {
    setAppealDialog(prev => ({ ...prev, open: false }));
  };
  
  const handleAppealSuccess = () => {
    // Refresh data after successful appeal
    fetchModerationData();
  };
  
  const hasActiveSuspension = moderationData.suspensions.some(
    s => new Date(s.expires_at) > new Date() && !s.is_revoked
  );
  
  const hasActiveBan = moderationData.bans.some(
    b => (b.is_permanent || new Date(b.expires_at) > new Date()) && !b.is_revoked
  );
  
  if (!isOwnProfile && !user?.isModerator && !user?.isAdmin) {
    return (
      <Box textAlign="center" p={3}>
        <Typography color="textSecondary">
          Moderation history is private
        </Typography>
      </Box>
    );
  }
  
  if (loading) {
    return (
      <Box display="flex" justifyContent="center" p={3}>
        <CircularProgress />
      </Box>
    );
  }
  
  if (error) {
    return (
      <Alert severity="error" sx={{ m: 2 }}>
        {error}
      </Alert>
    );
  }
  
  return (
    <Box>
      {(hasActiveSuspension || hasActiveBan) && (
        <Alert 
          severity={hasActiveBan ? "error" : "warning"} 
          sx={{ mb: 2 }}
          icon={hasActiveBan ? <BlockIcon /> : <GavelIcon />}
        >
          <Typography variant="subtitle1">
            {hasActiveBan 
              ? 'Your account is currently banned.' 
              : 'Your account is currently suspended.'}
          </Typography>
          {hasActiveBan ? (
            <Typography variant="body2">
              You cannot access most features of the platform. 
              {moderationData.bans[0]?.is_permanent 
                ? 'This ban is permanent.' 
                : `This ban will expire on ${new Date(moderationData.bans[0]?.expires_at).toLocaleDateString()}.`
              }
            </Typography>
          ) : (
            <Typography variant="body2">
              You cannot post, comment, or interact with other users until 
              {new Date(moderationData.suspensions[0]?.expires_at).toLocaleDateString()}.
            </Typography>
          )}
          
          {!moderationData.bans[0]?.appeal_id && (
            <Box mt={1}>
              <Button 
                variant="outlined" 
                color="inherit"
                size="small"
                onClick={() => handleOpenAppealDialog(
                  hasActiveBan ? moderationData.bans[0] : moderationData.suspensions[0],
                  hasActiveBan ? 'ban' : 'suspension'
                )}
              >
                Appeal This {hasActiveBan ? 'Ban' : 'Suspension'}
              </Button>
            </Box>
          )}
        </Alert>
      )}
      
      <Paper sx={{ mb: 2 }}>
        <Tabs
          value={activeTab}
          onChange={handleTabChange}
          indicatorColor="primary"
          textColor="primary"
          variant={isMobile ? "scrollable" : "standard"}
          scrollButtons="auto"
          allowScrollButtonsMobile
        >
          <Tab label={
            <Box display="flex" alignItems="center">
              <WarningIcon fontSize="small" sx={{ mr: 0.5 }} />
              <span>Warnings ({moderationData.warnings.length})</span>
            </Box>
          } />
          <Tab label={
            <Box display="flex" alignItems="center">
              <GavelIcon fontSize="small" sx={{ mr: 0.5 }} />
              <span>Suspensions ({moderationData.suspensions.length})</span>
            </Box>
          } />
          <Tab label={
            <Box display="flex" alignItems="center">
              <BlockIcon fontSize="small" sx={{ mr: 0.5 }} />
              <span>Bans ({moderationData.bans.length})</span>
            </Box>
          } />
        </Tabs>
        
        <Divider />
        
        <TabPanel value={activeTab} index={0}>
          {moderationData.warnings.length === 0 ? (
            <Box textAlign="center" p={3}>
              <Typography color="textSecondary">
                No warnings found
              </Typography>
            </Box>
          ) : (
            <List disablePadding>
              {moderationData.warnings.map((warning) => (
                <React.Fragment key={warning.id}>
                  <ModerationItem 
                    item={warning} 
                    type="warning" 
                    onAppealClick={handleOpenAppealDialog}
                  />
                </React.Fragment>
              ))}
            </List>
          )}
        </TabPanel>
        
        <TabPanel value={activeTab} index={1}>
          {moderationData.suspensions.length === 0 ? (
            <Box textAlign="center" p={3}>
              <Typography color="textSecondary">
                No suspensions found
              </Typography>
            </Box>
          ) : (
            <List disablePadding>
              {moderationData.suspensions.map((suspension) => (
                <React.Fragment key={suspension.id}>
                  <ModerationItem 
                    item={suspension} 
                    type="suspension" 
                    onAppealClick={handleOpenAppealDialog}
                  />
                </React.Fragment>
              ))}
            </List>
          )}
        </TabPanel>
        
        <TabPanel value={activeTab} index={2}>
          {moderationData.bans.length === 0 ? (
            <Box textAlign="center" p={3}>
              <Typography color="textSecondary">
                No bans found
              </Typography>
            </Box>
          ) : (
            <List disablePadding>
              {moderationData.bans.map((ban) => (
                <React.Fragment key={ban.id}>
                  <ModerationItem 
                    item={ban} 
                    type="ban" 
                    onAppealClick={handleOpenAppealDialog}
                  />
                </React.Fragment>
              ))}
            </List>
          )}
        </TabPanel>
      </Paper>
      
      {appealDialog.open && (
        <AppealDialog
          open={appealDialog.open}
          onClose={handleCloseAppealDialog}
          item={appealDialog.item}
          type={appealDialog.type}
          onSuccess={handleAppealSuccess}
        />
      )}
    </Box>
  );
};

export default UserModerationStatus;
