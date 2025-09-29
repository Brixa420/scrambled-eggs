import React, { useState, useEffect } from 'react';
import { 
  Box, 
  Typography, 
  Paper, 
  Tabs, 
  Tab, 
  Button, 
  Table, 
  TableBody, 
  TableCell, 
  TableContainer, 
  TableHead, 
  TableRow, 
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  MenuItem,
  IconButton,
  Tooltip,
  useTheme,
  useMediaQuery,
  CircularProgress,
  Snackbar,
  Alert,
  Divider,
  Card,
  CardContent,
  Grid
} from '@mui/material';
import { 
  Warning as WarningIcon, 
  Gavel as GavelIcon, 
  Block as BlockIcon,
  CheckCircle as CheckCircleIcon,
  Cancel as CancelIcon,
  Refresh as RefreshIcon,
  FilterList as FilterListIcon,
  Search as SearchIcon
} from '@mui/icons-material';
import { useAuth } from '../../contexts/AuthContext';
import api from '../../services/api';

const ModerationDashboard = () => {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const { user } = useAuth();
  
  const [activeTab, setActiveTab] = useState(0);
  const [queue, setQueue] = useState([]);
  const [stats, setStats] = useState({
    pending: 0,
    inReview: 0,
    resolved: 0,
    violations: {
      total: 0,
      byType: {}
    }
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedItem, setSelectedItem] = useState(null);
  const [actionDialogOpen, setActionDialogOpen] = useState(false);
  const [actionType, setActionType] = useState('warn');
  const [actionReason, setActionReason] = useState('');
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });
  const [filters, setFilters] = useState({
    status: 'pending',
    contentType: 'all',
    severity: 'all'
  });

  // Fetch moderation queue
  const fetchModerationQueue = async () => {
    try {
      setLoading(true);
      const response = await api.get('/moderation/queue', {
        params: {
          status: filters.status === 'all' ? undefined : filters.status,
          content_type: filters.contentType === 'all' ? undefined : filters.contentType,
          limit: 50
        }
      });
      setQueue(response.data);
    } catch (err) {
      console.error('Error fetching moderation queue:', err);
      setError('Failed to load moderation queue');
      showSnackbar('Failed to load moderation queue', 'error');
    } finally {
      setLoading(false);
    }
  };

  // Fetch moderation stats
  const fetchModerationStats = async () => {
    try {
      const response = await api.get('/moderation/stats');
      setStats(response.data);
    } catch (err) {
      console.error('Error fetching moderation stats:', err);
      showSnackbar('Failed to load moderation statistics', 'error');
    }
  };

  // Handle tab change
  const handleTabChange = (event, newValue) => {
    setActiveTab(newValue);
    // Update filters based on tab
    const statusMap = { 0: 'pending', 1: 'in_review', 2: 'resolved' };
    setFilters(prev => ({ ...prev, status: statusMap[newValue] }));
  };

  // Handle action dialog open
  const handleOpenActionDialog = (item, type) => {
    setSelectedItem(item);
    setActionType(type);
    setActionDialogOpen(true);
  };

  // Handle action submission
  const handleActionSubmit = async () => {
    if (!selectedItem || !actionReason.trim()) return;

    try {
      let endpoint = '';
      let data = {
        user_id: selectedItem.user_id,
        reason: actionReason,
        violation_id: selectedItem.id
      };

      switch (actionType) {
        case 'warn':
          endpoint = '/moderation/warnings';
          break;
        case 'suspend':
          endpoint = '/moderation/suspensions';
          data.duration_days = 7; // Default 7-day suspension
          break;
        case 'ban':
          endpoint = '/moderation/bans';
          data.permanent = true;
          break;
        default:
          throw new Error('Invalid action type');
      }

      await api.post(endpoint, data);
      
      // Update the queue
      await fetchModerationQueue();
      await fetchModerationStats();
      
      showSnackbar(`User ${actionType}ed successfully`, 'success');
      setActionDialogOpen(false);
      setActionReason('');
    } catch (err) {
      console.error(`Error performing ${actionType} action:`, err);
      showSnackbar(`Failed to ${actionType} user`, 'error');
    }
  };

  // Handle appeal approval/rejection
  const handleAppealDecision = async (appealId, approve) => {
    try {
      await api.post(`/moderation/appeals/${appealId}/process`, {
        decision: approve ? 'approve' : 'deny',
        reason: approve ? 'Appeal approved' : 'Appeal denied'
      });
      
      await fetchModerationQueue();
      await fetchModerationStats();
      
      showSnackbar(
        `Appeal ${approve ? 'approved' : 'denied'} successfully`,
        approve ? 'success' : 'info'
      );
    } catch (err) {
      console.error('Error processing appeal:', err);
      showSnackbar('Failed to process appeal', 'error');
    }
  };

  // Show snackbar notification
  const showSnackbar = (message, severity = 'info') => {
    setSnackbar({ open: true, message, severity });
  };

  // Close snackbar
  const handleCloseSnackbar = () => {
    setSnackbar(prev => ({ ...prev, open: false }));
  };

  // Initial data fetch
  useEffect(() => {
    if (user?.isModerator || user?.isAdmin) {
      fetchModerationQueue();
      fetchModerationStats();
    }
  }, [filters.status, filters.contentType, filters.severity]);

  // Check if user has moderator/admin permissions
  if (!user?.isModerator && !user?.isAdmin) {
    return (
      <Box sx={{ p: 3, textAlign: 'center' }}>
        <Typography variant="h5" color="error">
          Access Denied
        </Typography>
        <Typography variant="body1" sx={{ mt: 2 }}>
          You do not have permission to access the moderation dashboard.
        </Typography>
      </Box>
    );
  }

  // Render status chip
  const renderStatusChip = (status) => {
    const statusMap = {
      pending: { label: 'Pending', color: 'warning' },
      in_review: { label: 'In Review', color: 'info' },
      resolved: { label: 'Resolved', color: 'success' },
      rejected: { label: 'Rejected', color: 'error' },
      approved: { label: 'Approved', color: 'success' }
    };
    
    const statusInfo = statusMap[status.toLowerCase()] || { label: status, color: 'default' };
    
    return (
      <Chip 
        label={statusInfo.label} 
        color={statusInfo.color} 
        size="small"
        variant="outlined"
      />
    );
  };

  // Render action buttons
  const renderActionButtons = (item) => (
    <Box sx={{ display: 'flex', gap: 1, justifyContent: 'flex-end' }}>
      <Tooltip title="Warn User">
        <IconButton 
          size="small" 
          color="warning"
          onClick={() => handleOpenActionDialog(item, 'warn')}
        >
          <WarningIcon />
        </IconButton>
      </Tooltip>
      <Tooltip title="Suspend User">
        <IconButton 
          size="small" 
          color="secondary"
          onClick={() => handleOpenActionDialog(item, 'suspend')}
        >
          <GavelIcon />
        </IconButton>
      </Tooltip>
      <Tooltip title="Ban User">
        <IconButton 
          size="small" 
          color="error"
          onClick={() => handleOpenActionDialog(item, 'ban')}
        >
          <BlockIcon />
        </IconButton>
      </Tooltip>
    </Box>
  );

  // Render appeal actions
  const renderAppealActions = (appeal) => (
    <Box sx={{ display: 'flex', gap: 1, justifyContent: 'flex-end' }}>
      <Tooltip title="Approve Appeal">
        <IconButton 
          size="small" 
          color="success"
          onClick={() => handleAppealDecision(appeal.id, true)}
        >
          <CheckCircleIcon />
        </IconButton>
      </Tooltip>
      <Tooltip title="Deny Appeal">
        <IconButton 
          size="small" 
          color="error"
          onClick={() => handleAppealDecision(appeal.id, false)}
        >
          <CancelIcon />
        </IconButton>
      </Tooltip>
    </Box>
  );

  return (
    <Box sx={{ p: isMobile ? 1 : 3 }}>
      <Typography variant="h4" gutterBottom>
        Moderation Dashboard
      </Typography>
      
      {/* Stats Cards */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Pending Review
              </Typography>
              <Typography variant="h5">
                {stats.pending || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                In Review
              </Typography>
              <Typography variant="h5">
                {stats.inReview || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Resolved Today
              </Typography>
              <Typography variant="h5">
                {stats.resolvedToday || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Total Violations
              </Typography>
              <Typography variant="h5">
                {stats.violations?.total || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs */}
      <Paper sx={{ mb: 2 }}>
        <Tabs
          value={activeTab}
          onChange={handleTabChange}
          indicatorColor="primary"
          textColor="primary"
          variant="scrollable"
          scrollButtons="auto"
        >
          <Tab label="Pending Review" />
          <Tab label="In Review" />
          <Tab label="Resolved" />
          <Tab label="Appeals" />
        </Tabs>
      </Paper>

      {/* Filters */}
      <Box sx={{ display: 'flex', gap: 2, mb: 2, flexWrap: 'wrap' }}>
        <TextField
          select
          size="small"
          label="Content Type"
          value={filters.contentType}
          onChange={(e) => setFilters({ ...filters, contentType: e.target.value })}
          sx={{ minWidth: 150 }}
        >
          <MenuItem value="all">All Types</MenuItem>
          <MenuItem value="image">Image</MenuItem>
          <MenuItem value="video">Video</MenuItem>
          <MenuItem value="text">Text</MenuItem>
          <MenuItem value="comment">Comment</MenuItem>
          <MenuItem value="profile">Profile</MenuItem>
        </TextField>
        
        <TextField
          select
          size="small"
          label="Severity"
          value={filters.severity}
          onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
          sx={{ minWidth: 120 }}
        >
          <MenuItem value="all">All Severities</MenuItem>
          <MenuItem value="low">Low</MenuItem>
          <MenuItem value="medium">Medium</MenuItem>
          <MenuItem value="high">High</MenuItem>
          <MenuItem value="critical">Critical</MenuItem>
        </TextField>
        
        <Box sx={{ flexGrow: 1 }} />
        
        <Button 
          variant="outlined" 
          startIcon={<RefreshIcon />}
          onClick={fetchModerationQueue}
          disabled={loading}
        >
          Refresh
        </Button>
      </Box>

      {/* Content */}
      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
          <CircularProgress />
        </Box>
      ) : error ? (
        <Box sx={{ p: 2, bgcolor: 'error.background', borderRadius: 1 }}>
          <Typography color="error">{error}</Typography>
        </Box>
      ) : queue.length === 0 ? (
        <Paper sx={{ p: 3, textAlign: 'center' }}>
          <Typography variant="h6" color="textSecondary">
            No items found in the moderation queue
          </Typography>
        </Paper>
      ) : (
        <TableContainer component={Paper}>
          <Table size={isMobile ? 'small' : 'medium'}>
            <TableHead>
              <TableRow>
                <TableCell>ID</TableCell>
                <TableCell>Type</TableCell>
                <TableCell>Content</TableCell>
                <TableCell>Reported By</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Reported At</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {queue.map((item) => (
                <TableRow key={item.id} hover>
                  <TableCell>#{item.id}</TableCell>
                  <TableCell>
                    <Chip 
                      label={item.content_type} 
                      size="small" 
                      variant="outlined"
                    />
                  </TableCell>
                  <TableCell sx={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {item.content_preview || 'No preview available'}
                  </TableCell>
                  <TableCell>
                    {item.reported_by?.username || 'System'}
                  </TableCell>
                  <TableCell>
                    {renderStatusChip(item.status)}
                  </TableCell>
                  <TableCell>
                    {new Date(item.created_at).toLocaleString()}
                  </TableCell>
                  <TableCell align="right">
                    {item.type === 'appeal' 
                      ? renderAppealActions(item)
                      : renderActionButtons(item)
                    }
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Action Dialog */}
      <Dialog 
        open={actionDialogOpen} 
        onClose={() => setActionDialogOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>
          {actionType === 'warn' && 'Warn User'}
          {actionType === 'suspend' && 'Suspend User'}
          {actionType === 'ban' && 'Ban User'}
        </DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            margin="dense"
            label="Reason"
            type="text"
            fullWidth
            multiline
            rows={4}
            variant="outlined"
            value={actionReason}
            onChange={(e) => setActionReason(e.target.value)}
            placeholder={`Enter the reason for this ${actionType}...`}
          />
          
          {actionType === 'suspend' && (
            <TextField
              select
              fullWidth
              margin="normal"
              label="Suspension Duration"
              value={7}
              onChange={(e) => {}}
            >
              <MenuItem value={1}>1 Day</MenuItem>
              <MenuItem value={3}>3 Days</MenuItem>
              <MenuItem value={7}>7 Days</MenuItem>
              <MenuItem value={14}>14 Days</MenuItem>
              <MenuItem value={30}>30 Days</MenuItem>
            </TextField>
          )}
          
          {actionType === 'ban' && (
            <Box sx={{ mt: 2 }}>
              <Typography variant="body2" color="error">
                Warning: This action cannot be undone. The user will be permanently banned.
              </Typography>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setActionDialogOpen(false)}>Cancel</Button>
          <Button 
            onClick={handleActionSubmit} 
            variant="contained"
            color={
              actionType === 'warn' ? 'warning' :
              actionType === 'suspend' ? 'secondary' : 'error'
            }
            disabled={!actionReason.trim()}
          >
            {actionType === 'warn' ? 'Issue Warning' : 
             actionType === 'suspend' ? 'Suspend User' : 'Ban User'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={handleCloseSnackbar}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert 
          onClose={handleCloseSnackbar} 
          severity={snackbar.severity}
          sx={{ width: '100%' }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default ModerationDashboard;
