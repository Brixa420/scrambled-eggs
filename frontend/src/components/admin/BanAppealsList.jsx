import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Button,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Alert,
  CircularProgress,
  Tooltip,
  IconButton,
  Divider
} from '@mui/material';
import { 
  Check as ApproveIcon, 
  Close as RejectIcon, 
  Visibility as ViewIcon,
  Refresh as RefreshIcon
} from '@mui/icons-material';
import { formatDistanceToNow } from 'date-fns';

const STATUS_COLORS = {
  pending: 'default',
  under_review: 'info',
  approved: 'success',
  rejected: 'error',
  further_review_needed: 'warning'
};

const BanAppealsList = () => {
  const [appeals, setAppeals] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [total, setTotal] = useState(0);
  const [selectedAppeal, setSelectedAppeal] = useState(null);
  const [reviewDialogOpen, setReviewDialogOpen] = useState(false);
  const [action, setAction] = useState(null);
  const [reviewNotes, setReviewNotes] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState(null);
  const [statusFilter, setStatusFilter] = useState('all');

  const fetchAppeals = async () => {
    try {
      setLoading(true);
      
      let url = `/api/ban-appeals/admin/appeals?limit=${rowsPerPage}&offset=${page * rowsPerPage}`;
      if (statusFilter !== 'all') {
        url += `&status=${statusFilter}`;
      }
      
      const response = await fetch(url, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      
      if (!response.ok) {
        throw new Error('Failed to fetch ban appeals');
      }
      
      const data = await response.json();
      setAppeals(data.appeals || []);
      setTotal(data.total || 0);
      
    } catch (err) {
      console.error('Error fetching ban appeals:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAppeals();
  }, [page, rowsPerPage, statusFilter]);

  const handleChangePage = (event, newPage) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const handleReviewAppeal = (appeal, action) => {
    setSelectedAppeal(appeal);
    setAction(action);
    setReviewNotes('');
    setReviewDialogOpen(true);
  };

  const handleSubmitReview = async () => {
    if (!selectedAppeal || !action) return;
    
    try {
      setIsProcessing(true);
      setError(null);
      
      const response = await fetch(
        `/api/ban-appeals/admin/appeals/${selectedAppeal.id}/review`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${localStorage.getItem('token')}`
          },
          body: JSON.stringify({
            action,
            notes: reviewNotes
          })
        }
      );
      
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || 'Failed to process appeal');
      }
      
      // Refresh the list
      fetchAppeals();
      setReviewDialogOpen(false);
      
    } catch (err) {
      console.error('Error reviewing appeal:', err);
      setError(err.message);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleViewDetails = (appeal) => {
    setSelectedAppeal(appeal);
    // You can implement a detailed view dialog here
    console.log('View appeal details:', appeal);
  };

  const renderStatusChip = (status) => (
    <Chip 
      label={status.replace(/_/g, ' ').toUpperCase()}
      color={STATUS_COLORS[status] || 'default'}
      size="small"
    />
  );

  if (loading && appeals.length === 0) {
    return (
      <Box display="flex" justifyContent="center" p={4}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h5">Ban Appeals</Typography>
        <Box>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={fetchAppeals}
            disabled={loading}
          >
            Refresh
          </Button>
        </Box>
      </Box>
      
      <Box mb={2}>
        <Chip
          label="All"
          onClick={() => setStatusFilter('all')}
          color={statusFilter === 'all' ? 'primary' : 'default'}
          variant={statusFilter === 'all' ? 'filled' : 'outlined'}
          sx={{ mr: 1, mb: 1 }}
        />
        {Object.entries(STATUS_COLORS).map(([status, color]) => (
          <Chip
            key={status}
            label={status.replace(/_/g, ' ').toUpperCase()}
            onClick={() => setStatusFilter(status)}
            color={statusFilter === status ? 'primary' : 'default'}
            variant={statusFilter === status ? 'filled' : 'outlined'}
            sx={{ mr: 1, mb: 1 }}
          />
        ))}
      </Box>
      
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}
      
      <Paper sx={{ width: '100%', overflow: 'hidden' }}>
        <TableContainer sx={{ maxHeight: 'calc(100vh - 250px)' }}>
          <Table stickyHeader size="small">
            <TableHead>
              <TableRow>
                <TableCell>User</TableCell>
                <TableCell>Ban Reason</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Submitted</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {appeals.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} align="center" sx={{ py: 3 }}>
                    <Typography color="text.secondary">
                      No ban appeals found
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                appeals.map((appeal) => (
                  <TableRow key={appeal.id} hover>
                    <TableCell>
                      <Box>
                        <Typography variant="subtitle2">
                          {appeal.user?.username || `User #${appeal.user_id}`}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          ID: {appeal.user_id}
                        </Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Typography noWrap sx={{ maxWidth: 300 }}>
                        {appeal.ban_reason || 'No reason provided'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      {renderStatusChip(appeal.status)}
                    </TableCell>
                    <TableCell>
                      {formatDistanceToNow(new Date(appeal.created_at), { addSuffix: true })}
                    </TableCell>
                    <TableCell>
                      <Box display="flex" gap={1}>
                        <Tooltip title="View Details">
                          <IconButton
                            size="small"
                            onClick={() => handleViewDetails(appeal)}
                          >
                            <ViewIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        
                        {['pending', 'further_review_needed'].includes(appeal.status) && (
                          <>
                            <Tooltip title="Approve">
                              <IconButton
                                size="small"
                                color="success"
                                onClick={() => handleReviewAppeal(appeal, 'approve')}
                              >
                                <ApproveIcon fontSize="small" />
                              </IconButton>
                            </Tooltip>
                            
                            <Tooltip title="Reject">
                              <IconButton
                                size="small"
                                color="error"
                                onClick={() => handleReviewAppeal(appeal, 'reject')}
                              >
                                <RejectIcon fontSize="small" />
                              </IconButton>
                            </Tooltip>
                          </>
                        )}
                      </Box>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
        
        <TablePagination
          rowsPerPageOptions={[5, 10, 25, 50]}
          component="div"
          count={total}
          rowsPerPage={rowsPerPage}
          page={page}
          onPageChange={handleChangePage}
          onRowsPerPageChange={handleChangeRowsPerPage}
        />
      </Paper>
      
      {/* Review Dialog */}
      <Dialog 
        open={reviewDialogOpen} 
        onClose={() => !isProcessing && setReviewDialogOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>
          {action === 'approve' ? 'Approve' : 'Reject'} Appeal
        </DialogTitle>
        
        <DialogContent>
          {selectedAppeal && (
            <Box>
              <Typography variant="subtitle2" gutterBottom>
                Ban Reason:
              </Typography>
              <Typography paragraph>{selectedAppeal.ban_reason || 'No reason provided'}</Typography>
              
              <Typography variant="subtitle2" gutterBottom>
                User's Appeal:
              </Typography>
              <Typography paragraph sx={{ mb: 3, whiteSpace: 'pre-line' }}>
                {selectedAppeal.appeal_text}
              </Typography>
              
              <TextField
                fullWidth
                multiline
                rows={3}
                label="Notes (Optional)"
                value={reviewNotes}
                onChange={(e) => setReviewNotes(e.target.value)}
                disabled={isProcessing}
                placeholder="Add any notes about this decision..."
              />
              
              {error && (
                <Alert severity="error" sx={{ mt: 2 }}>
                  {error}
                </Alert>
              )}
            </Box>
          )}
        </DialogContent>
        
        <DialogActions>
          <Button 
            onClick={() => setReviewDialogOpen(false)}
            disabled={isProcessing}
          >
            Cancel
          </Button>
          <Button
            onClick={handleSubmitReview}
            color={action === 'approve' ? 'success' : 'error'}
            variant="contained"
            disabled={isProcessing}
            startIcon={isProcessing ? <CircularProgress size={20} /> : null}
          >
            {isProcessing ? 'Processing...' : action === 'approve' ? 'Approve' : 'Reject'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default BanAppealsList;
