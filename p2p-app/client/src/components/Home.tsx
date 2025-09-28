import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useSnackbar } from '../contexts/SnackbarContext';
import { Box, Button, Container, TextField, Typography, Paper, Grid, Avatar } from '@mui/material';
import { styled } from '@mui/material/styles';
import VideoCallIcon from '@mui/icons-material/VideoCall';
import JoinFullIcon from '@mui/icons-material/JoinFull';
import LogoutIcon from '@mui/icons-material/Logout';

const Home: React.FC = () => {
  const { user, logout } = useAuth();
  const { showMessage } = useSnackbar();
  const navigate = useNavigate();
  const [roomId, setRoomId] = useState('');
  const [isCreatingRoom, setIsCreatingRoom] = useState(false);
  const [isJoiningRoom, setIsJoiningRoom] = useState(false);

  const handleCreateRoom = () => {
    if (!user) {
      showMessage('Please log in to create a room', 'error');
      return;
    }
    setIsCreatingRoom(true);
    
    // In a real app, you would create a room on the server
    const newRoomId = Math.random().toString(36).substring(2, 8);
    
    // Simulate API call
    setTimeout(() => {
      navigate(`/call/${newRoomId}`);
      setIsCreatingRoom(false);
    }, 500);
  };

  const handleJoinRoom = () => {
    if (!roomId.trim()) {
      showMessage('Please enter a room ID', 'error');
      return;
    }
    
    if (!user) {
      showMessage('Please log in to join a room', 'error');
      return;
    }
    
    setIsJoiningRoom(true);
    // In a real app, you would validate the room ID with the server
    setTimeout(() => {
      navigate(`/call/${roomId.trim()}`);
      setIsJoiningRoom(false);
    }, 500);
  };

  const handleLogout = async () => {
    try {
      await logout();
      showMessage('Successfully logged out', 'success');
    } catch (error) {
      console.error('Logout error:', error);
      showMessage('Failed to log out', 'error');
    }
  };

  return (
    <Container maxWidth="md" sx={{ mt: 8 }}>
      <Paper elevation={3} sx={{ p: 4, borderRadius: 2 }}>
        <Box sx={{ textAlign: 'center', mb: 4 }}>
          <Typography variant="h4" component="h1" gutterBottom>
            Welcome to P2P Video Chat
          </Typography>
          
          {user ? (
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', mb: 3 }}>
              <Avatar sx={{ bgcolor: 'primary.main', mr: 2 }}>
                {user.username.charAt(0).toUpperCase()}
              </Avatar>
              <Typography variant="h6">
                Hello, {user.username}
              </Typography>
            </Box>
          ) : (
            <Typography variant="subtitle1" color="text.secondary" gutterBottom>
              Please log in to start or join a video call
            </Typography>
          )}
        </Box>

        <Grid container spacing={4} justifyContent="center">
          <Grid item xs={12} md={5}>
            <Paper 
              elevation={2} 
              sx={{ 
                p: 3, 
                height: '100%',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                textAlign: 'center',
                '&:hover': {
                  transform: 'translateY(-5px)',
                  transition: 'transform 0.3s',
                },
              }}
            >
              <VideoCallIcon color="primary" sx={{ fontSize: 60, mb: 2 }} />
              <Typography variant="h6" gutterBottom>
                New Meeting
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                Create a new video call and invite others to join
              </Typography>
              <Button
                variant="contained"
                color="primary"
                onClick={handleCreateRoom}
                disabled={isCreatingRoom || !user}
                fullWidth
                sx={{ mt: 'auto' }}
              >
                {isCreatingRoom ? 'Creating...' : 'New Meeting'}
              </Button>
            </Paper>
          </Grid>

          <Grid item xs={12} md={5}>
            <Paper 
              elevation={2} 
              sx={{ 
                p: 3, 
                height: '100%',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                textAlign: 'center',
                '&:hover': {
                  transform: 'translateY(-5px)',
                  transition: 'transform 0.3s',
                },
              }}
            >
              <JoinFullIcon color="secondary" sx={{ fontSize: 60, mb: 2 }} />
              <Typography variant="h6" gutterBottom>
                Join Meeting
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Enter a meeting ID to join an existing call
              </Typography>
              <TextField
                fullWidth
                variant="outlined"
                placeholder="Meeting ID"
                value={roomId}
                onChange={(e) => setRoomId(e.target.value)}
                sx={{ mb: 2 }}
                disabled={!user}
              />
              <Button
                variant="contained"
                color="secondary"
                onClick={handleJoinRoom}
                disabled={isJoiningRoom || !user || !roomId.trim()}
                fullWidth
              >
                {isJoiningRoom ? 'Joining...' : 'Join'}
              </Button>
            </Paper>
          </Grid>
        </Grid>

        {user && (
          <Box sx={{ mt: 4, textAlign: 'center' }}>
            <Button
              variant="outlined"
              color="error"
              startIcon={<LogoutIcon />}
              onClick={handleLogout}
            >
              Logout
            </Button>
          </Box>
        )}
      </Paper>
    </Container>
  );
};

export default Home;
