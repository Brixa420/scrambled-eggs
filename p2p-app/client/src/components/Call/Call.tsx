import React, { useEffect, useRef, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useCall } from '../../contexts/CallContext';
import { useSnackbar } from '../../contexts/SnackbarContext';
import { 
  Box, 
  Button, 
  Container, 
  Paper, 
  Typography, 
  IconButton, 
  Avatar, 
  Grid, 
  TextField,
  List,
  ListItem,
  ListItemText,
  ListItemAvatar,
  Divider,
  CircularProgress
} from '@mui/material';
import {
  CallEnd as CallEndIcon,
  Mic as MicIcon,
  MicOff as MicOffIcon,
  Videocam as VideocamIcon,
  VideocamOff as VideocamOffIcon,
  Chat as ChatIcon,
  Person as PersonIcon,
  Send as SendIcon,
} from '@mui/icons-material';

const Call: React.FC = () => {
  const { roomId } = useParams<{ roomId: string }>();
  const navigate = useNavigate();
  const { showMessage } = useSnackbar();
  const {
    localStream,
    remoteStream,
    isCallActive,
    isCallInitiator,
    isVideoEnabled,
    isAudioEnabled,
    startCall,
    answerCall,
    endCall,
    toggleVideo,
    toggleAudio,
    sendMessage,
    messages,
    participants,
    error,
    loading,
  } = useCall();

  const [message, setMessage] = useState('');
  const [showChat, setShowChat] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const localVideoRef = useRef<HTMLVideoElement>(null);
  const remoteVideoRef = useRef<HTMLVideoElement>(null);

  // Initialize call when component mounts
  useEffect(() => {
    if (roomId) {
      if (isCallInitiator) {
        startCall(roomId);
      } else {
        // In a real app, you would wait for an offer from the initiator
        // For now, we'll just start the call
        startCall(roomId);
      }
    }

    return () => {
      // Clean up when component unmounts
      endCall();
    };
  }, [roomId]);

  // Update video elements when streams change
  useEffect(() => {
    if (localVideoRef.current && localStream) {
      localVideoRef.current.srcObject = localStream;
    }
  }, [localStream]);

  useEffect(() => {
    if (remoteVideoRef.current && remoteStream) {
      remoteVideoRef.current.srcObject = remoteStream;
    }
  }, [remoteStream]);

  // Auto-scroll chat to bottom when new messages arrive
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Show error messages
  useEffect(() => {
    if (error) {
      showMessage(error, 'error');
    }
  }, [error, showMessage]);

  const handleEndCall = () => {
    endCall();
    navigate('/');
  };

  const handleSendMessage = (e: React.FormEvent) => {
    e.preventDefault();
    if (message.trim()) {
      sendMessage(message);
      setMessage('');
    }
  };

  if (loading) {
    return (
      <Box
        display="flex"
        justifyContent="center"
        alignItems="center"
        minHeight="100vh"
      >
        <CircularProgress size={60} />
      </Box>
    );
  }

  return (
    <Box sx={{ height: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Main content area */}
      <Box sx={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        {/* Video area */}
        <Box 
          sx={{ 
            flex: 1, 
            backgroundColor: '#1a1a1a',
            position: 'relative',
            overflow: 'hidden',
          }}
        >
          {/* Remote video */}
          {remoteStream ? (
            <video
              ref={remoteVideoRef}
              autoPlay
              playsInline
              style={{
                width: '100%',
                height: '100%',
                objectFit: 'cover',
              }}
            />
          ) : (
            <Box
              sx={{
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'center',
                alignItems: 'center',
                height: '100%',
                color: 'white',
              }}
            >
              <PersonIcon sx={{ fontSize: 100, mb: 2 }} />
              <Typography variant="h6">Waiting for participants...</Typography>
            </Box>
          )}

          {/* Local video */}
          {localStream && (
            <Paper
              elevation={6}
              sx={{
                position: 'absolute',
                bottom: 20,
                right: 20,
                width: '20%',
                minWidth: 200,
                maxWidth: 300,
                aspectRatio: '16/9',
                borderRadius: 1,
                overflow: 'hidden',
                '&:hover': {
                  transform: 'scale(1.05)',
                  transition: 'transform 0.3s',
                },
              }}
            >
              <video
                ref={localVideoRef}
                autoPlay
                playsInline
                muted
                style={{
                  width: '100%',
                  height: '100%',
                  objectFit: 'cover',
                  transform: 'rotateY(180deg)', // Mirror the local video
                }}
              />
            </Paper>
          )}
        </Box>

        {/* Chat sidebar */}
        {showChat && (
          <Paper 
            elevation={3} 
            sx={{ 
              width: 300, 
              display: 'flex', 
              flexDirection: 'column',
              borderLeft: '1px solid #e0e0e0',
            }}
          >
            <Box sx={{ p: 2, borderBottom: '1px solid #e0e0e0' }}>
              <Typography variant="h6">Chat</Typography>
            </Box>
            
            <Box sx={{ flex: 1, overflowY: 'auto', p: 2 }}>
              <List>
                {messages.map((msg, index) => (
                  <ListItem key={index} alignItems="flex-start" sx={{ px: 1 }}>
                    <ListItemAvatar sx={{ minWidth: 32, mr: 1 }}>
                      <Avatar sx={{ width: 24, height: 24, fontSize: '0.75rem' }}>
                        {msg.isMine ? 'Me' : 'Them'}
                      </Avatar>
                    </ListItemAvatar>
                    <ListItemText
                      primary={msg.text}
                      secondary={new Date(msg.timestamp).toLocaleTimeString()}
                      primaryTypographyProps={{
                        color: msg.isMine ? 'primary.main' : 'text.primary',
                        fontWeight: msg.isMine ? 'bold' : 'normal',
                      }}
                      secondaryTypographyProps={{
                        fontSize: '0.7rem',
                        color: 'text.secondary',
                      }}
                    />
                  </ListItem>
                ))}
                <div ref={messagesEndRef} />
              </List>
            </Box>

            <Box component="form" onSubmit={handleSendMessage} sx={{ p: 2, borderTop: '1px solid #e0e0e0' }}>
              <Box display="flex" gap={1}>
                <TextField
                  fullWidth
                  size="small"
                  placeholder="Type a message..."
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                />
                <Button type="submit" variant="contained" color="primary">
                  <SendIcon />
                </Button>
              </Box>
            </Box>
          </Paper>
        )}
      </Box>

      {/* Control bar */}
      <Box 
        sx={{ 
          backgroundColor: 'background.paper', 
          py: 2,
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          borderTop: '1px solid #e0e0e0',
        }}
      >
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
          {/* Toggle video */}
          <IconButton
            color={isVideoEnabled ? 'primary' : 'error'}
            onClick={toggleVideo}
            sx={{ bgcolor: 'action.hover', '&:hover': { bgcolor: 'action.selected' } }}
          >
            {isVideoEnabled ? <VideocamIcon /> : <VideocamOffIcon />}
          </IconButton>

          {/* Toggle audio */}
          <IconButton
            color={isAudioEnabled ? 'primary' : 'error'}
            onClick={toggleAudio}
            sx={{ bgcolor: 'action.hover', '&:hover': { bgcolor: 'action.selected' } }}
          >
            {isAudioEnabled ? <MicIcon /> : <MicOffIcon />}
          </IconButton>

          {/* End call */}
          <IconButton
            color="error"
            onClick={handleEndCall}
            sx={{ 
              bgcolor: 'error.main', 
              color: 'white',
              '&:hover': { 
                bgcolor: 'error.dark',
                transform: 'scale(1.1)',
                transition: 'transform 0.2s',
              },
              width: 56,
              height: 56,
            }}
          >
            <CallEndIcon />
          </IconButton>

          {/* Toggle chat */}
          <IconButton
            color={showChat ? 'primary' : 'default'}
            onClick={() => setShowChat(!showChat)}
            sx={{ bgcolor: 'action.hover', '&:hover': { bgcolor: 'action.selected' } }}
          >
            <ChatIcon />
          </IconButton>
        </Box>
      </Box>
    </Box>
  );
};

export default Call;
