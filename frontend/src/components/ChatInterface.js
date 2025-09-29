import React, { useState, useEffect, useRef } from 'react';
import { format } from 'date-fns';
import { Paper, TextField, Button, Typography, Box, Avatar, List, ListItem, ListItemAvatar, ListItemText, Divider, CircularProgress, Badge } from '@mui/material';
import { Send as SendIcon, Person as PersonIcon } from '@mui/icons-material';
import useChat from '../hooks/useChat';

const ChatInterface = ({ roomId, userId, token, userName }) => {
  const [message, setMessage] = useState('');
  const messageContainerRef = useRef(null);
  
  const {
    messages,
    sendMessage,
    typingUsers,
    setTypingIndicator,
    isConnected,
    unreadCount,
    markAsRead,
    messageEndRef,
  } = useChat(roomId, userId, token);

  // Handle sending a message
  const handleSendMessage = (e) => {
    e.preventDefault();
    if (!message.trim()) return;
    
    sendMessage(message);
    setMessage('');
  };

  // Mark messages as read when scrolled to bottom
  const handleScroll = () => {
    if (!messageContainerRef.current) return;
    
    const { scrollTop, scrollHeight, clientHeight } = messageContainerRef.current;
    const isNearBottom = scrollHeight - scrollTop - clientHeight < 100;
    
    if (isNearBottom && messages.length > 0) {
      const lastMessage = messages[messages.length - 1];
      if (lastMessage && !lastMessage.readBy?.[userId]) {
        markAsRead(lastMessage.id);
      }
    }
  };

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    if (messageContainerRef.current) {
      messageContainerRef.current.scrollTop = messageContainerRef.current.scrollHeight;
    }
  }, [messages]);

  // Mark messages as read when component mounts
  useEffect(() => {
    if (messages.length > 0) {
      const lastMessage = messages[messages.length - 1];
      if (lastMessage && !lastMessage.readBy?.[userId]) {
        markAsRead(lastMessage.id);
      }
    }
  }, [messages, userId, markAsRead]);

  // Typing indicator
  const handleTyping = () => {
    if (message) {
      setTypingIndicator(true);
    } else {
      setTypingIndicator(false);
    }
  };

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Chat header */}
      <Paper 
        elevation={1} 
        sx={{ 
          p: 2, 
          display: 'flex', 
          alignItems: 'center',
          borderBottom: '1px solid #e0e0e0',
          bgcolor: 'background.paper',
        }}
      >
        <Badge 
          color="success" 
          variant="dot" 
          invisible={!isConnected}
          anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
          sx={{ mr: 2 }}
        >
          <Avatar sx={{ bgcolor: 'primary.main' }}>
            <PersonIcon />
          </Avatar>
        </Badge>
        <Box sx={{ flex: 1 }}>
          <Typography variant="subtitle1" fontWeight="medium">
            {roomId}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {typingUsers.length > 0 
              ? `${typingUsers.join(', ')} ${typingUsers.length === 1 ? 'is' : 'are'} typing...`
              : isConnected ? 'Online' : 'Connecting...'}
          </Typography>
        </Box>
      </Paper>

      {/* Messages container */}
      <Box 
        ref={messageContainerRef}
        onScroll={handleScroll}
        sx={{
          flex: 1,
          overflowY: 'auto',
          p: 2,
          bgcolor: 'background.default',
          '&::-webkit-scrollbar': {
            width: '6px',
          },
          '&::-webkit-scrollbar-track': {
            background: '#f1f1f1',
          },
          '&::-webkit-scrollbar-thumb': {
            background: '#888',
            borderRadius: '3px',
          },
          '&::-webkit-scrollbar-thumb:hover': {
            background: '#555',
          },
        }}
      >
        <List sx={{ width: '100%' }}>
          {messages.map((msg, index) => (
            <React.Fragment key={msg.id || index}>
              <ListItem 
                alignItems="flex-start"
                sx={{
                  flexDirection: msg.isOwn ? 'row-reverse' : 'row',
                  pl: msg.isOwn ? 8 : 2,
                  pr: msg.isOwn ? 2 : 8,
                }}
              >
                <ListItemAvatar sx={{ minWidth: 40, alignSelf: 'flex-end' }}>
                  <Avatar 
                    sx={{ 
                      width: 32, 
                      height: 32,
                      bgcolor: msg.isOwn ? 'primary.main' : 'grey.500',
                      fontSize: '0.8rem',
                    }}
                  >
                    {msg.sender_name?.charAt(0) || 'U'}
                  </Avatar>
                </ListItemAvatar>
                <Box 
                  sx={{
                    maxWidth: '70%',
                    bgcolor: msg.isOwn ? 'primary.light' : 'grey.100',
                    color: msg.isOwn ? 'primary.contrastText' : 'text.primary',
                    p: 1.5,
                    borderRadius: 2,
                    position: 'relative',
                    wordBreak: 'break-word',
                    '&:after': {
                      content: '""',
                      position: 'absolute',
                      bottom: 0,
                      left: msg.isOwn ? 'auto' : '-8px',
                      right: msg.isOwn ? '-8px' : 'auto',
                      width: 0,
                      height: 0,
                      border: '8px solid transparent',
                      borderTopColor: msg.isOwn ? 'primary.light' : 'grey.100',
                      borderBottom: 0,
                      marginLeft: 'auto',
                      marginRight: 'auto',
                      transform: msg.isOwn 
                        ? 'rotate(45deg) translateX(-4px)' 
                        : 'rotate(-45deg) translateX(4px)',
                    },
                  }}
                >
                  {!msg.isOwn && (
                    <Typography 
                      variant="caption" 
                      sx={{ 
                        display: 'block', 
                        fontWeight: 'bold',
                        mb: 0.5,
                      }}
                    >
                      {msg.sender_name || 'Unknown User'}
                    </Typography>
                  )}
                  <Typography variant="body2">{msg.content}</Typography>
                  <Box 
                    sx={{ 
                      display: 'flex', 
                      justifyContent: 'flex-end',
                      alignItems: 'center',
                      mt: 0.5,
                    }}
                  >
                    <Typography 
                      variant="caption" 
                      sx={{ 
                        fontSize: '0.65rem',
                        opacity: 0.8,
                        mr: 0.5,
                      }}
                    >
                      {format(new Date(msg.timestamp), 'h:mm a')}
                    </Typography>
                    {msg.isOwn && (
                      <Box sx={{ display: 'flex', alignItems: 'center' }}>
                        {msg.readBy && Object.keys(msg.readBy).length > 0 ? (
                          <Typography 
                            variant="caption" 
                            sx={{ 
                              fontSize: '0.6rem',
                              opacity: 0.7,
                            }}
                          >
                            Read
                          </Typography>
                        ) : (
                          <Typography 
                            variant="caption" 
                            sx={{ 
                              fontSize: '0.6rem',
                              opacity: 0.5,
                            }}
                          >
                            Sent
                          </Typography>
                        )}
                      </Box>
                    )}
                  </Box>
                </Box>
              </ListItem>
              {index < messages.length - 1 && <Divider variant="inset" component="li" />}
            </React.Fragment>
          ))}
          <div ref={messageEndRef} />
        </List>
      </Box>

      {/* Message input */}
      <Paper 
        component="form" 
        onSubmit={handleSendMessage}
        elevation={2}
        sx={{ 
          p: 2, 
          display: 'flex', 
          alignItems: 'center',
          borderTop: '1px solid #e0e0e0',
          bgcolor: 'background.paper',
        }}
      >
        <TextField
          fullWidth
          variant="outlined"
          placeholder="Type a message..."
          value={message}
          onChange={(e) => {
            setMessage(e.target.value);
            handleTyping();
          }}
          onFocus={() => setTypingIndicator(true)}
          onBlur={() => setTypingIndicator(false)}
          size="small"
          disabled={!isConnected}
          InputProps={{
            sx: {
              borderRadius: 4,
              bgcolor: 'background.default',
              '& fieldset': {
                borderColor: 'divider',
              },
              '&:hover fieldset': {
                borderColor: 'primary.main',
              },
              '&.Mui-focused fieldset': {
                borderColor: 'primary.main',
              },
            },
          }}
        />
        <Button
          type="submit"
          variant="contained"
          color="primary"
          disabled={!message.trim() || !isConnected}
          sx={{ 
            ml: 1.5, 
            borderRadius: 4,
            minWidth: '48px',
            width: '48px',
            height: '40px',
          }}
        >
          {isConnected ? <SendIcon /> : <CircularProgress size={20} color="inherit" />}
        </Button>
      </Paper>
    </Box>
  );
};

export default ChatInterface;
