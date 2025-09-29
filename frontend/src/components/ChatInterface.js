import React, { useState, useEffect, useRef, useCallback, useContext } from 'react';
import { format } from 'date-fns';
import { 
  Paper, 
  TextField, 
  Button, 
  Typography, 
  Box, 
  Avatar, 
  List, 
  ListItem, 
  ListItemAvatar, 
  ListItemText, 
  Divider, 
  CircularProgress, 
  Badge,
  Fade,
  Zoom,
  Slide,
  IconButton,
  Tooltip
} from '@mui/material';
import { 
  Send as SendIcon, 
  Person as PersonIcon, 
  Keyboard as KeyboardIcon,
  Notifications as NotificationsIcon,
  Close as CloseIcon
} from '@mui/icons-material';
import useChat from '../hooks/useChat';
import { MessageSkeleton } from './Skeleton';
import useKeyboardShortcuts from '../hooks/useKeyboardShortcuts';
import { NotificationContext } from '../contexts/NotificationContext';

const ChatInterface = ({ roomId, userId, token, userName, isLoading = false }) => {
  const { addNotification } = useContext(NotificationContext);
  const [showShortcuts, setShowShortcuts] = useState(false);
  const inputRef = useRef(null);
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
  const handleSendMessage = useCallback((e) => {
    e?.preventDefault();
    if (!message.trim() || isLoading) return;
    
    sendMessage(message);
    setMessage('');
    
    // Focus back on input after sending
    setTimeout(() => {
      inputRef.current?.focus();
    }, 0);
  }, [message, isLoading, sendMessage]);
  
  // Keyboard shortcuts
  useKeyboardShortcuts([
    {
      key: 'Enter',
      action: handleSendMessage,
    },
    {
      key: 'Control+Enter',
      action: () => {
        setMessage(prev => prev + '\n');
      },
    },
    {
      key: 'Escape',
      action: () => {
        inputRef.current?.blur();
        setShowShortcuts(false);
      },
    },
    {
      key: 'Control+Shift+?',
      action: () => {
        setShowShortcuts(prev => !prev);
        addNotification({
          message: showShortcuts ? 'Keyboard shortcuts hidden' : 'Keyboard shortcuts shown',
          type: 'info',
          duration: 2000,
        });
      },
    },
  ]);

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
  
  // Show notification for new messages when not focused on the chat
  useEffect(() => {
    if (messages.length > 0 && document.visibilityState === 'hidden') {
      const lastMessage = messages[messages.length - 1];
      if (lastMessage && !lastMessage.isOwn) {
        addNotification({
          message: `New message from ${lastMessage.sender_name || 'a user'}`,
          type: 'info',
          duration: 5000,
          action: () => {
            // Scroll to the message when notification is clicked
            messageEndRef.current?.scrollIntoView({ behavior: 'smooth' });
          }
        });
      }
    }
  }, [messages]);

  // Typing indicator
  const handleTyping = () => {
    if (message) {
      setTypingIndicator(true);
    } else {
      setTypingIndicator(false);
    }
  };

  if (isLoading) {
    return (
      <Paper elevation={3} sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
        <MessageSkeleton count={5} />
      </Paper>
    );
  }

  return (
    <Paper elevation={3} sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
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
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography variant="subtitle1" fontWeight="medium">
              {roomId}
            </Typography>
            <Tooltip title="Keyboard shortcuts (Ctrl+Shift+/)">
              <IconButton 
                size="small" 
                onClick={() => setShowShortcuts(prev => !prev)}
                color={showShortcuts ? 'primary' : 'default'}
              >
                <KeyboardIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          </Box>
          <Typography variant="body2" color="text.secondary">
            {typingUsers.length > 0 
              ? `${typingUsers.join(', ')} ${typingUsers.length === 1 ? 'is' : 'are'} typing...`
              : isConnected ? 'Online' : 'Connecting...'}
          </Typography>
        </Box>
      </Paper>

      <Box 
        ref={messageContainerRef}
        onScroll={handleScroll}
        sx={{ 
          flex: 1, 
          overflowY: 'auto', 
          p: 2,
          '&::-webkit-scrollbar': {
            width: '8px',
          },
          '&::-webkit-scrollbar-track': {
            background: 'rgba(0,0,0,0.1)',
            borderRadius: '4px',
          },
          '&::-webkit-scrollbar-thumb': {
            background: 'rgba(0,0,0,0.2)',
            borderRadius: '4px',
            '&:hover': {
              background: 'rgba(0,0,0,0.3)',
            },
          },
        }}>
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
      
      {/* Keyboard Shortcuts Help */}
      <Slide direction="up" in={showShortcuts} mountOnEnter unmountOnExit>
        <Paper 
          elevation={3} 
          sx={{ 
            position: 'absolute', 
            bottom: '80px', 
            right: '20px', 
            p: 2, 
            maxWidth: '300px',
            zIndex: 1200,
            bgcolor: 'background.paper',
            borderRadius: 2,
          }}
        >
          <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
            <Typography variant="subtitle2" fontWeight="bold">
              Keyboard Shortcuts
            </Typography>
            <IconButton 
              size="small" 
              onClick={() => setShowShortcuts(false)}
              sx={{ ml: 1 }}
            >
              <CloseIcon fontSize="small" />
            </IconButton>
          </Box>
          <Box component="ul" sx={{ pl: 2, mb: 0, '& li': { mb: 0.5 } }}>
            <li><kbd>Enter</kbd> - Send message</li>
            <li><kbd>Ctrl</kbd> + <kbd>Enter</kbd> - New line</li>
            <li><kbd>Esc</kbd> - Close dialogs</li>
            <li><kbd>Ctrl</kbd> + <kbd>Shift</kbd> + <kbd>/</kbd> - Toggle this help</li>
          </Box>
        </Paper>
      </Slide>
      
      <Slide direction="up" in={!isLoading}>
        <Box component="form" onSubmit={handleSendMessage} sx={{ p: 2, borderTop: '1px solid', borderColor: 'divider', display: 'flex', gap: 1 }}>
          <TextField
            inputRef={inputRef}
            fullWidth
            variant="outlined"
            placeholder={
              isConnected 
                ? "Type a message... (Press Enter to send, Ctrl+Enter for new line)" 
                : "Connecting to chat..."
            }
            value={message}
            onChange={(e) => {
              setMessage(e.target.value);
              handleTyping();
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                handleSendMessage(e);
              }
            }}
            multiline
            maxRows={4}
            disabled={!isConnected}
            sx={{
              '& .MuiOutlinedInput-root': {
                borderRadius: 4,
                bgcolor: 'background.paper',
                '&:hover .MuiOutlinedInput-notchedOutline': {
                  borderColor: 'primary.main',
                },
                '&.Mui-focused .MuiOutlinedInput-notchedOutline': {
                  borderColor: 'primary.main',
                  borderWidth: '1px',
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
              minWidth: 'auto',
              width: '48px',
              height: '48px',
              borderRadius: '50%',
              boxShadow: 2,
              '&:hover': {
                boxShadow: 3,
              },
            }}
          >
            <SendIcon />
          </Button>
        </Box>
      </Slide>
    </Paper>
  );
};

export default ChatInterface;
