import React, { createContext, useContext, useEffect, useRef, useCallback } from 'react';
import { io } from 'socket.io-client';
import { useAuth } from './AuthContext';
import { useSnackbar } from 'notistack';
import { useNavigate } from 'react-router-dom';
import api from '../services/api';

const WebSocketContext = createContext(null);

export const WebSocketProvider = ({ children }) => {
  const { user, isAuthenticated, getAccessToken } = useAuth();
  const { enqueueSnackbar } = useSnackbar();
  const navigate = useNavigate();
  const socketRef = useRef(null);
  const reconnectAttempts = useRef(0);
  const maxReconnectAttempts = 5;
  const reconnectTimeout = useRef(null);

  // Initialize WebSocket connection
  const connect = useCallback(() => {
    if (socketRef.current?.connected) return;

    const token = getAccessToken();
    if (!token) return;

    // Clear any existing reconnection attempts
    if (reconnectTimeout.current) {
      clearTimeout(reconnectTimeout.current);
      reconnectTimeout.current = null;
    }

    // Initialize socket connection
    socketRef.current = io(process.env.REACT_APP_WS_URL || window.location.origin, {
      path: '/ws',
      query: { token },
      reconnection: true,
      reconnectionAttempts: maxReconnectAttempts,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      timeout: 20000,
      autoConnect: true,
      transports: ['websocket', 'polling'],
    });

    // Connection established
    socketRef.current.on('connect', () => {
      console.log('WebSocket connected');
      reconnectAttempts.current = 0; // Reset reconnect attempts on successful connection
      
      // Join user-specific room
      if (user?.id) {
        socketRef.current.emit('join_user_room', { userId: user.id });
      }
      
      // If user is a moderator, join the moderators room
      if (user?.isModerator || user?.isAdmin) {
        socketRef.current.emit('join_moderation_room', { room: 'moderators' });
      }
    });

    // Handle connection errors
    socketRef.current.on('connect_error', (error) => {
      console.error('WebSocket connection error:', error);
      
      // Only show error if we're not in a reconnection attempt
      if (reconnectAttempts.current === 0) {
        enqueueSnackbar('Connection error. Attempting to reconnect...', { 
          variant: 'error',
          autoHideDuration: 5000,
        });
      }
      
      // Attempt to reconnect with exponential backoff
      if (reconnectAttempts.current < maxReconnectAttempts) {
        const delay = Math.min(1000 * Math.pow(2, reconnectAttempts.current), 30000);
        reconnectAttempts.current++;
        
        reconnectTimeout.current = setTimeout(() => {
          console.log(`Reconnection attempt ${reconnectAttempts.current}/${maxReconnectAttempts}`);
          connect();
        }, delay);
      } else {
        enqueueSnackbar('Unable to connect to server. Please refresh the page.', { 
          variant: 'error',
          persist: true,
        });
      }
    });

    // Handle disconnection
    socketRef.current.on('disconnect', (reason) => {
      console.log(`WebSocket disconnected: ${reason}`);
      
      if (reason === 'io server disconnect') {
        // The server has forcefully disconnected the socket
        // Attempt to reconnect after a short delay
        reconnectTimeout.current = setTimeout(() => {
          connect();
        }, 1000);
      }
    });

    // Handle moderation events
    socketRef.current.on('moderation_action_taken', (data) => {
      console.log('Moderation action taken:', data);
      
      const actionMessages = {
        warning: 'You have received a warning',
        suspension: 'Your account has been suspended',
        ban: 'Your account has been banned',
      };
      
      const message = actionMessages[data.action_type] || 'A moderation action has been taken on your account';
      const severity = data.action_type === 'warning' ? 'warning' : 'error';
      
      enqueueSnackbar(message, { 
        variant: severity,
        persist: severity === 'error',
        action: severity === 'error' ? (
          <Button 
            color="inherit" 
            size="small"
            onClick={() => navigate('/appeal')}
          >
            Appeal
          </Button>
        ) : null,
      });
      
      // If banned, redirect to home page
      if (data.action_type === 'ban') {
        navigate('/');
      }
    });
    
    // Handle appeal updates
    socketRef.current.on('appeal_updated', (data) => {
      console.log('Appeal updated:', data);
      
      const statusMessages = {
        pending: 'Your appeal has been submitted and is under review',
        approved: 'Your appeal has been approved',
        denied: 'Your appeal has been denied',
      };
      
      const message = statusMessages[data.status] || `Your appeal status has been updated to: ${data.status}`;
      const severity = {
        pending: 'info',
        approved: 'success',
        denied: 'error',
      }[data.status] || 'info';
      
      enqueueSnackbar(message, { 
        variant: severity,
        autoHideDuration: 5000,
      });
    });
    
    // Handle content review requests (for moderators)
    socketRef.current.on('content_review_needed', (data) => {
      console.log('Content review needed:', data);
      
      if (user?.isModerator || user?.isAdmin) {
        enqueueSnackbar(
          `New ${data.content_type} reported for review`,
          { 
            variant: 'info',
            action: (
              <Button 
                color="inherit" 
                size="small"
                onClick={() => navigate(`/moderation/review/${data.content_type}/${data.content_id}`)}
              >
                Review
              </Button>
            ),
          }
        );
      }
    });

    // Handle errors from the server
    socketRef.current.on('error', (error) => {
      console.error('WebSocket error:', error);
      enqueueSnackbar(error.message || 'An error occurred', { variant: 'error' });
    });

    return () => {
      if (socketRef.current) {
        socketRef.current.disconnect();
        socketRef.current = null;
      }
      if (reconnectTimeout.current) {
        clearTimeout(reconnectTimeout.current);
        reconnectTimeout.current = null;
      }
    };
  }, [user, getAccessToken, enqueueSnackbar, navigate]);

  // Connect on mount and when auth state changes
  useEffect(() => {
    if (isAuthenticated && user) {
      connect();
    }
    
    return () => {
      if (socketRef.current) {
        socketRef.current.disconnect();
        socketRef.current = null;
      }
      if (reconnectTimeout.current) {
        clearTimeout(reconnectTimeout.current);
        reconnectTimeout.current = null;
      }
    };
  }, [isAuthenticated, user, connect]);

  // Reconnect when token is refreshed
  useEffect(() => {
    if (isAuthenticated && socketRef.current?.disconnected) {
      connect();
    }
  }, [isAuthenticated, getAccessToken, connect]);

  // Function to emit events
  const emitEvent = useCallback((event, data = {}, callback) => {
    if (!socketRef.current?.connected) {
      console.error('WebSocket is not connected');
      return false;
    }
    
    return new Promise((resolve, reject) => {
      socketRef.current.emit(event, data, (response) => {
        if (response?.error) {
          reject(new Error(response.error));
        } else {
          resolve(response);
        }
      });
    });
  }, []);

  // Function to subscribe to a room
  const subscribeToRoom = useCallback((room, callback) => {
    if (!socketRef.current?.connected) {
      console.error('WebSocket is not connected');
      return false;
    }
    
    socketRef.current.emit('join_room', { room });
    
    const eventHandler = (data) => {
      if (data.room === room) {
        callback(data);
      }
    };
    
    socketRef.current.on('room_message', eventHandler);
    
    // Return cleanup function
    return () => {
      if (socketRef.current) {
        socketRef.current.off('room_message', eventHandler);
        socketRef.current.emit('leave_room', { room });
      }
    };
  }, []);
  
  // Function to subscribe to moderation events
  const subscribeToModerationEvents = useCallback((callback) => {
    if (!socketRef.current?.connected) {
      console.error('WebSocket is not connected');
      return () => {};
    }
    
    const eventHandler = (data) => {
      callback(data);
    };
    
    socketRef.current.on('moderation_event', eventHandler);
    
    // Return cleanup function
    return () => {
      if (socketRef.current) {
        socketRef.current.off('moderation_event', eventHandler);
      }
    };
  }, []);

  const value = {
    socket: socketRef.current,
    isConnected: socketRef.current?.connected || false,
    emit: emitEvent,
    subscribeToRoom,
    subscribeToModerationEvents,
  };

  return (
    <WebSocketContext.Provider value={value}>
      {children}
    </WebSocketContext.Provider>
  );
};

export const useWebSocket = () => {
  const context = useContext(WebSocketContext);
  if (!context) {
    throw new Error('useWebSocket must be used within a WebSocketProvider');
  }
  return context;
};

export default WebSocketContext;
