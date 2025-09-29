import React, { createContext, useContext, useEffect, useRef, ReactNode, useCallback } from 'react';
import { io, Socket } from 'socket.io-client';
import { useSnackbar } from 'notistack';
import { useAuth } from './AuthContext';

interface WebSocketContextType {
  socket: Socket | null;
  isConnected: boolean;
  sendMessage: (event: string, data: any) => void;
  subscribe: (event: string, callback: (data: any) => void) => void;
  unsubscribe: (event: string) => void;
}

const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined);

const SOCKET_SERVER_URL = process.env.REACT_APP_WS_URL || 'ws://localhost:8000';

export const WebSocketProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const { token, isAuthenticated } = useAuth();
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const socketRef = useRef<Socket | null>(null);
  const { enqueueSnackbar } = useSnackbar();
  const eventHandlers = useRef<Map<string, (data: any) => void>>(new Map());

  // Initialize WebSocket connection
  useEffect(() => {
    if (!isAuthenticated || !token) {
      return;
    }

    // Initialize socket connection
    const socket = io(SOCKET_SERVER_URL, {
      auth: { token },
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      timeout: 10000,
    });

    socketRef.current = socket;

    // Connection established
    socket.on('connect', () => {
      console.log('WebSocket connected');
      setIsConnected(true);
    });

    // Connection error
    socket.on('connect_error', (error) => {
      console.error('WebSocket connection error:', error);
      enqueueSnackbar('Connection error. Reconnecting...', { variant: 'error' });
    });

    // Handle incoming messages
    socket.on('notification', (data) => {
      console.log('Received notification:', data);
      // Handle different types of notifications
      if (data.type === 'moderation_action') {
        enqueueSnackbar(data.message, { variant: data.severity || 'info' });
      }
      // Call any registered handlers for this event
      const handler = eventHandlers.current.get('notification');
      if (handler) {
        handler(data);
      }
    });

    // Handle moderation events
    const moderationEvents = [
      'content_flagged',
      'moderation_review_created',
      'moderation_action_taken',
      'appeal_created',
      'appeal_processed',
    ];

    moderationEvents.forEach((event) => {
      socket.on(event, (data) => {
        console.log(`Received ${event}:`, data);
        const handler = eventHandlers.current.get(event);
        if (handler) {
          handler(data);
        }
      });
    });

    // Cleanup on unmount
    return () => {
      if (socket) {
        socket.disconnect();
        setIsConnected(false);
      }
    };
  }, [isAuthenticated, token, enqueueSnackbar]);

  // Send message through WebSocket
  const sendMessage = useCallback((event: string, data: any) => {
    if (socketRef.current && isConnected) {
      socketRef.current.emit(event, data);
    } else {
      console.warn('WebSocket not connected');
      enqueueSnackbar('Not connected to server', { variant: 'warning' });
    }
  }, [isConnected, enqueueSnackbar]);

  // Subscribe to an event
  const subscribe = useCallback((event: string, callback: (data: any) => void) => {
    eventHandlers.current.set(event, callback);
    
    return () => {
      eventHandlers.current.delete(event);
    };
  }, []);

  // Unsubscribe from an event
  const unsubscribe = useCallback((event: string) => {
    eventHandlers.current.delete(event);
  }, []);

  const value = {
    socket: socketRef.current,
    isConnected,
    sendMessage,
    subscribe,
    unsubscribe,
  };

  return (
    <WebSocketContext.Provider value={value}>
      {children}
    </WebSocketContext.Provider>
  );
};

export const useWebSocket = (): WebSocketContextType => {
  const context = useContext(WebSocketContext);
  if (context === undefined) {
    throw new Error('useWebSocket must be used within a WebSocketProvider');
  }
  return context;
};

export default WebSocketContext;
