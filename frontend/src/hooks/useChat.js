import { useState, useEffect, useCallback, useRef } from 'react';
import { format } from 'date-fns';
import { io } from 'socket.io-client';

const useChat = (roomId, userId, token) => {
  const [messages, setMessages] = useState([]);
  const [typingUsers, setTypingUsers] = useState(new Set());
  const [isConnected, setIsConnected] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);
  const socketRef = useRef(null);
  const messageEndRef = useRef(null);
  const typingTimeoutRef = useRef(null);

  // Scroll to bottom of messages
  const scrollToBottom = () => {
    messageEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  // Initialize WebSocket connection
  useEffect(() => {
    if (!roomId || !userId || !token) return;

    // Connect to WebSocket server
    socketRef.current = io(process.env.REACT_APP_WS_URL, {
      auth: { token },
      query: { roomId, userId },
      transports: ['websocket'],
    });

    // Connection established
    socketRef.current.on('connect', () => {
      console.log('Connected to chat server');
      setIsConnected(true);
      
      // Join the room
      socketRef.current.emit('join_room', { roomId, userId });
      
      // Fetch message history
      fetchMessageHistory();
    });

    // Handle new messages
    socketRef.current.on('new_message', (message) => {
      setMessages((prev) => [...prev, formatMessage(message)]);
      scrollToBottom();
    });

    // Handle typing status updates
    socketRef.current.on('typing_status', ({ users }) => {
      setTypingUsers(new Set(users));
    });

    // Handle read receipts
    socketRef.current.on('read_receipt', ({ messageId, userId, readAt }) => {
      setMessages((prev) =>
        prev.map((msg) =>
          msg.id === messageId
            ? {
                ...msg,
                readBy: { ...msg.readBy, [userId]: new Date(readAt) },
              }
            : msg
        )
      );
    });

    // Handle disconnection
    socketRef.current.on('disconnect', () => {
      console.log('Disconnected from chat server');
      setIsConnected(false);
    });

    // Clean up on unmount
    return () => {
      if (socketRef.current) {
        socketRef.current.disconnect();
      }
      if (typingTimeoutRef.current) {
        clearTimeout(typingTimeoutRef.current);
      }
    };
  }, [roomId, userId, token]);

  // Format message for display
  const formatMessage = (message) => ({
    ...message,
    timestamp: new Date(message.timestamp),
    formattedTime: format(new Date(message.timestamp), 'h:mm a'),
    isOwn: message.sender_id === userId,
  });

  // Fetch message history
  const fetchMessageHistory = useCallback(async () => {
    try {
      const response = await fetch(
        `${process.env.REACT_APP_API_URL}/messages/${roomId}?limit=50`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );
      
      if (!response.ok) throw new Error('Failed to fetch messages');
      
      const data = await response.json();
      setMessages(data.map(formatMessage));
      scrollToBottom();
    } catch (error) {
      console.error('Error fetching message history:', error);
    }
  }, [roomId, token]);

  // Send a new message
  const sendMessage = useCallback(
    (content) => {
      if (!socketRef.current || !content.trim()) return;
      
      socketRef.current.emit('send_message', {
        roomId,
        content: content.trim(),
        senderId: userId,
      });
      
      // Reset typing status after sending a message
      setTypingIndicator(false);
    },
    [roomId, userId]
  );

  // Set typing indicator
  const setTypingIndicator = useCallback(
    (isTyping) => {
      if (!socketRef.current) return;
      
      // Clear any existing timeout
      if (typingTimeoutRef.current) {
        clearTimeout(typingTimeoutRef.current);
      }
      
      // Set a new timeout to stop typing after 3 seconds of inactivity
      if (isTyping) {
        typingTimeoutRef.current = setTimeout(() => {
          setTypingIndicator(false);
        }, 3000);
      }
      
      socketRef.current.emit('typing', {
        roomId,
        isTyping,
      });
    },
    [roomId]
  );

  // Mark messages as read
  const markAsRead = useCallback(
    (messageId) => {
      if (!socketRef.current) return;
      
      socketRef.current.emit('read_receipt', {
        messageId,
        roomId,
      });
      
      // Update unread count
      setUnreadCount(0);
    },
    [roomId]
  );

  return {
    messages,
    sendMessage,
    typingUsers: Array.from(typingUsers),
    setTypingIndicator,
    isConnected,
    unreadCount,
    markAsRead,
    messageEndRef,
  };
};

export default useChat;
