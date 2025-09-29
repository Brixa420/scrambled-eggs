import { useEffect, useCallback } from 'react';
import { useWebSocket } from '../contexts/WebSocketContext';

/**
 * Hook to subscribe to moderation-related WebSocket events
 * @param {Object} options - Configuration options
 * @param {Function} [options.onContentReported] - Callback for when content is reported
 * @param {Function} [options.onModerationAction] - Callback for when a moderation action is taken
 * @param {Function} [options.onAppealUpdated] - Callback for when an appeal is updated
 * @param {Function} [options.onModerationQueueUpdate] - Callback for when the moderation queue is updated
 * @returns {Object} WebSocket utilities
 */
export const useModerationWebSocket = ({
  onContentReported,
  onModerationAction,
  onAppealUpdated,
  onModerationQueueUpdate,
} = {}) => {
  const { socket, isConnected, subscribeToModerationEvents } = useWebSocket();

  // Handle content reported events
  useEffect(() => {
    if (!socket || !onContentReported) return;

    const handler = (data) => {
      onContentReported(data);
    };

    socket.on('content_reported', handler);
    return () => {
      socket.off('content_reported', handler);
    };
  }, [socket, onContentReported]);

  // Handle moderation action events
  useEffect(() => {
    if (!socket || !onModerationAction) return;

    const handler = (data) => {
      onModerationAction(data);
    };

    socket.on('moderation_action', handler);
    return () => {
      socket.off('moderation_action', handler);
    };
  }, [socket, onModerationAction]);

  // Handle appeal updated events
  useEffect(() => {
    if (!socket || !onAppealUpdated) return;

    const handler = (data) => {
      onAppealUpdated(data);
    };

    socket.on('appeal_updated', handler);
    return () => {
      socket.off('appeal_updated', handler);
    };
  }, [socket, onAppealUpdated]);

  // Handle moderation queue updates
  useEffect(() => {
    if (!socket || !onModerationQueueUpdate) return;

    const handler = (data) => {
      onModerationQueueUpdate(data);
    };

    socket.on('moderation_queue_update', handler);
    return () => {
      socket.off('moderation_queue_update', handler);
    };
  }, [socket, onModerationQueueUpdate]);

  // Function to report content
  const reportContent = useCallback(async (contentId, contentType, reason, context = {}) => {
    if (!socket) throw new Error('WebSocket is not connected');
    
    return new Promise((resolve, reject) => {
      socket.emit('report_content', 
        { contentId, contentType, reason, context },
        (response) => {
          if (response?.error) {
            reject(new Error(response.error));
          } else {
            resolve(response);
          }
        }
      );
    });
  }, [socket]);

  // Function to take moderation action
  const takeModerationAction = useCallback(async (actionType, targetUserId, reason, options = {}) => {
    if (!socket) throw new Error('WebSocket is not connected');
    
    return new Promise((resolve, reject) => {
      socket.emit('take_moderation_action', 
        { actionType, targetUserId, reason, ...options },
        (response) => {
          if (response?.error) {
            reject(new Error(response.error));
          } else {
            resolve(response);
          }
        }
      );
    });
  }, [socket]);

  // Function to update appeal status
  const updateAppealStatus = useCallback(async (appealId, status, decision = '') => {
    if (!socket) throw new Error('WebSocket is not connected');
    
    return new Promise((resolve, reject) => {
      socket.emit('update_appeal_status', 
        { appealId, status, decision },
        (response) => {
          if (response?.error) {
            reject(new Error(response.error));
          } else {
            resolve(response);
          }
        }
      );
    });
  }, [socket]);

  // Function to subscribe to a specific content's moderation events
  const subscribeToContentModeration = useCallback((contentId, callback) => {
    if (!socket) return () => {};
    
    const room = `content:${contentId}`;
    socket.emit('join_room', { room });
    
    const handler = (data) => {
      if (data.contentId === contentId) {
        callback(data);
      }
    };
    
    socket.on('content_moderation_update', handler);
    
    return () => {
      socket.off('content_moderation_update', handler);
      socket.emit('leave_room', { room });
    };
  }, [socket]);

  return {
    isConnected,
    reportContent,
    takeModerationAction,
    updateAppealStatus,
    subscribeToContentModeration,
  };
};

/**
 * Hook to subscribe to real-time moderation queue updates
 * @param {Function} onUpdate - Callback when the queue is updated
 * @returns {Object} Queue utilities
 */
export const useModerationQueue = (onUpdate) => {
  const { isConnected, subscribeToModerationEvents } = useWebSocket();

  useEffect(() => {
    if (!isConnected || !onUpdate) return;
    
    const unsubscribe = subscribeToModerationEvents((event) => {
      if (event.type === 'queue_update') {
        onUpdate(event.data);
      }
    });
    
    return () => {
      if (unsubscribe) unsubscribe();
    };
  }, [isConnected, onUpdate, subscribeToModerationEvents]);

  return { isConnected };
};

/**
 * Hook to subscribe to real-time moderation actions for a specific user
 * @param {string} userId - The ID of the user to monitor
 * @param {Function} onAction - Callback when a moderation action is taken
 * @returns {Object} Action utilities
 */
export const useUserModerationActions = (userId, onAction) => {
  const { isConnected, subscribeToModerationEvents } = useWebSocket();

  useEffect(() => {
    if (!isConnected || !userId || !onAction) return;
    
    const unsubscribe = subscribeToModerationEvents((event) => {
      if (event.type === 'moderation_action' && event.data.targetUserId === userId) {
        onAction(event.data);
      }
    });
    
    return () => {
      if (unsubscribe) unsubscribe();
    };
  }, [isConnected, userId, onAction, subscribeToModerationEvents]);

  return { isConnected };
};
