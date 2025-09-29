import React, { createContext, useState, useCallback, useRef } from 'react';
import { v4 as uuidv4 } from 'uuid';

export const NotificationContext = createContext();

export const NotificationProvider = ({ children }) => {
  const [notifications, setNotifications] = useState([]);
  const notificationTimeoutRef = useRef({});

  const removeNotification = useCallback((id) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
    
    // Clear any existing timeout for this notification
    if (notificationTimeoutRef.current[id]) {
      clearTimeout(notificationTimeoutRef.current[id]);
      delete notificationTimeoutRef.current[id];
    }
  }, []);

  const addNotification = useCallback(({ 
    message, 
    type = 'info', 
    duration = 5000,
    autoDismiss = true,
    action,
    actionLabel = 'Undo'
  }) => {
    const id = uuidv4();
    const newNotification = { 
      id, 
      message, 
      type, 
      duration,
      action,
      actionLabel,
      timestamp: Date.now()
    };

    setNotifications(prev => [...prev, newNotification]);

    // Set auto-dismiss timeout if enabled
    if (autoDismiss && duration > 0) {
      notificationTimeoutRef.current[id] = setTimeout(() => {
        removeNotification(id);
      }, duration);
    }

    return id;
  }, [removeNotification]);

  const clearAllNotifications = useCallback(() => {
    // Clear all timeouts
    Object.values(notificationTimeoutRef.current).forEach(clearTimeout);
    notificationTimeoutRef.current = {};
    setNotifications([]);
  }, []);

  const contextValue = {
    notifications,
    addNotification,
    removeNotification,
    clearAllNotifications,
  };

  return (
    <NotificationContext.Provider value={contextValue}>
      {children}
    </NotificationContext.Provider>
  );
};
