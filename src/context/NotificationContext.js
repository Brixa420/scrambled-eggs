import React, { createContext, useContext, useCallback } from 'react';
import NotificationService from '../services/NotificationService';

const NotificationContext = createContext(null);

export const NotificationProvider = ({ children }) => {
  const notify = useCallback((type, message, options = {}) => {
    switch (type) {
      case 'success':
        return NotificationService.success(message, options);
      case 'error':
        return NotificationService.error(message, options);
      case 'info':
        return NotificationService.info(message, options);
      case 'warning':
        return NotificationService.warning(message, options);
      default:
        return NotificationService.info(message, options);
    }
  }, []);

  const dismissNotification = useCallback((toastId) => {
    NotificationService.dismiss(toastId);
  }, []);

  const dismissAllNotifications = useCallback(() => {
    NotificationService.dismissAll();
  }, []);

  return (
    <NotificationContext.Provider
      value={{
        notify,
        dismissNotification,
        dismissAllNotifications,
      }}
    >
      {children}
    </NotificationContext.Provider>
  );
};

export const useNotification = () => {
  const context = useContext(NotificationContext);
  if (!context) {
    throw new Error('useNotification must be used within a NotificationProvider');
  }
  return context;
};
