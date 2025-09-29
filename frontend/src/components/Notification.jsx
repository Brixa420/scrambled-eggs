import React, { useEffect, useState } from 'react';
import { Snackbar, Alert, Slide, Fade } from '@mui/material';

const Notification = ({ notification, onClose }) => {
  const [open, setOpen] = useState(!!notification);

  useEffect(() => {
    setOpen(!!notification);
  }, [notification]);

  const handleClose = (event, reason) => {
    if (reason === 'clickaway') {
      return;
    }
    setOpen(false);
    if (onClose) {
      // Small delay to allow the animation to complete
      setTimeout(() => onClose(notification?.id), 300);
    }
  };

  if (!notification) return null;

  const { type = 'info', message, duration = 5000 } = notification;

  return (
    <Snackbar
      open={open}
      autoHideDuration={duration}
      onClose={handleClose}
      anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      TransitionComponent={Slide}
      TransitionProps={{ direction: 'left' }}
      sx={{
        '& .MuiPaper-root': {
          minWidth: '280px',
        },
      }}
    >
      <Fade in={open}>
        <Alert 
          onClose={handleClose} 
          severity={type}
          variant="filled"
          sx={{
            width: '100%',
            boxShadow: 3,
            '& .MuiAlert-message': {
              fontWeight: 500,
            },
          }}
        >
          {message}
        </Alert>
      </Fade>
    </Snackbar>
  );
};

export default Notification;
