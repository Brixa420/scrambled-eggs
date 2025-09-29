import React from 'react';
import { Skeleton as MuiSkeleton, Box } from '@mui/material';

export const Skeleton = ({ variant = 'text', width = '100%', height = 40, animation = 'wave', ...props }) => {
  return (
    <MuiSkeleton 
      variant={variant}
      width={width}
      height={height}
      animation={animation}
      sx={{ bgcolor: 'grey.800' }}
      {...props}
    />
  );
};

export const MessageSkeleton = ({ count = 3 }) => {
  return (
    <Box sx={{ width: '100%', p: 2 }}>
      {Array.from({ length: count }).map((_, index) => (
        <Box key={index} sx={{ display: 'flex', mb: 2, gap: 2 }}>
          <Skeleton variant="circular" width={40} height={40} />
          <Box sx={{ flex: 1 }}>
            <Skeleton width="30%" height={20} sx={{ mb: 1 }} />
            <Skeleton width="70%" height={40} />
          </Box>
        </Box>
      ))}
    </Box>
  );
};

export const TypingIndicator = () => (
  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, p: 1 }}>
    <Skeleton variant="circular" width={24} height={24} />
    <Skeleton width={100} height={20} />
  </Box>
);

export default Skeleton;
