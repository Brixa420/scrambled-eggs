import React from 'react';
import '../styles/loading-spinner.css';

const LoadingSpinner = ({ size = 'md', className = '' }) => {
  const sizeClasses = {
    sm: 'h-4 w-4 border-2',
    md: 'h-8 w-8 border-2',
    lg: 'h-12 w-12 border-4',
  };

  return (
    <div className={`flex items-center justify-center ${className}`}>
      <div
        className={`animate-spin rounded-full border-t-2 border-b-2 border-blue-500 ${
          sizeClasses[size] || sizeClasses.md
        }`}
      ></div>
      <span className="sr-only">Loading...</span>
    </div>
  );
};

export default LoadingSpinner;
