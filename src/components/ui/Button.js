import React from 'react';
import { motion } from 'framer-motion';
import { Loader2 } from 'lucide-react';

const buttonVariants = {
  initial: {
    scale: 1,
    opacity: 1,
  },
  tap: {
    scale: 0.95,
  },
  hover: {
    scale: 1.03,
  },
};

const Button = ({
  children,
  variant = 'primary',
  size = 'md',
  isLoading = false,
  disabled = false,
  fullWidth = false,
  startIcon,
  endIcon,
  className = '',
  ...props
}) => {
  const baseClasses = 'inline-flex items-center justify-center rounded-lg font-medium transition-all focus:outline-none focus:ring-2 focus:ring-offset-2 disabled:opacity-50 disabled:pointer-events-none';
  
  const variantClasses = {
    primary: 'bg-primary-600 text-white hover:bg-primary-700 focus:ring-primary-500',
    secondary: 'bg-secondary-600 text-white hover:bg-secondary-700 focus:ring-secondary-500',
    outline: 'border border-gray-300 bg-transparent text-gray-700 hover:bg-gray-50 focus:ring-primary-500 dark:border-gray-600 dark:text-gray-200 dark:hover:bg-gray-700',
    ghost: 'bg-transparent text-gray-700 hover:bg-gray-100 focus:ring-gray-500 dark:text-gray-200 dark:hover:bg-gray-800',
    danger: 'bg-red-600 text-white hover:bg-red-700 focus:ring-red-500',
    success: 'bg-green-600 text-white hover:bg-green-700 focus:ring-green-500',
  };
  
  const sizeClasses = {
    sm: 'px-3 py-1.5 text-sm',
    md: 'px-4 py-2 text-base',
    lg: 'px-6 py-3 text-lg',
  };
  
  const widthClass = fullWidth ? 'w-full' : '';
  
  return (
    <motion.button
      className={`${baseClasses} ${variantClasses[variant]} ${sizeClasses[size]} ${widthClass} ${className}`}
      disabled={disabled || isLoading}
      variants={buttonVariants}
      initial="initial"
      whileHover={!disabled && !isLoading ? "hover" : {}}
      whileTap={!disabled && !isLoading ? "tap" : {}}
      {...props}
    >
      {isLoading && <Loader2 className="animate-spin mr-2 h-4 w-4" />}
      {!isLoading && startIcon && <span className="mr-2">{startIcon}</span>}
      {children}
      {!isLoading && endIcon && <span className="ml-2">{endIcon}</span>}
    </motion.button>
  );
};

export default Button;
