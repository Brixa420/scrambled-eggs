import React from 'react';
import { motion } from 'framer-motion';

const Card = ({
  children,
  className = '',
  hoverable = false,
  noPadding = false,
  ...props
}) => {
  return (
    <motion.div
      className={`bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden ${
        hoverable ? 'hover:shadow-md transition-shadow duration-200' : ''
      } ${!noPadding ? 'p-6' : ''} ${className}`}
      whileHover={hoverable ? { y: -2 } : {}}
      {...props}
    >
      {children}
    </motion.div>
  );
};

const CardHeader = ({ children, className = '', ...props }) => (
  <div className={`border-b border-gray-200 dark:border-gray-700 px-6 py-4 ${className}`} {...props}>
    {children}
  </div>
);

const CardBody = ({ children, className = '', ...props }) => (
  <div className={`p-6 ${className}`} {...props}>
    {children}
  </div>
);

const CardFooter = ({ children, className = '', ...props }) => (
  <div className={`bg-gray-50 dark:bg-gray-700/50 px-6 py-4 ${className}`} {...props}>
    {children}
  </div>
);

export { Card, CardHeader, CardBody, CardFooter };
