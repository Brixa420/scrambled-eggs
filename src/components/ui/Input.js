import React, { forwardRef, useState } from 'react';
import { Eye, EyeOff, AlertCircle } from 'lucide-react';

const Input = forwardRef(({
  label,
  error,
  description,
  startIcon,
  endIcon,
  type = 'text',
  className = '',
  ...props
}, ref) => {
  const [showPassword, setShowPassword] = useState(false);
  const inputType = type === 'password' && showPassword ? 'text' : type;
  const hasError = !!error;

  return (
    <div className={`space-y-1 ${className}`}>
      {label && (
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
          {label}
          {props.required && <span className="text-red-500 ml-1">*</span>}
        </label>
      )}
      
      <div className="relative rounded-md shadow-sm">
        {startIcon && (
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            {startIcon}
          </div>
        )}
        
        <input
          ref={ref}
          type={inputType}
          className={`block w-full rounded-md border ${
            hasError
              ? 'border-red-300 text-red-900 placeholder-red-300 focus:outline-none focus:ring-red-500 focus:border-red-500'
              : 'border-gray-300 dark:border-gray-600 focus:ring-primary-500 focus:border-primary-500 dark:bg-gray-700 dark:text-white'
          } ${startIcon ? 'pl-10' : 'pl-3'} ${
            type === 'password' ? 'pr-10' : endIcon ? 'pr-10' : 'pr-3'
          } py-2 text-base`}
          {...props}
        />
        
        {type === 'password' && (
          <button
            type="button"
            className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-500"
            onClick={() => setShowPassword(!showPassword)}
            tabIndex={-1}
          >
            {showPassword ? (
              <EyeOff className="h-5 w-5" aria-hidden="true" />
            ) : (
              <Eye className="h-5 w-5" aria-hidden="true" />
            )}
          </button>
        )}
        
        {!type === 'password' && endIcon && (
          <div className="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
            {endIcon}
          </div>
        )}
      </div>
      
      {description && !hasError && (
        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">{description}</p>
      )}
      
      {hasError && (
        <div className="mt-1 flex items-center text-sm text-red-600 dark:text-red-400">
          <AlertCircle className="h-4 w-4 mr-1" />
          {error.message}
        </div>
      )}
    </div>
  );
});

Input.displayName = 'Input';

export default Input;
