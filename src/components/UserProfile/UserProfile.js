import React, { useState, useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { useAuth } from '../../context/AuthContext';
import { useNotification } from '../../context/NotificationContext';
import { User, Lock, Mail, Eye, EyeOff, Loader2 } from 'lucide-react';
import './UserProfile.css';

const UserProfile = () => {
  const { user, updateProfile, updateEmail, updatePassword } = useAuth();
  const { notify } = useNotification();
  const [isEditing, setIsEditing] = useState(false);
  const [isPasswordEditing, setIsPasswordEditing] = useState(false);
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const {
    register: registerProfile,
    handleSubmit: handleProfileSubmit,
    formState: { errors: profileErrors },
    reset: resetProfile,
  } = useForm({
    defaultValues: {
      username: user?.username || '',
      email: user?.email || '',
    },
  });

  const {
    register: registerPassword,
    handleSubmit: handlePasswordSubmit,
    formState: { errors: passwordErrors },
    watch,
    reset: resetPassword,
  } = useForm();

  useEffect(() => {
    if (user) {
      resetProfile({
        username: user.username || '',
        email: user.email || '',
      });
    }
  }, [user, resetProfile]);

  const onProfileSubmit = async (data) => {
    try {
      setIsLoading(true);
      const updates = {};
      
      if (data.username !== user.username) {
        updates.username = data.username;
      }
      
      if (data.email !== user.email) {
        await updateEmail(data.email);
        updates.email = data.email;
      }
      
      if (Object.keys(updates).length > 0) {
        await updateProfile(updates);
        notify('success', 'Profile updated successfully!');
      }
      
      setIsEditing(false);
    } catch (error) {
      console.error('Error updating profile:', error);
      notify('error', error.message || 'Failed to update profile');
    } finally {
      setIsLoading(false);
    }
  };

  const onPasswordSubmit = async (data) => {
    try {
      setIsLoading(true);
      await updatePassword(data.currentPassword, data.newPassword);
      notify('success', 'Password updated successfully!');
      setIsPasswordEditing(false);
      resetPassword();
    } catch (error) {
      console.error('Error updating password:', error);
      notify('error', error.message || 'Failed to update password');
    } finally {
      setIsLoading(false);
    }
  };

  if (!user) {
    return <div className="profile-loading">Loading user data...</div>;
  }

  return (
    <div className="profile-container">
      <div className="profile-header">
        <h2>User Profile</h2>
        {!isEditing && !isPasswordEditing && (
          <button
            className="edit-button"
            onClick={() => setIsEditing(true)}
            disabled={isLoading}
          >
            Edit Profile
          </button>
        )}
      </div>

      {!isPasswordEditing ? (
        <form onSubmit={handleProfileSubmit(onProfileSubmit)} className="profile-form">
          <div className={`form-group ${isEditing ? 'editing' : ''}`}>
            <label htmlFor="username">
              <User size={18} /> Username
            </label>
            {isEditing ? (
              <div className="input-wrapper">
                <input
                  id="username"
                  type="text"
                  {...registerProfile('username', {
                    required: 'Username is required',
                    minLength: {
                      value: 3,
                      message: 'Username must be at least 3 characters',
                    },
                    maxLength: {
                      value: 30,
                      message: 'Username must be less than 30 characters',
                    },
                    pattern: {
                      value: /^[a-zA-Z0-9_]+$/,
                      message: 'Username can only contain letters, numbers, and underscores',
                    },
                  })}
                  disabled={!isEditing || isLoading}
                />
                {profileErrors.username && (
                  <span className="error-message">{profileErrors.username.message}</span>
                )}
              </div>
            ) : (
              <div className="profile-value">{user.username}</div>
            )}
          </div>

          <div className={`form-group ${isEditing ? 'editing' : ''}`}>
            <label htmlFor="email">
              <Mail size={18} /> Email
            </label>
            {isEditing ? (
              <div className="input-wrapper">
                <input
                  id="email"
                  type="email"
                  {...registerProfile('email', {
                    required: 'Email is required',
                    pattern: {
                      value: /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i,
                      message: 'Invalid email address',
                    },
                  })}
                  disabled={!isEditing || isLoading}
                />
                {profileErrors.email && (
                  <span className="error-message">{profileErrors.email.message}</span>
                )}
              </div>
            ) : (
              <div className="profile-value">{user.email}</div>
            )}
          </div>

          {isEditing && (
            <div className="form-actions">
              <button
                type="button"
                className="cancel-button"
                onClick={() => {
                  resetProfile();
                  setIsEditing(false);
                }}
                disabled={isLoading}
              >
                Cancel
              </button>
              <button
                type="submit"
                className="save-button"
                disabled={isLoading}
              >
                {isLoading ? (
                  <>
                    <Loader2 className="spinner" size={18} /> Saving...
                  </>
                ) : (
                  'Save Changes'
                )}
              </button>
            </div>
          )}
        </form>
      ) : null}

      {!isEditing && !isPasswordEditing && (
        <div className="password-section">
          <h3>Password</h3>
          <button
            className="change-password-button"
            onClick={() => setIsPasswordEditing(true)}
          >
            Change Password
          </button>
        </div>
      )}

      {isPasswordEditing && (
        <form onSubmit={handlePasswordSubmit(onPasswordSubmit)} className="password-form">
          <h3>Change Password</h3>
          
          <div className="form-group">
            <label htmlFor="currentPassword">
              <Lock size={18} /> Current Password
            </label>
            <div className="input-wrapper">
              <input
                id="currentPassword"
                type={showCurrentPassword ? 'text' : 'password'}
                {...registerPassword('currentPassword', {
                  required: 'Current password is required',
                })}
                disabled={isLoading}
              />
              <button
                type="button"
                className="toggle-password"
                onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                tabIndex="-1"
              >
                {showCurrentPassword ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
              {passwordErrors.currentPassword && (
                <span className="error-message">
                  {passwordErrors.currentPassword.message}
                </span>
              )}
            </div>
          </div>

          <div className="form-group">
            <label htmlFor="newPassword">
              <Lock size={18} /> New Password
            </label>
            <div className="input-wrapper">
              <input
                id="newPassword"
                type={showNewPassword ? 'text' : 'password'}
                {...registerPassword('newPassword', {
                  required: 'New password is required',
                  minLength: {
                    value: 8,
                    message: 'Password must be at least 8 characters',
                  },
                  pattern: {
                    value: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])(?=.{8,})/,
                    message: 'Password must contain uppercase, lowercase, number, and special character',
                  },
                })}
                disabled={isLoading}
              />
              <button
                type="button"
                className="toggle-password"
                onClick={() => setShowNewPassword(!showNewPassword)}
                tabIndex="-1"
              >
                {showNewPassword ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
              {passwordErrors.newPassword && (
                <span className="error-message">
                  {passwordErrors.newPassword.message}
                </span>
              )}
            </div>
          </div>

          <div className="form-group">
            <label htmlFor="confirmPassword">
              <Lock size={18} /> Confirm New Password
            </label>
            <div className="input-wrapper">
              <input
                id="confirmPassword"
                type={showConfirmPassword ? 'text' : 'password'}
                {...registerPassword('confirmPassword', {
                  validate: (value) =>
                    value === watch('newPassword') || 'Passwords do not match',
                })}
                disabled={isLoading}
              />
              <button
                type="button"
                className="toggle-password"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                tabIndex="-1"
              >
                {showConfirmPassword ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
              {passwordErrors.confirmPassword && (
                <span className="error-message">
                  {passwordErrors.confirmPassword.message}
                </span>
              )}
            </div>
          </div>

          <div className="password-requirements">
            <p>Password must contain:</p>
            <ul>
              <li>At least 8 characters</li>
              <li>Uppercase letter (A-Z)</li>
              <li>Lowercase letter (a-z)</li>
              <li>Number (0-9)</li>
              <li>Special character (!@#$%^&*)</li>
            </ul>
          </div>

          <div className="form-actions">
            <button
              type="button"
              className="cancel-button"
              onClick={() => {
                resetPassword();
                setIsPasswordEditing(false);
              }}
              disabled={isLoading}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="save-button"
              disabled={isLoading}
            >
              {isLoading ? (
                <>
                  <Loader2 className="spinner" size={18} /> Updating...
                </>
              ) : (
                'Update Password'
              )}
            </button>
          </div>
        </form>
      )}
    </div>
  );
};

export default UserProfile;
