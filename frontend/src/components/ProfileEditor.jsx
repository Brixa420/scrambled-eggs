import React, { useState, useRef, useEffect } from 'react';
import { 
  Box, 
  Button, 
  TextField, 
  Typography, 
  Avatar, 
  Paper, 
  Divider,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Slider,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Snackbar,
  Alert,
  CircularProgress
} from '@mui/material';
import { PhotoCamera, Close, Crop, Save } from '@mui/icons-material';
import { useFormik } from 'formik';
import * as yup from 'yup';
import Cropper from 'react-easy-crop';
import { useAuth } from '../contexts/AuthContext';
import { getImage, getCroppedImg } from '../utils/imageUtils';

const validationSchema = yup.object({
  displayName: yup.string().max(32, 'Display name must be at most 32 characters'),
  bio: yup.string().max(500, 'Bio must be at most 500 characters'),
  email: yup.string().email('Enter a valid email'),
  currentPassword: yup.string().when('newPassword', {
    is: (val) => !!val,
    then: yup.string().required('Current password is required to change password'),
    otherwise: yup.string(),
  }),
  newPassword: yup.string().min(8, 'Password must be at least 8 characters'),
});

const ProfileEditor = ({ open, onClose, user, onSave }) => {
  const [avatar, setAvatar] = useState(user?.avatar || '');
  const [banner, setBanner] = useState(user?.banner || '');
  const [avatarFile, setAvatarFile] = useState(null);
  const [bannerFile, setBannerFile] = useState(null);
  const [crop, setCrop] = useState({ x: 0, y: 0 });
  const [zoom, setZoom] = useState(1);
  const [croppedAreaPixels, setCroppedAreaPixels] = useState(null);
  const [cropping, setCropping] = useState(false);
  const [croppingFor, setCroppingFor] = useState(null); // 'avatar' or 'banner'
  const [isSaving, setIsSaving] = useState(false);
  const [snackbar, setSnackbar] = useState({
    open: false,
    message: '',
    severity: 'success',
  });
  
  const fileInputRef = useRef(null);
  const bannerInputRef = useRef(null);
  const { updateProfile } = useAuth();

  const formik = useFormik({
    initialValues: {
      displayName: user?.displayName || '',
      bio: user?.bio || '',
      email: user?.email || '',
      currentPassword: '',
      newPassword: '',
    },
    validationSchema,
    onSubmit: async (values) => {
      try {
        setIsSaving(true);
        
        // Handle avatar upload if changed
        let avatarUrl = avatar;
        if (avatarFile) {
          const formData = new FormData();
          formData.append('file', avatarFile);
          
          if (croppedAreaPixels && croppingFor === 'avatar') {
            formData.append('x', croppedAreaPixels.x);
            formData.append('y', croppedAreaPixels.y);
            formData.append('width', croppedAreaPixels.width);
            formData.append('height', croppedAreaPixels.height);
          }
          
          const response = await fetch('/api/profiles/me/avatar', {
            method: 'POST',
            body: formData,
          });
          
          if (!response.ok) {
            throw new Error('Failed to upload avatar');
          }
          
          const data = await response.json();
          avatarUrl = data.url;
        }
        
        // Handle banner upload if changed
        let bannerUrl = banner;
        if (bannerFile) {
          const formData = new FormData();
          formData.append('file', bannerFile);
          
          const response = await fetch('/api/profiles/me/banner', {
            method: 'POST',
            body: formData,
          });
          
          if (!response.ok) {
            throw new Error('Failed to upload banner');
          }
          
          const data = await response.json();
          bannerUrl = data.url;
        }
        
        // Update profile
        const profileData = {
          ...values,
          avatar: avatarUrl,
          banner: bannerUrl,
        };
        
        await updateProfile(profileData);
        
        setSnackbar({
          open: true,
          message: 'Profile updated successfully!',
          severity: 'success',
        });
        
        onSave(profileData);
        onClose();
        
      } catch (error) {
        console.error('Error updating profile:', error);
        setSnackbar({
          open: true,
          message: error.message || 'Failed to update profile',
          severity: 'error',
        });
      } finally {
        setIsSaving(false);
      }
    },
  });

  const handleFileChange = async (e, type) => {
    const file = e.target.files[0];
    if (!file) return;
    
    try {
      const imageDataUrl = await getImage(file);
      
      if (type === 'avatar') {
        setAvatar(imageDataUrl);
        setAvatarFile(file);
        setCroppingFor('avatar');
        setCropping(true);
      } else {
        setBanner(imageDataUrl);
        setBannerFile(file);
        setCroppingFor('banner');
        setCropping(true);
      }
    } catch (error) {
      console.error('Error processing image:', error);
      setSnackbar({
        open: true,
        message: 'Error processing image. Please try another one.',
        severity: 'error',
      });
    }
  };

  const onCropComplete = (croppedArea, croppedAreaPixels) => {
    setCroppedAreaPixels(croppedAreaPixels);
  };

  const handleCropComplete = async () => {
    try {
      const croppedImage = await getCroppedImg(
        croppingFor === 'avatar' ? avatar : banner,
        croppedAreaPixels
      );
      
      if (croppingFor === 'avatar') {
        setAvatar(croppedImage);
      } else {
        setBanner(croppedImage);
      }
      
      setCropping(false);
      setCroppingFor(null);
    } catch (e) {
      console.error('Error cropping image:', e);
      setSnackbar({
        open: true,
        message: 'Error cropping image',
        severity: 'error',
      });
    }
  };

  const handleCloseSnackbar = () => {
    setSnackbar({ ...snackbar, open: false });
  };

  return (
    <Dialog 
      open={open} 
      onClose={onClose} 
      maxWidth="md" 
      fullWidth
      scroll="paper"
    >
      <DialogTitle>
        <Box display="flex" justifyContent="space-between" alignItems="center">
          <Typography variant="h6">Edit Profile</Typography>
          <IconButton onClick={onClose}>
            <Close />
          </IconButton>
        </Box>
      </DialogTitle>
      
      <form onSubmit={formik.handleSubmit}>
        <DialogContent dividers>
          {/* Banner */}
          <Box 
            sx={{
              height: 200,
              bgcolor: 'grey.200',
              borderRadius: 1,
              mb: 2,
              position: 'relative',
              overflow: 'hidden',
            }}
          >
            {banner && (
              <img 
                src={banner} 
                alt="Banner" 
                style={{
                  width: '100%',
                  height: '100%',
                  objectFit: 'cover',
                }}
              />
            )}
            <input
              type="file"
              ref={bannerInputRef}
              accept="image/*"
              style={{ display: 'none' }}
              onChange={(e) => handleFileChange(e, 'banner')}
            />
            <Button
              variant="contained"
              color="primary"
              size="small"
              startIcon={<PhotoCamera />}
              sx={{
                position: 'absolute',
                bottom: 16,
                right: 16,
                bgcolor: 'rgba(0, 0, 0, 0.6)',
                '&:hover': {
                  bgcolor: 'rgba(0, 0, 0, 0.8)',
                },
              }}
              onClick={() => bannerInputRef.current?.click()}
            >
              Change Banner
            </Button>
          </Box>
          
          {/* Avatar */}
          <Box 
            sx={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              mt: -8,
              mb: 2,
              position: 'relative',
              zIndex: 1,
            }}
          >
            <Box sx={{ position: 'relative' }}>
              <Avatar
                src={avatar}
                sx={{
                  width: 120,
                  height: 120,
                  border: '4px solid white',
                  bgcolor: 'primary.main',
                }}
              />
              <input
                type="file"
                ref={fileInputRef}
                accept="image/*"
                style={{ display: 'none' }}
                onChange={(e) => handleFileChange(e, 'avatar')}
              />
              <IconButton
                color="primary"
                sx={{
                  position: 'absolute',
                  bottom: 0,
                  right: 0,
                  bgcolor: 'primary.main',
                  color: 'white',
                  '&:hover': {
                    bgcolor: 'primary.dark',
                  },
                }}
                onClick={() => fileInputRef.current?.click()}
              >
                <PhotoCamera />
              </IconButton>
            </Box>
          </Box>
          
          {/* Profile Form */}
          <Box mt={4}>
            <TextField
              fullWidth
              id="displayName"
              name="displayName"
              label="Display Name"
              value={formik.values.displayName}
              onChange={formik.handleChange}
              onBlur={formik.handleBlur}
              error={formik.touched.displayName && Boolean(formik.errors.displayName)}
              helperText={formik.touched.displayName && formik.errors.displayName}
              margin="normal"
            />
            
            <TextField
              fullWidth
              id="bio"
              name="bio"
              label="Bio"
              multiline
              rows={4}
              value={formik.values.bio}
              onChange={formik.handleChange}
              onBlur={formik.handleBlur}
              error={formik.touched.bio && Boolean(formik.errors.bio)}
              helperText={formik.touched.bio && formik.errors.bio}
              margin="normal"
              placeholder="Tell us about yourself..."
            />
            
            <Divider sx={{ my: 3 }} />
            
            <Typography variant="h6" gutterBottom>Account</Typography>
            
            <TextField
              fullWidth
              id="email"
              name="email"
              label="Email Address"
              type="email"
              value={formik.values.email}
              onChange={formik.handleChange}
              onBlur={formik.handleBlur}
              error={formik.touched.email && Boolean(formik.errors.email)}
              helperText={formik.touched.email && formik.errors.email}
              margin="normal"
            />
            
            <Typography variant="subtitle2" color="textSecondary" gutterBottom sx={{ mt: 3 }}>
              Change Password
            </Typography>
            
            <TextField
              fullWidth
              id="currentPassword"
              name="currentPassword"
              label="Current Password"
              type="password"
              value={formik.values.currentPassword}
              onChange={formik.handleChange}
              onBlur={formik.handleBlur}
              error={formik.touched.currentPassword && Boolean(formik.errors.currentPassword)}
              helperText={formik.touched.currentPassword && formik.errors.currentPassword}
              margin="normal"
            />
            
            <TextField
              fullWidth
              id="newPassword"
              name="newPassword"
              label="New Password"
              type="password"
              value={formik.values.newPassword}
              onChange={formik.handleChange}
              onBlur={formik.handleBlur}
              error={formik.touched.newPassword && Boolean(formik.errors.newPassword)}
              helperText={
                formik.touched.newPassword && formik.errors.newPassword 
                  ? formik.errors.newPassword 
                  : 'Leave blank to keep current password'
              }
              margin="normal"
            />
          </Box>
        </DialogContent>
        
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={onClose} disabled={isSaving}>
            Cancel
          </Button>
          <Button
            type="submit"
            variant="contained"
            color="primary"
            disabled={isSaving}
            startIcon={isSaving ? <CircularProgress size={20} /> : <Save />}
          >
            {isSaving ? 'Saving...' : 'Save Changes'}
          </Button>
        </DialogActions>
      </form>
      
      {/* Image Cropper Dialog */}
      <Dialog 
        open={cropping} 
        onClose={() => setCropping(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>
          Crop {croppingFor === 'avatar' ? 'Profile Picture' : 'Banner'}
        </DialogTitle>
        <DialogContent>
          <Box 
            sx={{
              position: 'relative',
              height: croppingFor === 'avatar' ? 300 : 200,
              width: '100%',
              bgcolor: '#333',
            }}
          >
            <Cropper
              image={croppingFor === 'avatar' ? avatar : banner}
              crop={crop}
              zoom={zoom}
              aspect={croppingFor === 'avatar' ? 1 : 16/9}
              onCropChange={setCrop}
              onZoomChange={setZoom}
              onCropComplete={onCropComplete}
              objectFit="contain"
              style={{
                containerStyle: {
                  width: '100%',
                  height: '100%',
                  position: 'relative',
                },
                mediaStyle: {
                  maxHeight: 'none',
                  maxWidth: 'none',
                },
              }}
            />
          </Box>
          <Box sx={{ mt: 2, px: 2 }}>
            <Typography gutterBottom>Zoom</Typography>
            <Slider
              value={zoom}
              min={1}
              max={3}
              step={0.1}
              aria-labelledby="Zoom"
              onChange={(e, zoom) => setZoom(zoom)}
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCropping(false)}>Cancel</Button>
          <Button 
            onClick={handleCropComplete}
            variant="contained"
            color="primary"
            startIcon={<Crop />}
          >
            Crop
          </Button>
        </DialogActions>
      </Dialog>
      
      {/* Snackbar for notifications */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={handleCloseSnackbar}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert 
          onClose={handleCloseSnackbar} 
          severity={snackbar.severity}
          variant="filled"
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Dialog>
  );
};

export default ProfileEditor;
