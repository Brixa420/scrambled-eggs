import React, { useState, useEffect } from 'react';
import { 
  Box, 
  Typography, 
  Avatar, 
  Paper, 
  Button, 
  Divider, 
  Tabs, 
  Tab, 
  useTheme, 
  useMediaQuery,
  IconButton,
  CircularProgress
} from '@mui/material';
import { Edit, ArrowBack } from '@mui/icons-material';
import { useParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import ProfileEditor from './ProfileEditor';

function TabPanel(props) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`profile-tabpanel-${index}`}
      aria-labelledby={`profile-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ p: 3 }}>
          {children}
        </Box>
      )}
    </div>
  );
}

function a11yProps(index) {
  return {
    id: `profile-tab-${index}`,
    'aria-controls': `profile-tabpanel-${index}`,
  };
}

const UserProfile = () => {
  const { userId } = useParams();
  const { currentUser } = useAuth();
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [tabValue, setTabValue] = useState(0);
  const [editOpen, setEditOpen] = useState(false);
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('sm'));
  const navigate = useNavigate();
  const isOwnProfile = !userId || userId === currentUser?.id;
  const profileUser = isOwnProfile ? currentUser : user;

  useEffect(() => {
    const fetchUserProfile = async () => {
      if (isOwnProfile) {
        setUser(currentUser);
        setLoading(false);
        return;
      }

      try {
        setLoading(true);
        const response = await fetch(`/api/profiles/${userId}`);
        
        if (!response.ok) {
          throw new Error('Failed to fetch user profile');
        }
        
        const data = await response.json();
        setUser(data);
      } catch (err) {
        console.error('Error fetching user profile:', err);
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchUserProfile();
  }, [userId, currentUser, isOwnProfile]);

  const handleTabChange = (event, newValue) => {
    setTabValue(newValue);
  };

  const handleProfileUpdate = (updatedProfile) => {
    setUser(updatedProfile);
    if (isOwnProfile) {
      // Update current user in auth context
      // This would typically be handled by your auth context
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="60vh">
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box textAlign="center" p={4}>
        <Typography color="error" gutterBottom>
          Error loading profile: {error}
        </Typography>
        <Button 
          variant="contained" 
          color="primary" 
          onClick={() => window.location.reload()}
          sx={{ mt: 2 }}
        >
          Retry
        </Button>
      </Box>
    );
  }

  if (!profileUser) {
    return (
      <Box textAlign="center" p={4}>
        <Typography variant="h6">User not found</Typography>
      </Box>
    );
  }

  return (
    <Box>
      {/* Back button for mobile */}
      {isMobile && (
        <IconButton 
          onClick={() => navigate(-1)}
          sx={{ mb: 2 }}
        >
          <ArrowBack />
        </IconButton>
      )}

      {/* Banner */}
      <Box 
        sx={{
          height: { xs: 150, sm: 200 },
          bgcolor: 'grey.200',
          borderRadius: 1,
          mb: 2,
          position: 'relative',
          overflow: 'hidden',
        }}
      >
        {profileUser.banner && (
          <img 
            src={profileUser.banner} 
            alt="Banner" 
            style={{
              width: '100%',
              height: '100%',
              objectFit: 'cover',
            }}
          />
        )}
        
        {/* Edit button for own profile */}
        {isOwnProfile && (
          <Button
            variant="contained"
            color="primary"
            size="small"
            startIcon={<Edit />}
            onClick={() => setEditOpen(true)}
            sx={{
              position: 'absolute',
              bottom: 16,
              right: 16,
              bgcolor: 'rgba(0, 0, 0, 0.6)',
              '&:hover': {
                bgcolor: 'rgba(0, 0, 0, 0.8)',
              },
            }}
          >
            Edit Profile
          </Button>
        )}
      </Box>
      
      {/* Profile header */}
      <Box 
        sx={{
          display: 'flex',
          flexDirection: { xs: 'column', sm: 'row' },
          alignItems: { xs: 'center', sm: 'flex-start' },
          mb: 3,
          position: 'relative',
        }}
      >
        {/* Avatar */}
        <Box 
          sx={{
            mt: { xs: -8, sm: -12 },
            ml: { xs: 0, sm: 4 },
            mb: { xs: 2, sm: 0 },
            position: 'relative',
            zIndex: 1,
          }}
        >
          <Avatar
            src={profileUser.avatar}
            sx={{
              width: { xs: 100, sm: 150 },
              height: { xs: 100, sm: 150 },
              border: '4px solid white',
              bgcolor: 'primary.main',
              fontSize: { xs: 40, sm: 60 },
            }}
          >
            {profileUser.displayName?.charAt(0) || 'U'}
          </Avatar>
        </Box>
        
        {/* User info */}
        <Box 
          sx={{ 
            flex: 1, 
            textAlign: { xs: 'center', sm: 'left' },
            mt: { xs: 1, sm: 2 },
            ml: { xs: 0, sm: 4 },
          }}
        >
          <Box display="flex" alignItems="center" justifyContent={{ xs: 'center', sm: 'flex-start' }}>
            <Typography variant="h4" component="h1" sx={{ fontWeight: 'bold', mr: 1 }}>
              {profileUser.displayName || profileUser.username}
            </Typography>
            {profileUser.isVerified && (
              <Box component="span" sx={{ color: 'primary.main', display: 'inline-flex' }}>
                ✓
              </Box>
            )}
          </Box>
          
          <Typography variant="subtitle1" color="textSecondary" gutterBottom>
            @{profileUser.username}
          </Typography>
          
          {profileUser.bio && (
            <Typography variant="body1" sx={{ mt: 2, maxWidth: '600px', mx: 'auto', sm: { mx: 0 } }}>
              {profileUser.bio}
            </Typography>
          )}
          
          <Box display="flex" justifyContent={{ xs: 'center', sm: 'flex-start' }} mt={2}>
            <Typography variant="body2" color="textSecondary" sx={{ mr: 3 }}>
              <Box component="span" sx={{ fontWeight: 'bold', color: 'text.primary' }}>
                {profileUser.followersCount || 0}
              </Box> Followers
            </Typography>
            <Typography variant="body2" color="textSecondary">
              <Box component="span" sx={{ fontWeight: 'bold', color: 'text.primary' }}>
                {profileUser.followingCount || 0}
              </Box> Following
            </Typography>
          </Box>
        </Box>
      </Box>
      
      {/* Tabs */}
      <Paper sx={{ width: '100%', mb: 3 }}>
        <Tabs
          value={tabValue}
          onChange={handleTabChange}
          indicatorColor="primary"
          textColor="primary"
          variant="scrollable"
          scrollButtons="auto"
          aria-label="profile tabs"
        >
          <Tab label="Posts" {...a11yProps(0)} />
          <Tab label="Replies" {...a11yProps(1)} />
          <Tab label="Media" {...a11yProps(2)} />
          <Tab label="Likes" {...a11yProps(3)} />
        </Tabs>
        
        <Divider />
        
        <TabPanel value={tabValue} index={0}>
          <Typography>Posts will appear here</Typography>
        </TabPanel>
        <TabPanel value={tabValue} index={1}>
          <Typography>Replies will appear here</Typography>
        </TabPanel>
        <TabPanel value={tabValue} index={2}>
          <Typography>Media will appear here</Typography>
        </TabPanel>
        <TabPanel value={tabValue} index={3}>
          <Typography>Likes will appear here</Typography>
        </TabPanel>
      </Paper>
      
      {/* Profile Editor Modal */}
      {isOwnProfile && (
        <ProfileEditor 
          open={editOpen} 
          onClose={() => setEditOpen(false)} 
          user={currentUser}
          onSave={handleProfileUpdate}
        />
      )}
    </Box>
  );
};

export default UserProfile;
