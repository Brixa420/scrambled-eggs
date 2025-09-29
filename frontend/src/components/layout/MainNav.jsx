import React from 'react';
import { Link as RouterLink, useLocation } from 'react-router-dom';
import {
  AppBar,
  Toolbar,
  Typography,
  Button,
  Box,
  IconButton,
  Avatar,
  Menu,
  MenuItem,
  Divider,
  Badge,
  useTheme,
  useMediaQuery,
} from '@mui/material';
import {
  Home as HomeIcon,
  VideoLibrary as VideoLibraryIcon,
  Subscriptions as SubscriptionsIcon,
  Notifications as NotificationsIcon,
  AccountCircle as AccountCircleIcon,
  Menu as MenuIcon,
  MonetizationOn as DonateIcon,
} from '@mui/icons-material';
import { useAuth } from '../../contexts/AuthContext';

const MainNav = ({ onMenuToggle }) => {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const location = useLocation();
  const { currentUser, logout } = useAuth();
  const [anchorEl, setAnchorEl] = React.useState(null);

  const handleProfileMenuOpen = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handleLogout = async () => {
    try {
      await logout();
      handleMenuClose();
    } catch (error) {
      console.error('Failed to log out', error);
    }
  };

  const menuId = 'primary-account-menu';
  const isMenuOpen = Boolean(anchorEl);

  const renderMenu = (
    <Menu
      anchorEl={anchorEl}
      anchorOrigin={{
        vertical: 'top',
        horizontal: 'right',
      }}
      id={menuId}
      keepMounted
      transformOrigin={{
        vertical: 'top',
        horizontal: 'right',
      }}
      open={isMenuOpen}
      onClose={handleMenuClose}
    >
      <MenuItem 
        component={RouterLink} 
        to="/dashboard" 
        onClick={handleMenuClose}
      >
        Dashboard
      </MenuItem>
      <MenuItem 
        component={RouterLink} 
        to="/subscription" 
        onClick={handleMenuClose}
      >
        My Subscription
      </MenuItem>
      <MenuItem 
        component={RouterLink} 
        to="/settings" 
        onClick={handleMenuClose}
      >
        Settings
      </MenuItem>
      <Divider />
      <MenuItem onClick={handleLogout}>Logout</MenuItem>
    </Menu>
  );

  return (
    <>
      <AppBar position="static" color="default" elevation={1}>
        <Toolbar>
          {isMobile && (
            <IconButton
              edge="start"
              color="inherit"
              aria-label="open drawer"
              onClick={onMenuToggle}
              sx={{ mr: 2 }}
            >
              <MenuIcon />
            </IconButton>
          )}
          
          <Typography 
            variant="h6" 
            component={RouterLink} 
            to="/"
            sx={{
              flexGrow: 1,
              fontWeight: 'bold',
              textDecoration: 'none',
              color: 'inherit',
              '&:hover': {
                textDecoration: 'none',
              },
            }}
          >
            ScrambledEggs
          </Typography>

          {!isMobile && (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mr: 3 }}>
              <Button 
                component={RouterLink} 
                to="/" 
                startIcon={<HomeIcon />}
                color={location.pathname === '/' ? 'primary' : 'inherit'}
              >
                Home
              </Button>
              <Button 
                component={RouterLink} 
                to="/browse" 
                startIcon={<VideoLibraryIcon />}
                color={location.pathname.startsWith('/browse') ? 'primary' : 'inherit'}
              >
                Browse
              </Button>
              <Button 
                component={RouterLink} 
                to="/subscription" 
                startIcon={<SubscriptionsIcon />}
                color={location.pathname.startsWith('/subscription') ? 'primary' : 'inherit'}
              >
                Subscribe
              </Button>
            </Box>
          )}

          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {currentUser ? (
              <>
                <IconButton 
                  component={RouterLink} 
                  to="/donate"
                  color="primary"
                  size="large"
                  title="Support Creators"
                >
                  <DonateIcon />
                </IconButton>
                
                <IconButton 
                  aria-label="show new notifications" 
                  color="inherit"
                  size="large"
                >
                  <Badge badgeContent={0} color="error">
                    <NotificationsIcon />
                  </Badge>
                </IconButton>
                
                <IconButton
                  edge="end"
                  aria-label="account of current user"
                  aria-controls={menuId}
                  aria-haspopup="true"
                  onClick={handleProfileMenuOpen}
                  color="inherit"
                  size="large"
                >
                  {currentUser.avatar_url ? (
                    <Avatar 
                      alt={currentUser.username} 
                      src={currentUser.avatar_url} 
                      sx={{ width: 32, height: 32 }}
                    />
                  ) : (
                    <AccountCircleIcon />
                  )}
                </IconButton>
              </>
            ) : (
              <>
                <Button 
                  component={RouterLink} 
                  to="/login" 
                  color="inherit"
                >
                  Log In
                </Button>
                <Button 
                  component={RouterLink} 
                  to="/signup" 
                  variant="contained" 
                  color="primary"
                  sx={{ ml: 1 }}
                >
                  Sign Up
                </Button>
              </>
            )}
          </Box>
        </Toolbar>
      </AppBar>
      {renderMenu}
    </>
  );
};

export default MainNav;
