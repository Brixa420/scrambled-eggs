import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

const authService = {
  async login(email, password) {
    try {
      const response = await axios.post(`${API_URL}/auth/login`, { email, password });
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.message || 'Login failed');
    }
  },

  async register(userData) {
    try {
      const response = await axios.post(`${API_URL}/auth/register`, userData);
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.message || 'Registration failed');
    }
  },

  async verifyToken(token) {
    try {
      const response = await axios.get(`${API_URL}/auth/verify-token`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return response.data.user;
    } catch (error) {
      throw new Error('Invalid or expired token');
    }
  },

  async requestPasswordReset(email) {
    try {
      await axios.post(`${API_URL}/auth/request-password-reset`, { email });
      return true;
    } catch (error) {
      throw new Error(error.response?.data?.message || 'Failed to request password reset');
    }
  },

  async resetPassword(token, newPassword) {
    try {
      await axios.post(`${API_URL}/auth/reset-password`, { token, newPassword });
      return true;
    } catch (error) {
      throw new Error(error.response?.data?.message || 'Failed to reset password');
    }
  },
};

export default authService;
