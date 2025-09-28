import { Router } from 'express';
import { requireAuth } from '../middleware/require-auth';

const router = Router();

// Protected route example
router.get('/protected', requireAuth, (req, res) => {
  res.json({ message: 'This is a protected route', user: req.currentUser });
});

// Get WebRTC configuration
router.get('/webrtc-config', (req, res) => {
  // In production, you might want to generate these dynamically
  // or fetch from a configuration service
  res.json({
    iceServers: [
      { urls: 'stun:stun.l.google.com:19302' },
      { urls: 'stun:stun1.l.google.com:19302' },
      { urls: 'stun:stun2.l.google.com:19302' },
    ],
  });
});

// Create a new room
router.post('/rooms', requireAuth, (req, res) => {
  // In a real app, you'd create a room in the database
  const roomId = Math.random().toString(36).substring(2, 10);
  res.status(201).json({ roomId });
});

// Get room info
router.get('/rooms/:roomId', requireAuth, (req, res) => {
  // In a real app, you'd fetch this from the database
  const { roomId } = req.params;
  res.json({
    roomId,
    participants: [],
    createdAt: new Date().toISOString(),
  });
});

export { router as apiRouter };
