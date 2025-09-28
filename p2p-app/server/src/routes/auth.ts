import { Router } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config';
import { validateRequest } from '../middleware/validation';
import { body } from 'express-validator';

const router = Router();

// Mock user database (in production, use a real database)
const users = [
  { id: '1', username: 'user1', password: 'password1' },
  { id: '2', username: 'user2', password: 'password2' },
];

// Login route
router.post(
  '/login',
  [
    body('username').isString().notEmpty(),
    body('password').isString().notEmpty(),
  ],
  validateRequest,
  (req, res) => {
    const { username, password } = req.body;
    
    // Find user (in production, use proper password hashing)
    const user = users.find(
      u => u.username === username && u.password === password
    );
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Create JWT token
    const token = jwt.sign(
      { userId: user.id, username: user.username },
      config.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({ token, user: { id: user.id, username: user.username } });
  }
);

// Register route (simplified for example)
router.post(
  '/register',
  [
    body('username').isString().notEmpty(),
    body('password').isString().isLength({ min: 6 }),
  ],
  validateRequest,
  (req, res) => {
    const { username, password } = req.body;
    
    // Check if user exists (in production, use a database)
    if (users.some(u => u.username === username)) {
      return res.status(400).json({ error: 'Username already exists' });
    }
    
    // Create new user (in production, hash the password)
    const newUser = {
      id: (users.length + 1).toString(),
      username,
      password, // In production, hash this password
    };
    
    users.push(newUser);
    
    // Generate token
    const token = jwt.sign(
      { userId: newUser.id, username: newUser.username },
      config.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.status(201).json({
      token,
      user: { id: newUser.id, username: newUser.username },
    });
  }
);

// Get current user
router.get('/me', (req, res) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  const token = authHeader.split(' ')[1];
  
  try {
    const decoded = jwt.verify(token, config.JWT_SECRET) as { userId: string; username: string };
    const user = users.find(u => u.id === decoded.userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ id: user.id, username: user.username });
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

export { router as authRouter };
