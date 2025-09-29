require('dotenv').config();
const WebSocket = require('ws');
const http = require('http');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

// Import models
const User = require('./models/User');
const Chat = require('./models/Chat');
const Message = require('./models/Message');

// WebSocket server class
class ChatWebSocketServer {
  constructor(port) {
    this.port = port || 3001;
    this.clients = new Map(); // userId -> WebSocket
    this.userSockets = new Map(); // userId -> Set of socketIds
    this.socketToUser = new Map(); // socketId -> userId
    this.server = http.createServer();
    this.wss = new WebSocket.Server({ server: this.server });
    
    // Bind methods
    this.handleConnection = this.handleConnection.bind(this);
    this.handleMessage = this.handleMessage.bind(this);
    this.broadcastToChat = this.broadcastToChat.bind(this);
    this.sendToUser = this.sendToUser.bind(this);
    this.authenticate = this.authenticate.bind(this);
    this.setupEventHandlers = this.setupEventHandlers.bind(this);
  }

  // Start the WebSocket server
  async start() {
    try {
      // Connect to MongoDB
      await mongoose.connect(process.env.MONGODB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      });
      console.log('Connected to MongoDB');

      // Setup WebSocket server
      this.wss.on('connection', this.handleConnection);
      
      this.server.listen(this.port, () => {
        console.log(`Chat WebSocket server running on port ${this.port}`);
      });
    } catch (error) {
      console.error('Failed to start server:', error);
      process.exit(1);
    }
  }

  // Handle new WebSocket connection
  async handleConnection(ws, req) {
    const { token } = this.parseQueryParams(req.url);
    
    try {
      // Authenticate the user
      const userId = await this.authenticate(token);
      if (!userId) {
        ws.close(4001, 'Authentication failed');
        return;
      }

      const socketId = this.generateSocketId();
      
      // Store the connection
      this.clients.set(socketId, ws);
      
      if (!this.userSockets.has(userId)) {
        this.userSockets.set(userId, new Set());
      }
      this.userSockets.get(userId).add(socketId);
      this.socketToUser.set(socketId, userId);

      // Update user status
      await User.findByIdAndUpdate(userId, { 
        status: 'online',
        lastSeen: Date.now()
      });

      // Notify user's contacts about the online status
      this.notifyContacts(userId, true);

      // Setup event handlers
      this.setupEventHandlers(ws, socketId, userId);

      console.log(`User ${userId} connected with socket ${socketId}`);
    } catch (error) {
      console.error('Connection error:', error);
      ws.close(4000, 'Connection error');
    }
  }

  // Setup WebSocket event handlers
  setupEventHandlers(ws, socketId, userId) {
    // Handle incoming messages
    ws.on('message', async (data) => {
      try {
        const message = JSON.parse(data);
        await this.handleMessage(ws, socketId, userId, message);
      } catch (error) {
        console.error('Error processing message:', error);
      }
    });

    // Handle connection close
    ws.on('close', async () => {
      this.clients.delete(socketId);
      
      if (this.socketToUser.has(socketId)) {
        const userId = this.socketToUser.get(socketId);
        this.socketToUser.delete(socketId);
        
        if (this.userSockets.has(userId)) {
          const userSockets = this.userSockets.get(userId);
          userSockets.delete(socketId);
          
          // If no more connections for this user, update status
          if (userSockets.size === 0) {
            this.userSockets.delete(userId);
            
            // Update user status
            await User.findByIdAndUpdate(userId, { 
              status: 'offline',
              lastSeen: Date.now()
            });
            
            // Notify contacts about offline status
            this.notifyContacts(userId, false);
          }
        }
      }
      
      console.log(`Socket ${socketId} disconnected`);
    });

    // Handle errors
    ws.on('error', (error) => {
      console.error('WebSocket error:', error);
    });
  }

  // Handle incoming WebSocket messages
  async handleMessage(ws, socketId, userId, message) {
    try {
      const { type, data } = message;
      
      switch (type) {
        case 'SEND_MESSAGE':
          await this.handleSendMessage(userId, data);
          break;
          
        case 'TYPING_STATUS':
          await this.handleTypingStatus(userId, data);
          break;
          
        case 'MESSAGE_READ':
          await this.handleMessageRead(userId, data);
          break;
          
        case 'REACTION':
          await this.handleReaction(userId, data);
          break;
          
        case 'DELETE_MESSAGE':
          await this.handleDeleteMessage(userId, data);
          break;
          
        case 'EDIT_MESSAGE':
          await this.handleEditMessage(userId, data);
          break;
          
        default:
          console.warn('Unknown message type:', type);
      }
    } catch (error) {
      console.error('Error handling message:', error);
      this.sendToUser(userId, {
        type: 'ERROR',
        data: { message: error.message }
      });
    }
  }

  // Handle sending a new message
  async handleSendMessage(senderId, { chatId, content, attachments = [], replyTo }) {
    // Validate chat exists and user is a participant
    const chat = await Chat.findOne({
      _id: chatId,
      participants: senderId
    });
    
    if (!chat) {
      throw new Error('Chat not found or access denied');
    }
    
    // Create the message
    const message = new Message({
      chat: chatId,
      sender: senderId,
      content,
      attachments,
      replyTo,
      status: 'sent'
    });
    
    await message.save();
    
    // Update chat's last message
    chat.lastMessage = message._id;
    chat.updatedAt = Date.now();
    await chat.save();
    
    // Get the populated message to send to clients
    const populatedMessage = await Message.findById(message._id)
      .populate('sender', 'username displayName avatar')
      .populate('replyTo', 'content sender')
      .lean();
    
    // Broadcast the message to all participants
    const participants = chat.participants.map(p => p.toString());
    
    // Send the message to all online participants
    participants.forEach(participantId => {
      // For the sender, mark as delivered
      const status = participantId === senderId.toString() ? 'delivered' : 'sent';
      
      this.sendToUser(participantId, {
        type: 'NEW_MESSAGE',
        data: {
          ...populatedMessage,
          status
        }
      });
    });
    
    // Send push notifications to offline users
    this.sendPushNotifications(participants, {
      title: chat.isGroupChat 
        ? `${populatedMessage.sender.displayName} in ${chat.name}`
        : populatedMessage.sender.displayName,
      body: content || (attachments.length > 0 ? 'Sent an attachment' : ''),
      data: { chatId }
    });
  }

  // Handle typing status
  async handleTypingStatus(userId, { chatId, isTyping }) {
    const chat = await Chat.findById(chatId);
    if (!chat || !chat.participants.includes(userId)) {
      throw new Error('Chat not found or access denied');
    }
    
    // Get user info
    const user = await User.findById(userId, 'displayName');
    
    // Broadcast typing status to other participants
    chat.participants.forEach(participantId => {
      if (participantId.toString() !== userId.toString()) {
        this.sendToUser(participantId, {
          type: 'TYPING_STATUS',
          data: {
            chatId,
            userId,
            displayName: user.displayName,
            isTyping
          }
        });
      }
    });
  }

  // Handle message read receipt
  async handleMessageRead(userId, { messageId, chatId }) {
    const message = await Message.findById(messageId);
    if (!message) {
      throw new Error('Message not found');
    }
    
    // Update read status
    const hasRead = message.readBy.some(entry => 
      entry.user.toString() === userId.toString()
    );
    
    if (!hasRead) {
      message.readBy.push({ user: userId });
      await message.save();
      
      // Notify other participants that the message was read
      const chat = await Chat.findById(chatId);
      if (chat) {
        chat.participants.forEach(participantId => {
          if (participantId.toString() !== userId.toString()) {
            this.sendToUser(participantId, {
              type: 'MESSAGE_READ',
              data: {
                messageId,
                chatId,
                userId,
                readAt: Date.now()
              }
            });
          }
        });
      }
    }
  }

  // Handle message reactions
  async handleReaction(userId, { messageId, emoji }) {
    const message = await Message.findById(messageId);
    if (!message) {
      throw new Error('Message not found');
    }
    
    // Add or update reaction
    await message.addReaction(userId, emoji);
    
    // Get the updated message
    const updatedMessage = await Message.findById(messageId)
      .populate('reactions.users', 'displayName');
    
    // Find the chat to get participants
    const chat = await Chat.findById(message.chat);
    
    // Broadcast the reaction to all participants
    chat.participants.forEach(participantId => {
      this.sendToUser(participantId, {
        type: 'MESSAGE_REACTION',
        data: {
          messageId,
          chatId: chat._id,
          reactions: updatedMessage.reactions
        }
      });
    });
  }

  // Handle message deletion
  async handleDeleteMessage(userId, { messageId }) {
    const message = await Message.findById(messageId);
    if (!message) {
      throw new Error('Message not found');
    }
    
    // Only allow sender or admin to delete
    if (message.sender.toString() !== userId.toString()) {
      const chat = await Chat.findOne({
        _id: message.chat,
        $or: [
          { admins: userId },
          { createdBy: userId }
        ]
      });
      
      if (!chat) {
        throw new Error('Not authorized to delete this message');
      }
    }
    
    // Soft delete the message
    message.deleted = true;
    message.deletedAt = Date.now();
    message.deletedBy = userId;
    await message.save();
    
    // Find the chat to get participants
    const chat = await Chat.findById(message.chat);
    
    // Broadcast the deletion to all participants
    chat.participants.forEach(participantId => {
      this.sendToUser(participantId, {
        type: 'MESSAGE_DELETED',
        data: {
          messageId,
          chatId: chat._id,
          deletedBy: userId,
          deletedAt: message.deletedAt
        }
      });
    });
  }

  // Handle message editing
  async handleEditMessage(userId, { messageId, content }) {
    const message = await Message.findById(messageId);
    if (!message) {
      throw new Error('Message not found');
    }
    
    // Only allow sender to edit
    if (message.sender.toString() !== userId.toString()) {
      throw new Error('Not authorized to edit this message');
    }
    
    // Update the message
    message.content = content;
    message.edited = true;
    message.editedAt = Date.now();
    await message.save();
    
    // Find the chat to get participants
    const chat = await Chat.findById(message.chat);
    
    // Broadcast the update to all participants
    chat.participants.forEach(participantId => {
      this.sendToUser(participantId, {
        type: 'MESSAGE_UPDATED',
        data: {
          messageId,
          chatId: chat._id,
          content: message.content,
          editedAt: message.editedAt
        }
      });
    });
  }

  // Send a message to a specific user
  sendToUser(userId, message) {
    if (this.userSockets.has(userId)) {
      const sockets = this.userSockets.get(userId);
      const messageStr = JSON.stringify(message);
      
      sockets.forEach(socketId => {
        const ws = this.clients.get(socketId);
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(messageStr);
        }
      });
    }
  }

  // Broadcast a message to all participants in a chat
  async broadcastToChat(chatId, message, excludeUserId = null) {
    const chat = await Chat.findById(chatId);
    if (!chat) return;
    
    chat.participants.forEach(participantId => {
      if (!excludeUserId || participantId.toString() !== excludeUserId.toString()) {
        this.sendToUser(participantId, message);
      }
    });
  }

  // Notify user's contacts about status change
  async notifyContacts(userId, isOnline) {
    // In a real app, you would fetch the user's contacts here
    // For now, we'll just notify all users in the same chats
    const userChats = await Chat.find({ participants: userId }, '_id');
    const chatIds = userChats.map(chat => chat._id);
    
    // Find all participants in these chats
    const chats = await Chat.find({
      _id: { $in: chatIds }
    }).select('participants');
    
    const participantIds = new Set();
    chats.forEach(chat => {
      chat.participants.forEach(id => {
        if (id.toString() !== userId.toString()) {
          participantIds.add(id.toString());
        }
      });
    });
    
    // Notify each participant
    participantIds.forEach(participantId => {
      this.sendToUser(participantId, {
        type: 'USER_STATUS_CHANGED',
        data: {
          userId,
          isOnline,
          lastSeen: isOnline ? null : new Date()
        }
      });
    });
  }

  // Send push notifications to users (stub implementation)
  sendPushNotifications(userIds, notification) {
    // In a real app, you would integrate with a push notification service
    // like Firebase Cloud Messaging (FCM) or OneSignal
    console.log('Sending push notifications:', { userIds, notification });
  }

  // Helper: Parse query parameters from URL
  parseQueryParams(url) {
    const params = {};
    const queryString = url.split('?')[1];
    
    if (queryString) {
      queryString.split('&').forEach(pair => {
        const [key, value] = pair.split('=');
        params[key] = decodeURIComponent(value || '');
      });
    }
    
    return params;
  }

  // Helper: Authenticate user from JWT token
  async authenticate(token) {
    if (!token) {
      throw new Error('No token provided');
    }
    
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      return decoded.userId;
    } catch (error) {
      console.error('Authentication error:', error);
      throw new Error('Invalid token');
    }
  }

  // Helper: Generate a unique socket ID
  generateSocketId() {
    return Math.random().toString(36).substr(2, 9);
  }
}

// Create and start the server
if (require.main === module) {
  const port = process.env.CHAT_WS_PORT || 3001;
  const server = new ChatWebSocketServer(port);
  server.start();
}

module.exports = ChatWebSocketServer;
