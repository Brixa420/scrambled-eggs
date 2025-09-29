const mongoose = require('mongoose');

const reactionSchema = new mongoose.Schema({
  emoji: {
    type: String,
    required: true
  },
  users: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  count: {
    type: Number,
    default: 1
  }
});

const messageSchema = new mongoose.Schema({
  chat: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Chat',
    required: true
  },
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  content: {
    type: String,
    trim: true
  },
  // For file attachments
  attachments: [{
    type: {
      type: String, // 'image', 'video', 'document', 'audio', etc.
      required: true
    },
    url: {
      type: String,
      required: true
    },
    name: String,
    size: Number,
    mimeType: String,
    thumbnail: String // For images/videos
  }],
  // Message status: 'sent', 'delivered', 'read'
  status: {
    type: String,
    enum: ['sending', 'sent', 'delivered', 'read', 'failed'],
    default: 'sending'
  },
  // For tracking read receipts
  readBy: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    readAt: {
      type: Date,
      default: Date.now
    }
  }],
  // For message replies
  replyTo: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Message'
  },
  // For message reactions
  reactions: [reactionSchema],
  // For message deletion
  deleted: {
    type: Boolean,
    default: false
  },
  deletedAt: Date,
  deletedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  // For message editing
  edited: {
    type: Boolean,
    default: false
  },
  editedAt: Date,
  // For system messages (user joined, user left, etc.)
  isSystemMessage: {
    type: Boolean,
    default: false
  },
  systemMessageType: {
    type: String,
    enum: ['user_joined', 'user_left', 'group_created', 'name_changed', 'photo_changed', null],
    default: null
  }
}, {
  timestamps: true
});

// Indexes for faster queries
messageSchema.index({ chat: 1, createdAt: -1 });
messageSchema.index({ sender: 1, createdAt: -1 });

// Add a method to add a reaction
messageSchema.methods.addReaction = async function(userId, emoji) {
  const existingReaction = this.reactions.find(r => r.emoji === emoji);
  
  if (existingReaction) {
    // If user already reacted with this emoji, remove their reaction
    const userIndex = existingReaction.users.indexOf(userId);
    if (userIndex > -1) {
      existingReaction.users.splice(userIndex, 1);
      existingReaction.count--;
      
      // Remove the reaction if no users left
      if (existingReaction.count === 0) {
        this.reactions = this.reactions.filter(r => r.emoji !== emoji);
      }
    } else {
      // Add user to existing reaction
      existingReaction.users.push(userId);
      existingReaction.count++;
    }
  } else {
    // Add new reaction
    this.reactions.push({
      emoji,
      users: [userId],
      count: 1
    });
  }
  
  return this.save();
};

// Add a method to mark message as read by a user
messageSchema.methods.markAsRead = async function(userId) {
  const hasRead = this.readBy.some(entry => 
    entry.user.toString() === userId.toString()
  );
  
  if (!hasRead) {
    this.readBy.push({ user: userId });
    this.status = 'read';
    return this.save();
  }
  
  return this;
};

const Message = mongoose.model('Message', messageSchema);
module.exports = Message;
