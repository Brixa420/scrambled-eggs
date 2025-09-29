const mongoose = require('mongoose');

const chatSchema = new mongoose.Schema({
  name: {
    type: String,
    required: function() {
      return this.isGroupChat;
    },
    trim: true
  },
  isGroupChat: {
    type: Boolean,
    default: false
  },
  participants: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }],
  admins: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  lastMessage: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Message'
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  },
  // For group chats
  groupPhoto: {
    type: String,
    default: ''
  },
  // For direct messages, we can have a custom name
  customNames: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    name: String
  }]
});

// Update the updatedAt timestamp before saving
chatSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

// Add a method to get chat name for a specific user (for direct messages)
chatSchema.methods.getChatName = function(userId) {
  if (this.isGroupChat) {
    return this.name;
  }
  
  // For direct messages, find the other participant
  const otherUser = this.participants.find(
    participant => participant._id.toString() !== userId.toString()
  );
  
  // If there's a custom name set by the current user, use it
  const customName = this.customNames.find(
    cn => cn.user.toString() === userId.toString()
  );
  
  return customName?.name || otherUser?.displayName || 'Unknown User';
};

const Chat = mongoose.model('Chat', chatSchema);
module.exports = Chat;
