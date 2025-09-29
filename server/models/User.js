const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 30
  },
  displayName: {
    type: String,
    required: true,
    trim: true
  },
  avatar: {
    type: String,
    default: ''
  },
  status: {
    type: String,
    enum: ['online', 'offline', 'away'],
    default: 'offline'
  },
  lastSeen: {
    type: Date,
    default: Date.now
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Update lastSeen timestamp on user activity
userSchema.methods.updateLastSeen = function() {
  this.lastSeen = Date.now();
  return this.save();
};

// Update user status
userSchema.methods.updateStatus = function(status) {
  if (['online', 'offline', 'away'].includes(status)) {
    this.status = status;
    if (status === 'offline') {
      this.lastSeen = Date.now();
    }
    return this.save();
  }
  throw new Error('Invalid status');
};

const User = mongoose.model('User', userSchema);
module.exports = User;
