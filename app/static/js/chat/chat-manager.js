/**
 * Chat Manager - Handles P2P chat functionality
 */
import WebRTCManager from '../webrtc/webrtc-manager.js';

class ChatManager {
    constructor(socket, userId, chatContainer) {
        this.socket = socket;
        this.userId = userId;
        this.chatContainer = chatContainer;
        this.activeChats = new Map(); // Map of peerId -> { element, messageHistory }
        this.webrtcManager = null;
        
        this.initializeUI();
        this.initializeWebRTC();
        this.setupEventListeners();
    }

    /**
     * Initialize the chat UI
     */
    initializeUI() {
        // Create main chat container
        this.chatContainer.innerHTML = `
            <div class="chat-sidebar">
                <div class="user-info">
                    <div class="avatar">${this.userId.charAt(0).toUpperCase()}</div>
                    <div class="username">${this.userId}</div>
                </div>
                <div class="online-users" id="onlineUsers">
                    <div class="section-title">Online Users</div>
                    <div class="user-list" id="userList"></div>
                </div>
            </div>
            <div class="chat-main">
                <div class="chat-header">
                    <div class="chat-title">Scrambled Eggs Chat</div>
                    <div class="chat-actions">
                        <button id="startVideoCall" title="Start Video Call">
                            <i class="fas fa-video"></i>
                        </button>
                        <button id="startVoiceCall" title="Start Voice Call">
                            <i class="fas fa-phone"></i>
                        </button>
                    </div>
                </div>
                <div class="chat-messages" id="chatMessages">
                    <div class="welcome-message">
                        <h2>Welcome to Scrambled Eggs Chat</h2>
                        <p>Select a user to start chatting or start a call.</p>
                    </div>
                </div>
                <div class="chat-input-container" style="display: none;">
                    <div class="typing-indicator" id="typingIndicator"></div>
                    <div class="input-group">
                        <textarea 
                            id="messageInput" 
                            placeholder="Type a message..."
                            rows="1"
                        ></textarea>
                        <button id="sendMessage">
                            <i class="fas fa-paper-plane"></i>
                        </button>
                    </div>
                    <div class="chat-options">
                        <button class="btn-icon" title="Send File">
                            <i class="fas fa-paperclip"></i>
                        </button>
                        <button class="btn-icon" title="Emoji">
                            <i class="far fa-smile"></i>
                        </button>
                        <button class="btn-icon" title="More options">
                            <i class="fas fa-ellipsis-h"></i>
                        </button>
                    </div>
                </div>
            </div>
        `;
    }

    /**
     * Initialize WebRTC manager
     */
    initializeWebRTC() {
        this.webrtcManager = new WebRTCManager(this.socket, this.userId);
        
        // Set up event handlers
        this.webrtcManager.onDataChannelOpen = (peerId, dataChannel) => {
            console.log(`Data channel with ${peerId} is open`);
            this.showChatInterface(peerId);
        };
        
        this.webrtcManager.onDataChannelMessage = (peerId, message) => {
            try {
                const data = JSON.parse(message);
                this.displayMessage(peerId, data.sender, data.content, data.timestamp, false);
            } catch (e) {
                console.error('Error parsing message:', e);
            }
        };
        
        this.webrtcManager.onPeerDisconnected = (peerId) => {
            console.log(`Peer ${peerId} disconnected`);
            this.updateUserStatus(peerId, false);
        };
    }

    /**
     * Set up event listeners
     */
    setupEventListeners() {
        // Send message on button click
        document.getElementById('sendMessage')?.addEventListener('click', () => this.sendMessage());
        
        // Send message on Enter key (with Shift+Enter for new line)
        document.getElementById('messageInput')?.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });
        
        // Auto-resize textarea
        document.getElementById('messageInput')?.addEventListener('input', (e) => {
            this.adjustTextareaHeight(e.target);
            this.sendTypingStatus();
        });
        
        // Start video call
        document.getElementById('startVideoCall')?.addEventListener('click', () => {
            const activeChat = this.getActiveChat();
            if (activeChat) {
                this.startVideoCall(activeChat);
            }
        });
        
        // Start voice call
        document.getElementById('startVoiceCall')?.addEventListener('click', () => {
            const activeChat = this.getActiveChat();
            if (activeChat) {
                this.startVoiceCall(activeChat);
            }
        });
        
        // Listen for online users updates
        this.socket.on('user_list', (users) => {
            this.updateOnlineUsers(users);
        });
        
        // Listen for user status changes
        this.socket.on('user_status', (data) => {
            this.updateUserStatus(data.userId, data.online);
        });
        
        // Listen for typing indicators
        this.socket.on('user_typing', (data) => {
            this.showTypingIndicator(data.from, data.isTyping);
        });
    }

    /**
     * Update the online users list
     */
    updateOnlineUsers(users) {
        const userList = document.getElementById('userList');
        if (!userList) return;
        
        userList.innerHTML = '';
        
        users.forEach(user => {
            if (user.id === this.userId) return; // Skip self
            
            const userElement = document.createElement('div');
            userElement.className = `user-item ${user.online ? 'online' : 'offline'}`;
            userElement.dataset.userId = user.id;
            userElement.innerHTML = `
                <div class="user-avatar">${user.id.charAt(0).toUpperCase()}</div>
                <div class="user-details">
                    <div class="user-name">${user.id}</div>
                    <div class="user-status">${user.online ? 'Online' : 'Offline'}</div>
                </div>
            `;
            
            userElement.addEventListener('click', () => this.startChat(user.id));
            userList.appendChild(userElement);
        });
    }

    /**
     * Update user status
     */
    updateUserStatus(userId, isOnline) {
        const userElement = document.querySelector(`.user-item[data-user-id="${userId}"]`);
        if (userElement) {
            userElement.classList.toggle('online', isOnline);
            userElement.classList.toggle('offline', !isOnline);
            
            const statusElement = userElement.querySelector('.user-status');
            if (statusElement) {
                statusElement.textContent = isOnline ? 'Online' : 'Offline';
            }
        }
    }

    /**
     * Start a chat with a user
     */
    async startChat(peerId) {
        // If chat already exists, just show it
        if (this.activeChats.has(peerId)) {
            this.showChat(peerId);
            return;
        }
        
        // Create chat UI
        this.createChatUI(peerId);
        
        try {
            // Initiate WebRTC connection
            await this.webrtcManager.callPeer(peerId);
            this.showChat(peerId);
        } catch (error) {
            console.error('Error starting chat:', error);
            this.showError(`Failed to start chat with ${peerId}`);
        }
    }

    /**
     * Create chat UI for a peer
     */
    createChatUI(peerId) {
        const chatId = `chat-${peerId}`;
        const chatElement = document.createElement('div');
        chatElement.className = 'chat-window';
        chatElement.id = chatId;
        chatElement.dataset.peerId = peerId;
        chatElement.style.display = 'none';
        
        chatElement.innerHTML = `
            <div class="chat-header">
                <div class="chat-partner">
                    <div class="avatar">${peerId.charAt(0).toUpperCase()}</div>
                    <div class="info">
                        <div class="name">${peerId}</div>
                        <div class="status">typing...</div>
                    </div>
                </div>
                <div class="chat-actions">
                    <button class="btn-icon" title="Voice Call">
                        <i class="fas fa-phone"></i>
                    </button>
                    <button class="btn-icon" title="Video Call">
                        <i class="fas fa-video"></i>
                    </button>
                    <button class="btn-icon" title="More options">
                        <i class="fas fa-ellipsis-v"></i>
                    </button>
                </div>
            </div>
            <div class="chat-messages" id="messages-${peerId}"></div>
            <div class="chat-input">
                <div class="typing-indicator" id="typing-${peerId}"></div>
                <div class="input-group">
                    <textarea 
                        id="input-${peerId}" 
                        placeholder="Type a message..."
                        rows="1"
                    ></textarea>
                    <button class="send-button" data-peer-id="${peerId}">
                        <i class="fas fa-paper-plane"></i>
                    </button>
                </div>
                <div class="chat-options">
                    <button class="btn-icon" title="Send File">
                        <i class="fas fa-paperclip"></i>
                    </button>
                    <button class="btn-icon" title="Emoji">
                        <i class="far fa-smile"></i>
                    </button>
                </div>
            </div>
        `;
        
        // Add to DOM
        document.getElementById('chatMessages').appendChild(chatElement);
        
        // Store reference
        this.activeChats.set(peerId, {
            element: chatElement,
            messageHistory: [],
            input: chatElement.querySelector(`#input-${peerId}`),
            messagesContainer: chatElement.querySelector(`#messages-${peerId}`),
            typingIndicator: chatElement.querySelector(`#typing-${peerId}`),
            lastTypingTime: 0
        });
        
        // Set up event listeners for this chat
        this.setupChatEventListeners(peerId);
    }

    /**
     * Set up event listeners for a chat
     */
    setupChatEventListeners(peerId) {
        const chat = this.activeChats.get(peerId);
        if (!chat) return;
        
        // Send message on button click
        chat.element.querySelector('.send-button').addEventListener('click', () => {
            this.sendMessage(peerId);
        });
        
        // Send message on Enter key (with Shift+Enter for new line)
        chat.input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage(peerId);
            }
        });
        
        // Auto-resize textarea
        chat.input.addEventListener('input', (e) => {
            this.adjustTextareaHeight(e.target);
            this.sendTypingStatus(peerId, true);
        });
        
        // Handle blur to stop typing indicator
        chat.input.addEventListener('blur', () => {
            this.sendTypingStatus(peerId, false);
        });
    }

    /**
     * Show chat interface for a specific peer
     */
    showChat(peerId) {
        // Hide all chats
        document.querySelectorAll('.chat-window').forEach(chat => {
            chat.style.display = 'none';
        });
        
        // Show the selected chat
        const chat = this.activeChats.get(peerId);
        if (chat) {
            chat.element.style.display = 'flex';
            chat.input.focus();
            
            // Mark messages as read
            this.markMessagesAsRead(peerId);
        }
        
        // Show input container if not already shown
        document.querySelector('.chat-input-container').style.display = 'block';
    }

    /**
     * Send a message to a peer
     */
    sendMessage(peerId) {
        const chat = this.activeChats.get(peerId);
        if (!chat || !chat.input.value.trim()) return;
        
        const message = {
            type: 'text',
            content: chat.input.value,
            sender: this.userId,
            timestamp: new Date().toISOString()
        };
        
        // Send via WebRTC data channel
        const success = this.webrtcManager.sendMessage(peerId, message);
        
        if (success) {
            // Add to local message history
            this.displayMessage(peerId, this.userId, message.content, message.timestamp, true);
            
            // Clear input
            chat.input.value = '';
            this.adjustTextareaHeight(chat.input);
            
            // Send typing stopped
            this.sendTypingStatus(peerId, false);
        } else {
            this.showError('Failed to send message. Please try again.');
        }
    }

    /**
     * Display a message in the chat
     */
    displayMessage(peerId, sender, content, timestamp, isOutgoing) {
        const chat = this.activeChats.get(peerId);
        if (!chat) return;
        
        const messageElement = document.createElement('div');
        messageElement.className = `message ${isOutgoing ? 'outgoing' : 'incoming'}`;
        
        const time = new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        
        messageElement.innerHTML = `
            <div class="message-content">${content}</div>
            <div class="message-time">${time}</div>
        `;
        
        chat.messagesContainer.appendChild(messageElement);
        chat.messagesContainer.scrollTop = chat.messagesContainer.scrollHeight;
        
        // Add to message history
        chat.messageHistory.push({
            sender,
            content,
            timestamp,
            isOutgoing
        });
    }

    /**
     * Show typing indicator
     */
    showTypingIndicator(peerId, isTyping) {
        const chat = this.activeChats.get(peerId);
        if (!chat) return;
        
        const now = Date.now();
        
        if (isTyping) {
            chat.typingIndicator.textContent = `${peerId} is typing...`;
            chat.typingIndicator.style.display = 'block';
            chat.lastTypingTime = now;
            
            // Auto-hide after 3 seconds of no typing
            setTimeout(() => {
                if (now === chat.lastTypingTime) {
                    chat.typingIndicator.style.display = 'none';
                }
            }, 3000);
        } else {
            chat.typingIndicator.style.display = 'none';
        }
    }

    /**
     * Send typing status to peer
     */
    sendTypingStatus(peerId, isTyping) {
        this.socket.emit('typing', {
            to: peerId,
            isTyping
        });
    }

    /**
     * Mark messages as read
     */
    markMessagesAsRead(peerId) {
        const chat = this.activeChats.get(peerId);
        if (!chat) return;
        
        // Update UI to show messages as read
        chat.element.querySelectorAll('.message').forEach(msg => {
            if (!msg.classList.contains('read')) {
                msg.classList.add('read');
            }
        });
    }

    /**
     * Start a video call
     */
    async startVideoCall(peerId) {
        // Implementation for starting a video call
        console.log(`Starting video call with ${peerId}`);
        // This would involve setting up video tracks and handling the call UI
    }

    /**
     * Start a voice call
     */
    async startVoiceCall(peerId) {
        // Implementation for starting a voice call
        console.log(`Starting voice call with ${peerId}`);
        // This would involve setting up audio tracks and handling the call UI
    }

    /**
     * Get the currently active chat
     */
    getActiveChat() {
        const activeChat = document.querySelector('.chat-window[style*="display: flex"]');
        return activeChat ? activeChat.dataset.peerId : null;
    }

    /**
     * Adjust textarea height based on content
     */
    adjustTextareaHeight(textarea) {
        textarea.style.height = 'auto';
        textarea.style.height = `${Math.min(textarea.scrollHeight, 120)}px`;
    }

    /**
     * Show error message
     */
    showError(message) {
        // Implement error display logic
        console.error(message);
    }
}

export default ChatManager;
