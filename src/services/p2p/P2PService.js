import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import { see } from '../encryption/ScrambledEggsEncryption';

// Default configuration
const DEFAULT_CONFIG = {
  iceServers: [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
    { urls: 'stun:stun2.l.google.com:19302' },
  ],
  sdpSemantics: 'unified-plan',
  bundlePolicy: 'max-bundle',
  rtcpMuxPolicy: 'require',
  iceCandidatePoolSize: 10,
};

// Message types for signaling
const MESSAGE_TYPES = {
  OFFER: 'offer',
  ANSWER: 'answer',
  ICE_CANDIDATE: 'ice-candidate',
  FILE_METADATA: 'file-metadata',
  FILE_CHUNK: 'file-chunk',
  FILE_ACK: 'file-ack',
  PING: 'ping',
  PONG: 'pong',
};

// Default chunk size for file transfers (64KB)
const DEFAULT_CHUNK_SIZE = 64 * 1024;

export class P2PService extends EventEmitter {
  constructor(config = {}) {
    super();
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.peers = new Map(); // peerId -> { connection, channels, metadata }
    this.dataChannels = new Map(); // dataChannelLabel -> { peerId, channel, metadata }
    this.pendingOffers = new Map(); // offerId -> { resolve, reject, timeout }
    this.fileTransfers = new Map(); // transferId -> { file, peerId, chunkSize, chunksSent, totalChunks, metadata }
    this.connectionStats = new Map(); // peerId -> { bytesSent, bytesReceived, startTime, lastActivity }
    this.isInitialized = false;
    this.localPeerId = uuidv4();
    this.signalingServer = null;
    this.iceServers = [];
    this.iceCandidateQueue = new Map(); // peerId -> [candidate]
    this.reconnectionAttempts = 0;
    this.maxReconnectionAttempts = 5;
    this.reconnectionDelay = 1000; // Start with 1 second delay
  }

  // Initialize the P2P service
  async initialize(signalingServer) {
    if (this.isInitialized) return;

    this.signalingServer = signalingServer;
    this.setupSignalingHandlers();

    // Initialize ICE servers
    await this.updateIceServers();

    // Set up periodic reconnection checks
    this.reconnectionInterval = setInterval(
      () => this.checkConnections(),
      30000 // Check every 30 seconds
    );

    this.isInitialized = true;
    this.emit('initialized');
  }

  // Set up WebSocket message handlers
  setupSignalingHandlers() {
    if (!this.signalingServer) return;

    this.signalingServer.on('message', async (message) => {
      try {
        const { type, from, data } = this.validateMessage(message);
        
        switch (type) {
          case MESSAGE_TYPES.OFFER:
            await this.handleOffer(from, data);
            break;
          case MESSAGE_TYPES.ANSWER:
            await this.handleAnswer(from, data);
            break;
          case MESSAGE_TYPES.ICE_CANDIDATE:
            await this.handleIceCandidate(from, data);
            break;
          case MESSAGE_TYPES.FILE_METADATA:
            await this.handleFileMetadata(from, data);
            break;
          case MESSAGE_TYPES.FILE_CHUNK:
            await this.handleFileChunk(from, data);
            break;
          case MESSAGE_TYPES.FILE_ACK:
            await this.handleFileAck(from, data);
            break;
          case MESSAGE_TYPES.PING:
            await this.sendSignalingMessage(from, { type: MESSAGE_TYPES.PONG });
            break;
          default:
            console.warn('Unknown message type:', type);
        }
      } catch (error) {
        console.error('Error processing signaling message:', error);
        this.emit('error', { type: 'signaling_error', error, message });
      }
    });
  }

  // Validate and parse incoming messages
  validateMessage(message) {
    if (!message || typeof message !== 'object') {
      throw new Error('Invalid message format');
    }

    const { type, from, data } = message;
    
    if (!type || !MESSAGE_TYPES[type.toUpperCase()]) {
      throw new Error(`Invalid message type: ${type}`);
    }

    if (!from || typeof from !== 'string') {
      throw new Error('Missing or invalid sender ID');
    }

    if (data === undefined) {
      throw new Error('Missing message data');
    }

    return { type, from, data };
  }

  // Connect to a peer
  async connect(peerId, metadata = {}) {
    if (this.peers.has(peerId)) {
      console.warn(`Already connected to peer ${peerId}`);
      return this.peers.get(peerId).connection;
    }

    try {
      const connection = new RTCPeerConnection(this.config);
      this.setupConnectionHandlers(connection, peerId);
      
      // Create a reliable data channel for control messages
      const controlChannel = connection.createDataChannel('control', {
        ordered: true,
        maxRetransmits: 10,
      });
      
      this.setupDataChannel(controlChannel, peerId, { isControl: true });
      
      // Store peer information
      this.peers.set(peerId, {
        connection,
        channels: new Map([['control', controlChannel]]),
        metadata,
        connected: false,
        connectionTime: null,
      });
      
      // Initialize connection stats
      this.connectionStats.set(peerId, {
        bytesSent: 0,
        bytesReceived: 0,
        startTime: Date.now(),
        lastActivity: Date.now(),
        packetsSent: 0,
        packetsReceived: 0,
      });

      // Create and send offer
      const offer = await connection.createOffer({
        offerToReceiveAudio: true,
        offerToReceiveVideo: true,
      });
      
      await connection.setLocalDescription(offer);
      
      // Encrypt the offer before sending
      const encryptedOffer = await see.encrypt({
        type: MESSAGE_TYPES.OFFER,
        sdp: offer.sdp,
        metadata,
      });
      
      await this.sendSignalingMessage(peerId, {
        type: MESSAGE_TYPES.OFFER,
        data: encryptedOffer,
      });

      return connection;
    } catch (error) {
      console.error('Error creating peer connection:', error);
      this.cleanupPeer(peerId);
      throw error;
    }
  }

  // Handle incoming offer
  async handleOffer(from, encryptedOffer) {
    if (this.peers.has(from)) {
      console.warn(`Already connected to peer ${from}, ignoring offer`);
      return;
    }

    try {
      // Decrypt the offer
      const { sdp, metadata } = await see.decrypt(
        encryptedOffer.encryptedData,
        encryptedOffer.layerId,
        encryptedOffer.nonce,
        encryptedOffer.authTag
      );

      const connection = new RTCPeerConnection(this.config);
      this.setupConnectionHandlers(connection, from);
      
      // Store peer information
      this.peers.set(from, {
        connection,
        channels: new Map(),
        metadata,
        connected: false,
        connectionTime: null,
      });
      
      // Initialize connection stats
      this.connectionStats.set(from, {
        bytesSent: 0,
        bytesReceived: 0,
        startTime: Date.now(),
        lastActivity: Date.now(),
        packetsSent: 0,
        packetsReceived: 0,
      });

      // Set remote description
      await connection.setRemoteDescription({
        type: 'offer',
        sdp,
      });

      // Create and send answer
      const answer = await connection.createAnswer();
      await connection.setLocalDescription(answer);
      
      // Encrypt the answer
      const encryptedAnswer = await see.encrypt({
        type: MESSAGE_TYPES.ANSWER,
        sdp: answer.sdp,
      });
      
      await this.sendSignalingMessage(from, {
        type: MESSAGE_TYPES.ANSWER,
        data: encryptedAnswer,
      });

      // Set up data channel handler for incoming channels
      connection.ondatachannel = (event) => {
        const { channel } = event;
        const isControl = channel.label === 'control';
        this.setupDataChannel(channel, from, { isControl });
      };
    } catch (error) {
      console.error('Error handling offer:', error);
      this.cleanupPeer(from);
      throw error;
    }
  }

  // Handle incoming answer
  async handleAnswer(from, encryptedAnswer) {
    const peer = this.peers.get(from);
    if (!peer) {
      console.warn(`Received answer from unknown peer: ${from}`);
      return;
    }

    try {
      // Decrypt the answer
      const { sdp } = await see.decrypt(
        encryptedAnswer.encryptedData,
        encryptedAnswer.layerId,
        encryptedAnswer.nonce,
        encryptedAnswer.authTag
      );

      await peer.connection.setRemoteDescription({
        type: 'answer',
        sdp,
      });
    } catch (error) {
      console.error('Error handling answer:', error);
      this.cleanupPeer(from);
      throw error;
    }
  }

  // Handle ICE candidates
  async handleIceCandidate(from, candidateData) {
    const peer = this.peers.get(from);
    if (!peer) {
      // Queue the candidate in case the peer connects soon
      if (!this.iceCandidateQueue.has(from)) {
        this.iceCandidateQueue.set(from, []);
      }
      this.iceCandidateQueue.get(from).push(candidateData);
      return;
    }

    try {
      const candidate = new RTCIceCandidate(candidateData);
      await peer.connection.addIceCandidate(candidate);
    } catch (error) {
      console.error('Error adding ICE candidate:', error);
      this.emit('error', { type: 'ice_error', error, peerId: from });
    }
  }

  // Set up WebRTC connection event handlers
  setupConnectionHandlers(connection, peerId) {
    connection.onicecandidate = (event) => {
      if (event.candidate) {
        this.sendSignalingMessage(peerId, {
          type: MESSAGE_TYPES.ICE_CANDIDATE,
          data: event.candidate.toJSON(),
        }).catch(console.error);
      }
    };

    connection.oniceconnectionstatechange = () => {
      const connectionState = connection.iceConnectionState;
      console.log(`ICE connection state (${peerId}):`, connectionState);
      
      const peer = this.peers.get(peerId);
      if (peer) {
        peer.iceState = connectionState;
        
        if (connectionState === 'connected' || connectionState === 'completed') {
          if (!peer.connected) {
            peer.connected = true;
            peer.connectionTime = new Date();
            this.emit('peer:connected', { peerId, metadata: peer.metadata });
            
            // Process any queued ICE candidates
            this.processQueuedCandidates(peerId);
          }
        } else if (connectionState === 'disconnected' || 
                  connectionState === 'failed' || 
                  connectionState === 'closed') {
          if (peer.connected) {
            peer.connected = false;
            this.emit('peer:disconnected', { 
              peerId, 
              reason: connectionState,
              stats: this.connectionStats.get(peerId),
            });
            
            // Attempt to reconnect if this was unexpected
            if (connectionState !== 'closed') {
              this.scheduleReconnect(peerId);
            }
          }
        }
      }
    };

    connection.onnegotiationneeded = async () => {
      console.log('Negotiation needed for peer:', peerId);
      // Handle renegotiation if needed
    };

    connection.onsignalingstatechange = () => {
      console.log(`Signaling state (${peerId}):`, connection.signalingState);
    };

    // Track connection statistics
    connection.onconnectionstatechange = () => {
      console.log(`Connection state (${peerId}):`, connection.connectionState);
    };
  }

  // Process any queued ICE candidates for a peer
  processQueuedCandidates(peerId) {
    if (!this.iceCandidateQueue.has(peerId)) return;
    
    const queue = this.iceCandidateQueue.get(peerId);
    const peer = this.peers.get(peerId);
    
    if (!peer || !peer.connected) return;
    
    console.log(`Processing ${queue.length} queued ICE candidates for ${peerId}`);
    
    const processNext = async () => {
      if (queue.length === 0) {
        this.iceCandidateQueue.delete(peerId);
        return;
      }
      
      const candidate = queue.shift();
      try {
        await peer.connection.addIceCandidate(new RTCIceCandidate(candidate));
        processNext();
      } catch (error) {
        console.error('Error processing queued ICE candidate:', error);
      }
    };
    
    processNext();
  }

  // Schedule a reconnection attempt
  scheduleReconnect(peerId) {
    if (this.reconnectionAttempts >= this.maxReconnectionAttempts) {
      console.warn(`Max reconnection attempts (${this.maxReconnectionAttempts}) reached for peer ${peerId}`);
      this.emit('peer:reconnection_failed', { peerId });
      return;
    }
    
    const delay = this.reconnectionDelay * Math.pow(2, this.reconnectionAttempts);
    this.reconnectionAttempts++;
    
    console.log(`Scheduling reconnection attempt ${this.reconnectionAttempts} in ${delay}ms`);
    
    setTimeout(async () => {
      try {
        await this.reconnect(peerId);
        this.reconnectionAttempts = 0; // Reset on successful reconnect
      } catch (error) {
        console.error(`Reconnection attempt ${this.reconnectionAttempts} failed:`, error);
        this.scheduleReconnect(peerId); // Try again with exponential backoff
      }
    }, delay);
  }

  // Attempt to reconnect to a peer
  async reconnect(peerId) {
    const peer = this.peers.get(peerId);
    if (!peer) {
      throw new Error(`Cannot reconnect to unknown peer: ${peerId}`);
    }
    
    console.log(`Attempting to reconnect to ${peerId}...`);
    
    // Close the existing connection
    this.cleanupPeer(peerId, false);
    
    // Create a new connection
    return this.connect(peerId, peer.metadata);
  }

  // Set up a data channel
  setupDataChannel(channel, peerId, options = {}) {
    const { isControl = false } = options;
    const channelLabel = channel.label;
    
    console.log(`Data channel ${channelLabel} ${isControl ? '(control)' : ''} established with ${peerId}`);
    
    // Store the channel
    const peer = this.peers.get(peerId);
    if (peer) {
      peer.channels.set(channelLabel, channel);
    }
    
    // Set up event handlers
    channel.onopen = () => {
      console.log(`Data channel ${channelLabel} with ${peerId} is open`);
      this.emit('channel:open', { peerId, channelLabel, isControl });
    };
    
    channel.onclose = () => {
      console.log(`Data channel ${channelLabel} with ${peerId} is closed`);
      this.emit('channel:close', { peerId, channelLabel, isControl });
    };
    
    channel.onerror = (error) => {
      console.error(`Data channel ${channelLabel} error:`, error);
      this.emit('error', { 
        type: 'data_channel_error', 
        error, 
        peerId, 
        channelLabel 
      });
    };
    
    channel.onmessage = async (event) => {
      try {
        const stats = this.connectionStats.get(peerId);
        if (stats) {
          stats.bytesReceived += event.data.size || event.data.length || 0;
          stats.packetsReceived++;
          stats.lastActivity = Date.now();
        }
        
        // Handle control messages
        if (isControl) {
          await this.handleControlMessage(peerId, event.data);
        } else {
          // For non-control channels, emit the message
          this.emit('message', {
            peerId,
            channel: channelLabel,
            data: event.data,
          });
        }
      } catch (error) {
        console.error('Error handling data channel message:', error);
        this.emit('error', { 
          type: 'message_handling_error', 
          error, 
          peerId, 
          channelLabel 
        });
      }
    };
    
    // Track when the channel is actually ready
    channel.onbufferedamountlow = () => {
      this.emit('channel:bufferedamountlow', { 
        peerId, 
        channelLabel, 
        bufferedAmount: channel.bufferedAmount 
      });
    };
  }

  // Handle control channel messages
  async handleControlMessage(peerId, data) {
    try {
      // In a real implementation, we would parse and handle different control messages
      // For now, we'll just emit a generic control message event
      this.emit('control:message', { peerId, data });
    } catch (error) {
      console.error('Error handling control message:', error);
      this.emit('error', { 
        type: 'control_message_error', 
        error, 
        peerId 
      });
    }
  }

  // Send a message to a peer over a data channel
  async send(peerId, data, channelLabel = 'default') {
    const peer = this.peers.get(peerId);
    if (!peer || !peer.connected) {
      throw new Error(`Not connected to peer ${peerId}`);
    }
    
    let channel = peer.channels.get(channelLabel);
    
    // Create a new data channel if it doesn't exist
    if (!channel) {
      channel = peer.connection.createDataChannel(channelLabel, {
        ordered: true,
        maxRetransmits: 5,
      });
      
      this.setupDataChannel(channel, peerId, { isControl: channelLabel === 'control' });
      
      // Wait for the channel to be open
      await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error(`Timeout waiting for channel ${channelLabel} to open`));
        }, 10000); // 10 second timeout
        
        channel.onopen = () => {
          clearTimeout(timeout);
          resolve();
        };
        
        channel.onerror = (error) => {
          clearTimeout(timeout);
          reject(error);
        };
      });
    }
    
    // Send the data
    try {
      channel.send(data);
      
      // Update statistics
      const stats = this.connectionStats.get(peerId);
      if (stats) {
        stats.bytesSent += data.size || data.length || 0;
        stats.packetsSent++;
        stats.lastActivity = Date.now();
      }
      
      return true;
    } catch (error) {
      console.error(`Error sending data to ${peerId} on channel ${channelLabel}:`, error);
      this.emit('error', { 
        type: 'send_error', 
        error, 
        peerId, 
        channelLabel 
      });
      
      // If the channel is in a bad state, try to recover
      if (channel.readyState !== 'open') {
        console.warn(`Channel ${channelLabel} is not open, attempting to recover...`);
        peer.channels.delete(channelLabel);
        return this.send(peerId, data, channelLabel);
      }
      
      throw error;
    }
  }

  // Send a file to a peer
  async sendFile(peerId, file, options = {}) {
    const transferId = uuidv4();
    const chunkSize = options.chunkSize || DEFAULT_CHUNK_SIZE;
    const channelLabel = options.channel || 'file-transfer';
    
    // Prepare file metadata
    const metadata = {
      name: file.name,
      type: file.type,
      size: file.size,
      lastModified: file.lastModified,
      transferId,
      chunkSize,
      totalChunks: Math.ceil(file.size / chunkSize),
      timestamp: Date.now(),
    };
    
    // Store transfer information
    this.fileTransfers.set(transferId, {
      file,
      peerId,
      chunkSize,
      chunksSent: 0,
      totalChunks: metadata.totalChunks,
      metadata,
      startTime: Date.now(),
      channelLabel,
    });
    
    // Send metadata first
    await this.send(peerId, {
      type: 'file-metadata',
      data: metadata,
    }, channelLabel);
    
    // Start sending chunks
    await this.sendNextChunk(transferId);
    
    return transferId;
  }

  // Send the next chunk of a file transfer
  async sendNextChunk(transferId) {
    const transfer = this.fileTransfers.get(transferId);
    if (!transfer) {
      console.warn(`Transfer ${transferId} not found`);
      return;
    }
    
    const { file, peerId, chunkSize, chunksSent, channelLabel } = transfer;
    
    // Check if transfer is complete
    if (chunksSent >= transfer.totalChunks) {
      console.log(`File transfer ${transferId} complete`);
      this.fileTransfers.delete(transferId);
      this.emit('file:complete', { 
        transferId, 
        peerId, 
        metadata: transfer.metadata 
      });
      return;
    }
    
    // Read the next chunk
    const offset = chunksSent * chunkSize;
    const chunk = file.slice(offset, offset + chunkSize);
    
    try {
      // In a real implementation, we would read the chunk as an ArrayBuffer
      // and send it over the data channel
      const arrayBuffer = await this.readFileChunk(chunk);
      
      await this.send(peerId, {
        type: 'file-chunk',
        data: {
          transferId,
          chunkIndex: chunksSent,
          data: arrayBuffer,
          isLast: (offset + chunkSize) >= file.size,
        },
      }, channelLabel);
      
      // Update transfer progress
      transfer.chunksSent++;
      
      // Emit progress event
      const progress = (transfer.chunksSent / transfer.totalChunks) * 100;
      this.emit('file:progress', { 
        transferId, 
        peerId, 
        progress,
        bytesTransferred: transfer.chunksSent * chunkSize,
        totalBytes: file.size,
      });
      
      // Send next chunk
      await this.sendNextChunk(transferId);
      
    } catch (error) {
      console.error(`Error sending chunk ${chunksSent} of ${transferId}:`, error);
      this.emit('file:error', { 
        transferId, 
        peerId, 
        error,
        chunk: chunksSent,
      });
    }
  }

  // Helper to read a file chunk as ArrayBuffer
  readFileChunk(chunk) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = reject;
      reader.readAsArrayBuffer(chunk);
    });
  }

  // Handle incoming file metadata
  async handleFileMetadata(from, metadata) {
    const { transferId } = metadata;
    
    this.emit('file:incoming', {
      transferId,
      peerId: from,
      metadata,
      accept: async (options = {}) => {
        // In a real implementation, we would set up to receive the file
        this.emit('file:accepted', { transferId, peerId: from, options });
        
        // Send ACK to sender
        await this.send(from, {
          type: 'file-ack',
          data: { transferId, accepted: true },
        }, metadata.channelLabel || 'file-transfer');
      },
      
      reject: async (reason = '') => {
        // Notify sender that the transfer was rejected
        await this.send(from, {
          type: 'file-ack',
          data: { transferId, accepted: false, reason },
        }, metadata.channelLabel || 'file-transfer');
        
        this.emit('file:rejected', { transferId, peerId: from, reason });
      },
    });
  }

  // Handle incoming file chunks
  async handleFileChunk(from, chunkData) {
    const { transferId, chunkIndex, data, isLast } = chunkData;
    
    this.emit('file:chunk', {
      transferId,
      peerId: from,
      chunkIndex,
      data,
      isLast,
      ack: async () => {
        await this.send(from, {
          type: 'file-chunk-ack',
          data: { transferId, chunkIndex, received: true },
        });
      },
    });
  }

  // Handle file transfer ACK
  async handleFileAck(from, ackData) {
    const { transferId, accepted, reason } = ackData;
    
    if (accepted) {
      this.emit('file:acknowledged', { transferId, peerId: from });
    } else {
      this.emit('file:rejected', { 
        transferId, 
        peerId: from, 
        reason: reason || 'Transfer rejected by peer' 
      });
      
      // Clean up the transfer
      this.fileTransfers.delete(transferId);
    }
  }

  // Check all connections and attempt to reconnect if needed
  async checkConnections() {
    const now = Date.now();
    const disconnectedPeers = [];
    
    // Check for disconnected peers
    for (const [peerId, peer] of this.peers.entries()) {
      const stats = this.connectionStats.get(peerId);
      if (!peer.connected && stats) {
        const timeSinceLastActivity = now - stats.lastActivity;
        
        // If we haven't heard from the peer in a while, try to reconnect
        if (timeSinceLastActivity > 30000) { // 30 seconds
          console.log(`Peer ${peerId} appears to be disconnected, attempting to reconnect...`);
          disconnectedPeers.push(peerId);
        }
      }
    }
    
    // Attempt to reconnect to disconnected peers
    for (const peerId of disconnectedPeers) {
      try {
        await this.reconnect(peerId);
      } catch (error) {
        console.error(`Failed to reconnect to ${peerId}:`, error);
      }
    }
    
    // Send keep-alive pings to all connected peers
    for (const [peerId, peer] of this.peers.entries()) {
      if (peer.connected && peer.channels.has('control')) {
        try {
          await this.send(peerId, { type: MESSAGE_TYPES.PING }, 'control');
        } catch (error) {
          console.error(`Failed to send ping to ${peerId}:`, error);
        }
      }
    }
  }

  // Update ICE servers (e.g., from a TURN/STUN server)
  async updateIceServers() {
    try {
      // In a real implementation, you would fetch ICE servers from your signaling server
      // or a TURN/STUN service
      const response = await fetch('/api/ice-servers');
      const { iceServers } = await response.json();
      
      if (iceServers && iceServers.length > 0) {
        this.config.iceServers = iceServers;
        this.emit('iceServers:updated', { iceServers });
      }
    } catch (error) {
      console.error('Failed to update ICE servers:', error);
      this.emit('error', { 
        type: 'ice_servers_error', 
        error 
      });
    }
  }

  // Send a signaling message through the signaling server
  async sendSignalingMessage(to, message) {
    if (!this.signalingServer) {
      throw new Error('Signaling server not initialized');
    }
    
    return new Promise((resolve, reject) => {
      try {
        this.signalingServer.send({
          to,
          from: this.localPeerId,
          ...message,
        });
        resolve();
      } catch (error) {
        reject(error);
      }
    });
  }

  // Get connection statistics for a peer
  getStats(peerId) {
    const stats = this.connectionStats.get(peerId);
    if (!stats) return null;
    
    const now = Date.now();
    const duration = (now - stats.startTime) / 1000; // in seconds
    
    return {
      ...stats,
      duration,
      averageBitrate: stats.bytesSent / duration * 8, // bits per second
      averagePacketSize: stats.bytesSent / Math.max(1, stats.packetsSent),
      lastActivity: new Date(stats.lastActivity).toISOString(),
    };
  }

  // Get all connected peers
  getConnectedPeers() {
    return Array.from(this.peers.entries())
      .filter(([_, peer]) => peer.connected)
      .map(([peerId, peer]) => ({
        peerId,
        ...peer,
        stats: this.getStats(peerId),
      }));
  }

  // Close a connection to a peer
  async disconnect(peerId) {
    const peer = this.peers.get(peerId);
    if (!peer) return;
    
    // Close all data channels
    for (const [label, channel] of peer.channels.entries()) {
      try {
        channel.close();
        this.emit('channel:closed', { peerId, channelLabel: label });
      } catch (error) {
        console.error(`Error closing channel ${label}:`, error);
      }
    }
    
    // Close the RTCPeerConnection
    try {
      peer.connection.close();
      this.emit('peer:disconnected', { 
        peerId, 
        reason: 'user_disconnect',
        stats: this.connectionStats.get(peerId),
      });
    } catch (error) {
      console.error(`Error closing connection to ${peerId}:`, error);
    }
    
    // Clean up
    this.cleanupPeer(peerId);
  }

  // Clean up resources for a peer
  cleanupPeer(peerId, emitEvent = true) {
    const peer = this.peers.get(peerId);
    if (!peer) return;
    
    // Close all data channels
    for (const [label, channel] of peer.channels.entries()) {
      try {
        if (channel.readyState !== 'closed') {
          channel.close();
        }
      } catch (error) {
        console.error(`Error closing channel ${label}:`, error);
      }
    }
    
    // Close the RTCPeerConnection
    try {
      if (peer.connection.signalingState !== 'closed') {
        peer.connection.close();
      }
    } catch (error) {
      console.error(`Error closing connection to ${peerId}:`, error);
    }
    
    // Remove from tracking
    this.peers.delete(peerId);
    this.connectionStats.delete(peerId);
    
    // Remove any queued ICE candidates
    this.iceCandidateQueue.delete(peerId);
    
    // Emit event if requested
    if (emitEvent) {
      this.emit('peer:removed', { peerId });
    }
  }

  // Clean up all resources
  destroy() {
    // Clear reconnection interval
    if (this.reconnectionInterval) {
      clearInterval(this.reconnectionInterval);
      this.reconnectionInterval = null;
    }
    
    // Disconnect from all peers
    for (const peerId of this.peers.keys()) {
      this.cleanupPeer(peerId, false);
    }
    
    // Clear all data structures
    this.peers.clear();
    this.dataChannels.clear();
    this.pendingOffers.clear();
    this.fileTransfers.clear();
    this.connectionStats.clear();
    this.iceCandidateQueue.clear();
    
    // Reset state
    this.isInitialized = false;
    this.reconnectionAttempts = 0;
    
    // Emit destroy event
    this.emit('destroyed');
    
    // Remove all listeners
    this.removeAllListeners();
  }
}

// Create a singleton instance
export const p2pService = new P2PService();

// Auto-cleanup on page unload
if (typeof window !== 'undefined') {
  window.addEventListener('beforeunload', () => {
    p2pService.destroy();
  });
}
