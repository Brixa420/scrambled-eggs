import { io } from 'socket.io-client';
import { v4 as uuidv4 } from 'uuid';

export class WebRTCService {
  constructor() {
    this.peerConnections = {};
    this.localStream = null;
    this.socket = null;
    this.configuration = {
      iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        // Add TURN servers here for relay
      ]
    };
  }

  async initialize(socket) {
    this.socket = socket;
    this.setupSocketListeners();
    try {
      this.localStream = await navigator.mediaDevices.getUserMedia({
        audio: true,
        video: true
      });
      return this.localStream;
    } catch (error) {
      console.error('Error accessing media devices:', error);
      throw error;
    }
  }

  setupSocketListeners() {
    this.socket.on('offer', async (data) => {
      const { from, offer } = data;
      const peerConnection = this.createPeerConnection(from);
      
      await peerConnection.setRemoteDescription(new RTCSessionDescription(offer));
      const answer = await peerConnection.createAnswer();
      await peerConnection.setLocalDescription(answer);
      
      this.socket.emit('answer', { to: from, answer });
    });

    this.socket.on('answer', async (data) => {
      const { from, answer } = data;
      const peerConnection = this.peerConnections[from];
      if (peerConnection) {
        await peerConnection.setRemoteDescription(new RTCSessionDescription(answer));
      }
    });

    this.socket.on('ice-candidate', (data) => {
      const { from, candidate } = data;
      const peerConnection = this.peerConnections[from];
      if (peerConnection && candidate) {
        peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
      }
    });

    this.socket.on('end-call', (from) => {
      this.closePeerConnection(from);
    });
  }

  createPeerConnection(userId) {
    const peerConnection = new RTCPeerConnection(this.configuration);
    
    // Add local stream to connection
    if (this.localStream) {
      this.localStream.getTracks().forEach(track => {
        peerConnection.addTrack(track, this.localStream);
      });
    }

    // ICE candidate handling
    peerConnection.onicecandidate = (event) => {
      if (event.candidate) {
        this.socket.emit('ice-candidate', {
          to: userId,
          candidate: event.candidate
        });
      }
    };

    // Track remote streams
    peerConnection.ontrack = (event) => {
      // Emit event to update UI with remote stream
      const eventName = `stream-${userId}`;
      this.socket.emit(eventName, event.streams[0]);
    };

    this.peerConnections[userId] = peerConnection;
    return peerConnection;
  }

  async startCall(userId) {
    const peerConnection = this.createPeerConnection(userId);
    
    const offer = await peerConnection.createOffer();
    await peerConnection.setLocalDescription(offer);
    
    this.socket.emit('offer', {
      to: userId,
      offer: peerConnection.localDescription
    });
  }

  endCall(userId) {
    this.closePeerConnection(userId);
    this.socket.emit('end-call', { to: userId });
  }

  closePeerConnection(userId) {
    const peerConnection = this.peerConnections[userId];
    if (peerConnection) {
      peerConnection.close();
      delete this.peerConnections[userId];
    }
  }

  // File sharing methods
  async sendFile(userId, file) {
    const peerConnection = this.peerConnections[userId];
    if (!peerConnection) {
      throw new Error('No active connection to send file');
    }

    const channel = peerConnection.createDataChannel('fileTransfer');
    const fileId = uuidv4();
    const chunkSize = 16 * 1024; // 16KB chunks
    let offset = 0;

    channel.binaryType = 'arraybuffer';
    
    channel.onopen = () => {
      // Send file metadata first
      channel.send(JSON.stringify({
        type: 'metadata',
        name: file.name,
        size: file.size,
        mime: file.type,
        id: fileId
      }));

      // Send file in chunks
      const reader = new FileReader();
      
      reader.onload = (e) => {
        if (channel.bufferedAmount > channel.bufferedAmountLowThreshold) {
          channel.onbufferedamountlow = () => {
            channel.onbufferedamountlow = null;
            sendChunk();
          };
        } else {
          sendChunk();
        }
      };

      const sendChunk = () => {
        if (offset >= file.size) {
          channel.send(JSON.stringify({ type: 'end', id: fileId }));
          return;
        }
        
        const chunk = file.slice(offset, offset + chunkSize);
        reader.readAsArrayBuffer(chunk);
        offset += chunkSize;
        
        channel.send(reader.result);
      };

      sendChunk();
    };
  }
}

export const webRTCService = new WebRTCService();
