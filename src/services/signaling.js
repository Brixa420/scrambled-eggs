import { v4 as uuidv4 } from 'uuid';

export class SignalingService {
  constructor(config = {}) {
    this.socket = null;
    this.roomId = config.roomId || uuidv4();
    this.peerId = uuidv4();
    this.onOffer = config.onOffer || (() => {});
    this.onAnswer = config.onAnswer || (() => {});
    this.onIceCandidate = config.onIceCandidate || (() => {});
    this.onPeerConnected = config.onPeerConnected || (() => {});
    this.onPeerDisconnected = config.onPeerDisconnected || (() => {});
    this.onError = config.onError || (() => {});
  }

  connect(serverUrl) {
    return new Promise((resolve, reject) => {
      try {
        this.socket = new WebSocket(serverUrl);

        this.socket.onopen = () => {
          // Register with the signaling server
          this.send({
            type: 'register',
            roomId: this.roomId,
            peerId: this.peerId
          });
          resolve();
        };

        this.socket.onmessage = (event) => {
          try {
            const message = JSON.parse(event.data);
            this.handleMessage(message);
          } catch (error) {
            console.error('Error parsing message:', error);
            this.onError('Invalid message format');
          }
        };

        this.socket.onclose = () => {
          this.onPeerDisconnected();
        };

        this.socket.onerror = (error) => {
          console.error('WebSocket error:', error);
          this.onError('Connection error');
          reject(error);
        };
      } catch (error) {
        console.error('Error connecting to signaling server:', error);
        reject(error);
      }
    });
  }

  handleMessage(message) {
    switch (message.type) {
      case 'offer':
        this.onOffer(message.sdp, message.sender);
        break;
      case 'answer':
        this.onAnswer(message.sdp, message.sender);
        break;
      case 'candidate':
        this.onIceCandidate(message.candidate, message.sender);
        break;
      case 'peer-connected':
        this.onPeerConnected(message.peerId);
        break;
      case 'peer-disconnected':
        this.onPeerDisconnected(message.peerId);
        break;
      default:
        console.warn('Unknown message type:', message.type);
    }
  }

  sendOffer(sdp, targetPeerId) {
    this.send({
      type: 'offer',
      sdp,
      target: targetPeerId,
      sender: this.peerId,
      roomId: this.roomId
    });
  }

  sendAnswer(sdp, targetPeerId) {
    this.send({
      type: 'answer',
      sdp,
      target: targetPeerId,
      sender: this.peerId,
      roomId: this.roomId
    });
  }

  sendIceCandidate(candidate, targetPeerId) {
    this.send({
      type: 'candidate',
      candidate,
      target: targetPeerId,
      sender: this.peerId,
      roomId: this.roomId
    });
  }

  send(message) {
    if (this.socket && this.socket.readyState === WebSocket.OPEN) {
      this.socket.send(JSON.stringify(message));
    } else {
      console.warn('WebSocket is not connected');
      this.onError('Not connected to signaling server');
    }
  }

  disconnect() {
    if (this.socket) {
      this.socket.close();
    }
  }
}

export default SignalingService;
