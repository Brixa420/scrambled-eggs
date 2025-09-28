import { v4 as uuidv4 } from 'uuid';

export class P2PConnection {
  constructor(config = {}) {
    this.peerConnection = null;
    this.dataChannel = null;
    this.iceServers = {
      iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        // Add your TURN servers here if needed
      ],
      ...config.rtcConfig
    };
    this.onMessage = config.onMessage || (() => {});
    this.onConnectionChange = config.onConnectionChange || (() => {});
    this.connectionId = uuidv4();
    this.connected = false;
  }

  async createOffer() {
    try {
      this.peerConnection = new RTCPeerConnection(this.iceServers);
      this.setupDataChannel();
      const offer = await this.peerConnection.createOffer();
      await this.peerConnection.setLocalDescription(offer);
      return offer;
    } catch (error) {
      console.error('Error creating offer:', error);
      throw error;
    }
  }

  async createAnswer(offer) {
    try {
      this.peerConnection = new RTCPeerConnection(this.iceServers);
      this.setupDataChannel();
      await this.peerConnection.setRemoteDescription(new RTCSessionDescription(offer));
      const answer = await this.peerConnection.createAnswer();
      await this.peerConnection.setLocalDescription(answer);
      return answer;
    } catch (error) {
      console.error('Error creating answer:', error);
      throw error;
    }
  }

  async setRemoteAnswer(answer) {
    try {
      await this.peerConnection.setRemoteDescription(new RTCSessionDescription(answer));
    } catch (error) {
      console.error('Error setting remote answer:', error);
      throw error;
    }
  }

  setupDataChannel() {
    if (this.peerConnection.createDataChannel) {
      this.dataChannel = this.peerConnection.createDataChannel('messaging');
      this.setupDataChannelHandlers();
    }

    this.peerConnection.ondatachannel = (event) => {
      this.dataChannel = event.channel;
      this.setupDataChannelHandlers();
    };

    this.peerConnection.onicecandidate = (event) => {
      if (event.candidate) {
        // Send the ICE candidate to the remote peer
        if (this.onIceCandidate) {
          this.onIceCandidate(event.candidate);
        }
      }
    };

    this.peerConnection.onconnectionstatechange = () => {
      this.connected = this.peerConnection.connectionState === 'connected';
      this.onConnectionChange(this.connected);
    };
  }

  setupDataChannelHandlers() {
    this.dataChannel.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        this.onMessage(message);
      } catch (error) {
        console.error('Error parsing message:', error);
      }
    };

    this.dataChannel.onopen = () => {
      this.connected = true;
      this.onConnectionChange(true);
    };

    this.dataChannel.onclose = () => {
      this.connected = false;
      this.onConnectionChange(false);
    };
  }

  sendMessage(message) {
    if (this.dataChannel && this.dataChannel.readyState === 'open') {
      this.dataChannel.send(JSON.stringify({
        id: uuidv4(),
        timestamp: new Date().toISOString(),
        ...message
      }));
      return true;
    }
    return false;
  }

  close() {
    if (this.dataChannel) {
      this.dataChannel.close();
    }
    if (this.peerConnection) {
      this.peerConnection.close();
    }
    this.connected = false;
    this.onConnectionChange(false);
  }
}

export default P2PConnection;
