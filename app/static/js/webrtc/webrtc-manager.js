/**
 * WebRTC Manager - Handles P2P connections for voice, video, and data channels
 */
class WebRTCManager {
    constructor(socket, localUserId) {
        this.socket = socket;
        this.localUserId = localUserId;
        this.peerConnections = new Map();
        this.localStream = null;
        this.configuration = {
            iceServers: [
                { urls: 'stun:stun.l.google.com:19302' },
                // Add TURN servers here for NAT traversal
            ]
        };
        
        this.setupSocketHandlers();
    }

    /**
     * Set up socket.io event handlers
     */
    setupSocketHandlers() {
        // Handle incoming call
        this.socket.on('rtc_offer', async (data) => {
            const { from, offer } = data;
            console.log(`Received offer from ${from}`);
            
            // Create or get peer connection
            const peerConnection = await this.getOrCreatePeerConnection(from);
            
            // Set remote description
            await peerConnection.setRemoteDescription(new RTCSessionDescription(offer));
            
            // Create answer
            const answer = await peerConnection.createAnswer();
            await peerConnection.setLocalDescription(answer);
            
            // Send answer back to caller
            this.socket.emit('rtc_answer', {
                to: from,
                from: this.localUserId,
                answer: peerConnection.localDescription
            });
        });

        // Handle answer
        this.socket.on('rtc_answer', async (data) => {
            const { from, answer } = data;
            console.log(`Received answer from ${from}`);
            
            const peerConnection = this.peerConnections.get(from);
            if (peerConnection) {
                await peerConnection.setRemoteDescription(new RTCSessionDescription(answer));
            }
        });

        // Handle ICE candidates
        this.socket.on('ice_candidate', async (data) => {
            const { from, candidate } = data;
            console.log(`Received ICE candidate from ${from}`);
            
            const peerConnection = this.peerConnections.get(from);
            if (peerConnection && candidate) {
                try {
                    await peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
                } catch (e) {
                    console.error('Error adding ICE candidate:', e);
                }
            }
        });

        // Handle incoming data messages
        this.socket.on('data_message', (data) => {
            const { from, data: message } = data;
            console.log(`Data message from ${from}:`, message);
            
            // Handle the incoming message (e.g., update UI)
            this.onMessageReceived && this.onMessageReceived(from, message);
        });
    }

    /**
     * Get or create a peer connection
     */
    async getOrCreatePeerConnection(peerId) {
        if (this.peerConnections.has(peerId)) {
            return this.peerConnections.get(peerId);
        }

        // Create a new RTCPeerConnection
        const peerConnection = new RTCPeerConnection(this.configuration);
        this.peerConnections.set(peerId, peerConnection);

        // Set up event handlers for the connection
        peerConnection.onicecandidate = (event) => {
            if (event.candidate) {
                this.socket.emit('ice_candidate', {
                    to: peerId,
                    from: this.localUserId,
                    candidate: event.candidate
                });
            }
        };

        // Handle data channel creation
        peerConnection.ondatachannel = (event) => {
            const dataChannel = event.channel;
            this.setupDataChannel(peerId, dataChannel);
        };

        // Handle connection state changes
        peerConnection.onconnectionstatechange = () => {
            console.log(`Connection state with ${peerId}:`, peerConnection.connectionState);
            
            if (['disconnected', 'failed', 'closed'].includes(peerConnection.connectionState)) {
                this.cleanupPeer(peerId);
            }
        };

        // Add local stream if available
        if (this.localStream) {
            this.localStream.getTracks().forEach(track => {
                peerConnection.addTrack(track, this.localStream);
            });
        }

        return peerConnection;
    }

    /**
     * Set up a data channel
     */
    setupDataChannel(peerId, dataChannel) {
        dataChannel.onopen = () => {
            console.log(`Data channel with ${peerId} opened`);
            this.onDataChannelOpen && this.onDataChannelOpen(peerId, dataChannel);
        };

        dataChannel.onclose = () => {
            console.log(`Data channel with ${peerId} closed`);
            this.onDataChannelClose && this.onDataChannelClose(peerId);
        };

        dataChannel.onmessage = (event) => {
            console.log(`Message from ${peerId}:`, event.data);
            this.onDataChannelMessage && this.onDataChannelMessage(peerId, event.data);
        };
    }

    /**
     * Initiate a call to a peer
     */
    async callPeer(peerId) {
        console.log(`Initiating call to ${peerId}`);
        
        // Get or create peer connection
        const peerConnection = await this.getOrCreatePeerConnection(peerId);
        
        // Create a data channel
        const dataChannel = peerConnection.createDataChannel(`chat-${Date.now()}`);
        this.setupDataChannel(peerId, dataChannel);
        
        // Create an offer
        const offer = await peerConnection.createOffer();
        await peerConnection.setLocalDescription(offer);
        
        // Send the offer to the peer
        this.socket.emit('rtc_offer', {
            to: peerId,
            from: this.localUserId,
            offer: peerConnection.localDescription
        });
        
        return dataChannel;
    }

    /**
     * Send a message to a peer
     */
    sendMessage(peerId, message) {
        const peerConnection = this.peerConnections.get(peerId);
        if (peerConnection) {
            const dataChannel = peerConnection.dataChannel;
            if (dataChannel && dataChannel.readyState === 'open') {
                dataChannel.send(JSON.stringify(message));
                return true;
            }
        }
        return false;
    }

    /**
     * Start local media (camera and microphone)
     */
    async startLocalMedia(constraints = { audio: true, video: true }) {
        try {
            this.localStream = await navigator.mediaDevices.getUserMedia(constraints);
            return this.localStream;
        } catch (error) {
            console.error('Error accessing media devices:', error);
            throw error;
        }
    }

    /**
     * Stop local media
     */
    stopLocalMedia() {
        if (this.localStream) {
            this.localStream.getTracks().forEach(track => track.stop());
            this.localStream = null;
        }
    }

    /**
     * Clean up a peer connection
     */
    cleanupPeer(peerId) {
        const peerConnection = this.peerConnections.get(peerId);
        if (peerConnection) {
            peerConnection.close();
            this.peerConnections.delete(peerId);
            this.onPeerDisconnected && this.onPeerDisconnected(peerId);
        }
    }

    /**
     * Clean up all connections
     */
    cleanup() {
        // Close all peer connections
        this.peerConnections.forEach((_, peerId) => this.cleanupPeer(peerId));
        
        // Stop local media
        this.stopLocalMedia();
        
        // Remove socket listeners
        this.socket.off('rtc_offer');
        this.socket.off('rtc_answer');
        this.socket.off('ice_candidate');
        this.socket.off('data_message');
    }

    // Event handlers (to be set by the application)
    onDataChannelOpen(peerId, dataChannel) {}
    onDataChannelClose(peerId) {}
    onDataChannelMessage(peerId, message) {}
    onPeerDisconnected(peerId) {}
    onMessageReceived(from, message) {}
}

// Export for use in other modules
export default WebRTCManager;
