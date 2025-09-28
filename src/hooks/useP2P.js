import { useState, useEffect, useCallback, useRef } from 'react';
import P2PConnection from '../utils/webrtc';
import SignalingService from '../services/signaling';

const useP2P = (config = {}) => {
  const [isConnected, setIsConnected] = useState(false);
  const [peers, setPeers] = useState([]);
  const [error, setError] = useState(null);
  const [isInitiator, setIsInitiator] = useState(false);
  
  const connectionRef = useRef(null);
  const signalingRef = useRef(null);
  const peerConnectionsRef = useRef(new Map());
  const dataChannelsRef = useRef(new Map());

  // Initialize signaling service
  useEffect(() => {
    if (!config.roomId || !config.peerId) return;

    const signaling = new SignalingService({
      roomId: config.roomId,
      onPeerConnected: (peerId) => {
        setPeers(prev => [...new Set([...prev, peerId])]);
        if (config.onPeerConnected) {
          config.onPeerConnected(peerId);
        }
      },
      onPeerDisconnected: (peerId) => {
        setPeers(prev => prev.filter(id => id !== peerId));
        peerConnectionsRef.current.delete(peerId);
        dataChannelsRef.current.delete(peerId);
        if (config.onPeerDisconnected) {
          config.onPeerDisconnected(peerId);
        }
      },
      onOffer: async (sdp, senderId) => {
        try {
          const connection = new P2PConnection({
            onMessage: (message) => {
              if (config.onMessage) {
                config.onMessage(message, senderId);
              }
            },
            onConnectionChange: (connected) => {
              if (connected) {
                setIsConnected(true);
                if (config.onConnect) config.onConnect(senderId);
              } else {
                if (config.onDisconnect) config.onDisconnect(senderId);
              }
            }
          });

          const answer = await connection.createAnswer(sdp);
          signaling.sendAnswer(answer, senderId);
          
          peerConnectionsRef.current.set(senderId, connection);
          setIsInitiator(false);
        } catch (error) {
          console.error('Error handling offer:', error);
          setError('Failed to establish connection');
        }
      },
      onAnswer: async (sdp, senderId) => {
        const connection = peerConnectionsRef.current.get(senderId);
        if (connection) {
          try {
            await connection.setRemoteAnswer(sdp);
            setIsConnected(true);
            if (config.onConnect) config.onConnect(senderId);
          } catch (error) {
            console.error('Error handling answer:', error);
            setError('Failed to establish connection');
          }
        }
      },
      onIceCandidate: (candidate, senderId) => {
        const connection = peerConnectionsRef.current.get(senderId);
        if (connection && connection.peerConnection) {
          connection.peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
        }
      },
      onError: (error) => {
        console.error('Signaling error:', error);
        setError(error);
      }
    });

    signalingRef.current = signaling;

    const connect = async () => {
      try {
        await signaling.connect(config.signalingServerUrl || 'ws://localhost:8080');
        console.log('Connected to signaling server');
      } catch (err) {
        console.error('Failed to connect to signaling server:', err);
        setError('Failed to connect to signaling server');
      }
    };

    connect();

    return () => {
      signaling.disconnect();
      peerConnectionsRef.current.forEach(connection => connection.close());
      peerConnectionsRef.current.clear();
      dataChannelsRef.current.clear();
    };
  }, [config.roomId, config.peerId]);

  // Connect to a peer
  const connectToPeer = useCallback(async (peerId) => {
    if (!signalingRef.current) return;

    try {
      const connection = new P2PConnection({
        onMessage: (message) => {
          if (config.onMessage) {
            config.onMessage(message, peerId);
          }
        },
        onConnectionChange: (connected) => {
          if (connected) {
            setIsConnected(true);
            if (config.onConnect) config.onConnect(peerId);
          } else {
            if (config.onDisconnect) config.onDisconnect(peerId);
          }
        }
      });

      const offer = await connection.createOffer();
      signalingRef.current.sendOffer(offer, peerId);
      
      peerConnectionsRef.current.set(peerId, connection);
      setIsInitiator(true);
      
      return connection;
    } catch (error) {
      console.error('Error connecting to peer:', error);
      setError('Failed to connect to peer');
      throw error;
    }
  }, []);

  // Send a message to a specific peer
  const sendMessage = useCallback((peerId, message) => {
    const connection = peerConnectionsRef.current.get(peerId);
    if (connection && connection.connected) {
      return connection.sendMessage(message);
    }
    return false;
  }, []);

  // Send a message to all connected peers
  const broadcast = useCallback((message) => {
    let success = true;
    peerConnectionsRef.current.forEach((connection, peerId) => {
      if (!connection.sendMessage(message)) {
        success = false;
      }
    });
    return success;
  }, []);

  // Disconnect from a peer
  const disconnectFromPeer = useCallback((peerId) => {
    const connection = peerConnectionsRef.current.get(peerId);
    if (connection) {
      connection.close();
      peerConnectionsRef.current.delete(peerId);
      dataChannelsRef.current.delete(peerId);
    }
  }, []);

  // Disconnect from all peers
  const disconnectAll = useCallback(() => {
    peerConnectionsRef.current.forEach(connection => connection.close());
    peerConnectionsRef.current.clear();
    dataChannelsRef.current.clear();
    setIsConnected(false);
  }, []);

  return {
    isConnected,
    peers,
    error,
    isInitiator,
    connectToPeer,
    sendMessage,
    broadcast,
    disconnectFromPeer,
    disconnectAll
  };
};

export default useP2P;
