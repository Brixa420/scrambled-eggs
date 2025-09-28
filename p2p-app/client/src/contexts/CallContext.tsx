import React, { createContext, useContext, useState, useRef, useEffect, ReactNode } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { io, Socket } from 'socket.io-client';
import Peer from 'simple-peer';

interface CallContextType {
  localStream: MediaStream | null;
  remoteStream: MediaStream | null;
  isCallActive: boolean;
  isCallInitiator: boolean;
  isVideoEnabled: boolean;
  isAudioEnabled: boolean;
  startCall: (roomId: string) => Promise<void>;
  answerCall: () => void;
  endCall: () => void;
  toggleVideo: () => void;
  toggleAudio: () => void;
  sendMessage: (message: string) => void;
  messages: Array<{ text: string; isMine: boolean; timestamp: Date }>;
  participants: Array<{ id: string; username?: string }>;
  error: string | null;
  loading: boolean;
}

const CallContext = createContext<CallContextType | undefined>(undefined);

interface CallProviderProps {
  children: ReactNode;
}

export const CallProvider: React.FC<CallProviderProps> = ({ children }) => {
  const [localStream, setLocalStream] = useState<MediaStream | null>(null);
  const [remoteStream, setRemoteStream] = useState<MediaStream | null>(null);
  const [isCallActive, setIsCallActive] = useState<boolean>(false);
  const [isCallInitiator, setIsCallInitiator] = useState<boolean>(false);
  const [isVideoEnabled, setIsVideoEnabled] = useState<boolean>(true);
  const [isAudioEnabled, setIsAudioEnabled] = useState<boolean>(true);
  const [messages, setMessages] = useState<Array<{ text: string; isMine: boolean; timestamp: Date }>>([]);
  const [participants, setParticipants] = useState<Array<{ id: string; username?: string }>>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  
  const socketRef = useRef<Socket | null>(null);
  const peerRef = useRef<Peer.Instance | null>(null);
  const localVideoRef = useRef<HTMLVideoElement>(null);
  const remoteVideoRef = useRef<HTMLVideoElement>(null);
  const { roomId } = useParams();
  const navigate = useNavigate();

  // Initialize socket connection
  useEffect(() => {
    const socket = io('http://localhost:3001', {
      withCredentials: true,
      transports: ['websocket'],
    });
    
    socketRef.current = socket;

    socket.on('connect', () => {
      console.log('Connected to WebSocket server');
    });

    socket.on('disconnect', () => {
      console.log('Disconnected from WebSocket server');
      handleEndCall();
    });

    socket.on('offer', handleOffer);
    socket.on('answer', handleAnswer);
    socket.on('ice-candidate', handleNewICECandidate);
    socket.on('user_joined', handleUserJoined);
    socket.on('user_left', handleUserLeft);
    socket.on('chat_message', handleChatMessage);
    socket.on('error', handleError);

    return () => {
      socket.disconnect();
    };
  }, []);

  const handleOffer = async (offer: any) => {
    try {
      setLoading(true);
      
      // Create a new peer connection
      const peer = new Peer({
        initiator: false,
        trickle: true,
        stream: localStream || undefined,
      });

      peer.on('signal', (data) => {
        socketRef.current?.emit('answer', {
          to: offer.from,
          answer: data,
          roomId,
        });
      });

      peer.on('stream', (stream) => {
        setRemoteStream(stream);
        if (remoteVideoRef.current) {
          remoteVideoRef.current.srcObject = stream;
        }
      });

      peer.signal(offer.offer);
      peerRef.current = peer;
      setIsCallActive(true);
    } catch (err) {
      console.error('Error handling offer:', err);
      setError('Failed to handle call offer');
    } finally {
      setLoading(false);
    }
  };

  const handleAnswer = (answer: any) => {
    if (peerRef.current) {
      peerRef.current.signal(answer.answer);
      setIsCallActive(true);
    }
  };

  const handleNewICECandidate = (candidate: any) => {
    if (peerRef.current) {
      peerRef.current.addIceCandidate(candidate);
    }
  };

  const handleUserJoined = (user: any) => {
    setParticipants(prev => [...prev, { id: user.clientId, username: user.username }]);
  };

  const handleUserLeft = (user: any) => {
    setParticipants(prev => prev.filter(p => p.id !== user.clientId));
  };

  const handleChatMessage = (message: any) => {
    setMessages(prev => [...prev, {
      text: message.text,
      isMine: false,
      timestamp: new Date(),
    }]);
  };

  const handleError = (error: any) => {
    console.error('WebSocket error:', error);
    setError(error.message || 'An error occurred');
  };

  const handleEndCall = () => {
    if (peerRef.current) {
      peerRef.current.destroy();
      peerRef.current = null;
    }
    
    if (localStream) {
      localStream.getTracks().forEach(track => track.stop());
      setLocalStream(null);
    }
    
    setRemoteStream(null);
    setIsCallActive(false);
    setIsCallInitiator(false);
    setMessages([]);
    setParticipants([]);
    
    if (socketRef.current) {
      socketRef.current.emit('leave_room', { roomId });
    }
    
    navigate('/');
  };

  const startCall = async (roomId: string) => {
    try {
      setLoading(true);
      setError(null);
      
      // Get user media
      const stream = await navigator.mediaDevices.getUserMedia({
        video: isVideoEnabled,
        audio: isAudioEnabled,
      });
      
      setLocalStream(stream);
      
      if (localVideoRef.current) {
        localVideoRef.current.srcObject = stream;
      }
      
      // Create a new peer connection
      const peer = new Peer({
        initiator: true,
        trickle: true,
        stream,
      });

      peer.on('signal', (data) => {
        socketRef.current?.emit('offer', {
          offer: data,
          roomId,
        });
      });

      peer.on('stream', (stream) => {
        setRemoteStream(stream);
        if (remoteVideoRef.current) {
          remoteVideoRef.current.srcObject = stream;
        }
      });

      peerRef.current = peer;
      setIsCallActive(true);
      setIsCallInitiator(true);
      
      // Join the room
      socketRef.current?.emit('join_room', { roomId });
      
    } catch (err) {
      console.error('Error starting call:', err);
      setError('Failed to access camera/microphone');
    } finally {
      setLoading(false);
    }
  };

  const answerCall = () => {
    if (peerRef.current) {
      peerRef.current.signal(peerRef.current.signalData);
      setIsCallActive(true);
    }
  };

  const toggleVideo = () => {
    if (localStream) {
      const videoTrack = localStream.getVideoTracks()[0];
      if (videoTrack) {
        videoTrack.enabled = !videoTrack.enabled;
        setIsVideoEnabled(videoTrack.enabled);
      }
    }
  };

  const toggleAudio = () => {
    if (localStream) {
      const audioTrack = localStream.getAudioTracks()[0];
      if (audioTrack) {
        audioTrack.enabled = !audioTrack.enabled;
        setIsAudioEnabled(audioTrack.enabled);
      }
    }
  };

  const sendMessage = (text: string) => {
    if (peerRef.current && text.trim()) {
      const message = {
        text,
        timestamp: new Date().toISOString(),
      };
      
      // In a real app, you would send this through the data channel
      // For now, we'll just add it to the local messages
      setMessages(prev => [...prev, {
        text,
        isMine: true,
        timestamp: new Date(),
      }]);
      
      // Emit the message through the signaling server
      socketRef.current?.emit('chat_message', {
        roomId,
        message: message,
      });
    }
  };

  return (
    <CallContext.Provider
      value={{
        localStream,
        remoteStream,
        isCallActive,
        isCallInitiator,
        isVideoEnabled,
        isAudioEnabled,
        startCall,
        answerCall,
        endCall: handleEndCall,
        toggleVideo,
        toggleAudio,
        sendMessage,
        messages,
        participants,
        error,
        loading,
      }}
    >
      {children}
      {/* Hidden video elements for streams */}
      <video
        ref={localVideoRef}
        autoPlay
        playsInline
        muted
        style={{ display: 'none' }}
      />
      <video
        ref={remoteVideoRef}
        autoPlay
        playsInline
        style={{ display: 'none' }}
      />
    </CallContext.Provider>
  );
};

export const useCall = (): CallContextType => {
  const context = useContext(CallContext);
  if (context === undefined) {
    throw new Error('useCall must be used within a CallProvider');
  }
  return context;
};
