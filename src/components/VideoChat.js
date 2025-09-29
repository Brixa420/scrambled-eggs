import React, { useState, useEffect, useRef } from 'react';
import { clippyAI } from '../services/ai/ClippyAIService';
import { P2PService } from '../services/p2p/P2PService';
import '../styles/VideoChat.css';

const VideoChat = () => {
  const [messages, setMessages] = useState([]);
  const [inputMessage, setInputMessage] = useState('');
  const [participants, setParticipants] = useState(new Set());
  const [isScreenSharing, setIsScreenSharing] = useState(false);
  const [localStream, setLocalStream] = useState(null);
  const [remoteStreams, setRemoteStreams] = useState(new Map());
  
  const localVideoRef = useRef(null);
  const messagesEndRef = useRef(null);
  const p2pService = useRef(null);
  const screenStream = useRef(null);

  useEffect(() => {
    // Initialize P2P service
    p2pService.current = new P2PService({
      onRemoteStream: handleRemoteStream,
      onMessage: handleChatMessage,
      onPeerJoined: handlePeerJoined,
      onPeerLeft: handlePeerLeft,
    });

    // Initialize Clippy AI
    clippyAI.on('log', handleAILog);
    clippyAI.on('anomaly-detected', handleAnomaly);

    // Start local media
    startLocalMedia();

    // Clean up
    return () => {
      p2pService.current.disconnect();
      if (localStream) {
        localStream.getTracks().forEach(track => track.stop());
      }
      if (screenStream.current) {
        screenStream.current.getTracks().forEach(track => track.stop());
      }
      clippyAI.off('log', handleAILog);
      clippyAI.off('anomaly-detected', handleAnomaly);
    };
  }, []);

  const startLocalMedia = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: true,
        audio: true,
      });
      
      setLocalStream(stream);
      if (localVideoRef.current) {
        localVideoRef.current.srcObject = stream;
      }
      
      // Start P2P connection
      p2pService.current.startLocalStream(stream);
      
    } catch (error) {
      console.error('Error accessing media devices:', error);
      clippyAI.log(`Media access error: ${error.message}`, 'error');
    }
  };

  const toggleScreenShare = async () => {
    try {
      if (!isScreenSharing) {
        // Start screen sharing
        const stream = await navigator.mediaDevices.getDisplayMedia({
          video: true,
          audio: true,
        });
        
        screenStream.current = stream;
        p2pService.current.replaceVideoTrack(stream.getVideoTracks()[0]);
        
        // Handle when user stops sharing via browser UI
        stream.getVideoTracks()[0].onended = () => {
          toggleScreenShare();
        };
        
        setIsScreenSharing(true);
        clippyAI.log('Screen sharing started', 'success');
      } else {
        // Stop screen sharing
        if (screenStream.current) {
          screenStream.current.getTracks().forEach(track => track.stop());
          screenStream.current = null;
        }
        
        // Switch back to camera
        const stream = await navigator.mediaDevices.getUserMedia({
          video: true,
          audio: true,
        });
        
        p2pService.current.replaceVideoTrack(stream.getVideoTracks()[0]);
        setIsScreenSharing(false);
        clippyAI.log('Screen sharing stopped', 'info');
      }
    } catch (error) {
      console.error('Error toggling screen share:', error);
      clippyAI.log(`Screen share error: ${error.message}`, 'error');
    }
  };

  const handleChatMessage = (message) => {
    setMessages(prev => [...prev, message]);
    // Auto-scroll to bottom
    setTimeout(() => {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, 100);
    
    // Read message aloud if from another user
    if (message.sender !== p2pService.current.peerId) {
      clippyAI.speak(`New message from ${message.sender}: ${message.text}`, 'info');
    }
  };

  const sendMessage = () => {
    if (!inputMessage.trim()) return;
    
    const message = {
      text: inputMessage,
      sender: p2pService.current.peerId,
      timestamp: new Date().toISOString(),
    };
    
    p2pService.current.sendMessage(message);
    setInputMessage('');
  };

  const handleRemoteStream = (peerId, stream) => {
    setRemoteStreams(prev => new Map(prev).set(peerId, stream));
    clippyAI.speak(`Participant ${peerId} has joined`, 'info');
  };

  const handlePeerJoined = (peerId) => {
    setParticipants(prev => new Set([...prev, peerId]));
    clippyAI.log(`Peer ${peerId} joined the call`, 'info');
  };

  const handlePeerLeft = (peerId) => {
    setParticipants(prev => {
      const newSet = new Set(prev);
      newSet.delete(peerId);
      return newSet;
    });
    
    setRemoteStreams(prev => {
      const newMap = new Map(prev);
      newMap.delete(peerId);
      return newMap;
    });
    
    clippyAI.speak(`Participant ${peerId} has left`, 'info');
  };

  const handleAILog = ({ message, type }) => {
    // Update UI with AI logs if needed
    console.log(`[ClippyAI] ${message}`);
  };

  const handleAnomaly = ({ score, features }) => {
    const alert = `Security Alert: Anomaly detected (score: ${score.toFixed(2)})`;
    clippyAI.speak(alert, 'warning');
    
    // Update UI with security alert
    setMessages(prev => [...prev, {
      text: alert,
      sender: 'system',
      timestamp: new Date().toISOString(),
      isAlert: true,
    }]);
  };

  return (
    <div className="video-chat-container">
      <div className="video-grid">
        {/* Local video */}
        <div className="video-container local">
          <video 
            ref={localVideoRef} 
            autoPlay 
            playsInline 
            muted 
            className="video-element"
          />
          <div className="video-label">You ({p2pService.current?.peerId || '...'})</div>
        </div>
        
        {/* Remote videos */}
        {Array.from(remoteStreams.entries()).map(([peerId, stream]) => (
          <div key={peerId} className="video-container">
            <video
              ref={ref => {
                if (ref) ref.srcObject = stream;
              }}
              autoPlay
              playsInline
              className="video-element"
            />
            <div className="video-label">Participant {peerId}</div>
          </div>
        ))}
      </div>
      
      <div className="chat-container">
        <div className="messages">
          {messages.map((msg, index) => (
            <div 
              key={index} 
              className={`message ${msg.sender === p2pService.current?.peerId ? 'sent' : 'received'} ${msg.isAlert ? 'alert' : ''}`}
            >
              <div className="message-sender">
                {msg.sender === p2pService.current?.peerId ? 'You' : 
                 msg.sender === 'system' ? 'System' : `User ${msg.sender}`}
              </div>
              <div className="message-text">{msg.text}</div>
              <div className="message-time">
                {new Date(msg.timestamp).toLocaleTimeString()}
              </div>
            </div>
          ))}
          <div ref={messagesEndRef} />
        </div>
        
        <div className="chat-input">
          <input
            type="text"
            value={inputMessage}
            onChange={(e) => setInputMessage(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
            placeholder="Type a message..."
          />
          <button onClick={sendMessage}>Send</button>
        </div>
      </div>
      
      <div className="controls">
        <button 
          onClick={toggleScreenShare}
          className={isScreenSharing ? 'active' : ''}
        >
          {isScreenSharing ? 'Stop Sharing' : 'Share Screen'}
        </button>
        <button onClick={() => p2pService.current?.toggleMute()}>
          Mute
        </button>
        <button onClick={() => p2pService.current?.toggleVideo()}>
          Toggle Video
        </button>
      </div>
    </div>
  );
};

export default VideoChat;
