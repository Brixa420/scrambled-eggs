import * as tf from '@tensorflow/tfjs';
import { EventEmitter } from 'events';

class ClippyAIService extends EventEmitter {
  constructor() {
    super();
    this.model = null;
    this.isModelLoading = false;
    this.securityMetrics = {
      connectionAttempts: 0,
      failedAttempts: 0,
      dataTransferred: 0,
      lastActivity: null,
      connectionHistory: [],
      anomalyScores: []
    };
    this.anomalyThreshold = 0.8; // Threshold for flagging anomalies
    this.initialize();
  }

  async initialize() {
    await this.loadAnomalyDetectionModel();
    this.setupEventListeners();
  }

  async loadAnomalyDetectionModel() {
    try {
      this.isModelLoading = true;
      // Load a pre-trained anomaly detection model (simplified example)
      this.model = await tf.loadLayersModel('models/anomaly-detection/model.json');
      this.log('Anomaly detection model loaded', 'success');
    } catch (error) {
      console.error('Error loading anomaly detection model:', error);
      this.log('Using basic security checks only', 'warning');
    } finally {
      this.isModelLoading = false;
    }
  }

  setupEventListeners() {
    // Listen for WebRTC events
    window.addEventListener('webrtc-event', this.handleWebRTCEvent.bind(this));
    
    // Listen for network events
    window.addEventListener('network-quality', this.analyzeNetworkQuality.bind(this));
    
    // Periodically check for anomalies
    setInterval(this.runSecurityScan.bind(this), 30000);
  }

  async analyzeConnection(pc) {
    if (!pc) return;
    
    try {
      // Basic security checks
      this.checkIceConnection(pc);
      this.checkEncryption(pc);
      
      // Advanced ML-based analysis
      if (this.model && !this.isModelLoading) {
        await this.detectAnomalies(pc);
      }
      
      // Update security metrics
      this.updateConnectionMetrics(pc);
      
    } catch (error) {
      this.log(`Error in connection analysis: ${error.message}`, 'error');
    }
  }

  async detectAnomalies(pc) {
    try {
      const stats = await pc.getStats();
      const features = this.extractFeatures(stats);
      
      // Convert features to tensor
      const inputTensor = tf.tensor2d([features]);
      
      // Get predictions
      const predictions = this.model.predict(inputTensor);
      const score = predictions.dataSync()[0];
      
      // Store anomaly score
      this.securityMetrics.anomalyScores.push({
        timestamp: Date.now(),
        score: score,
        isAnomaly: score > this.anomalyThreshold
      });
      
      if (score > this.anomalyThreshold) {
        this.log(`⚠️ Anomaly detected in connection (score: ${score.toFixed(2)})`, 'warning');
        this.emit('anomaly-detected', { score, features });
      }
      
      return score;
      
    } catch (error) {
      console.error('Error in anomaly detection:', error);
      throw error;
    }
  }

  extractFeatures(stats) {
    // Extract relevant features for anomaly detection
    const features = [];
    let bytesSent = 0;
    let bytesReceived = 0;
    
    stats.forEach(report => {
      if (report.type === 'outbound-rtp' || report.type === 'inbound-rtp') {
        bytesSent += report.bytesSent || 0;
        bytesReceived += report.bytesReceived || 0;
      }
    });
    
    // Add features to the array (simplified example)
    features.push(
      bytesSent,
      bytesReceived,
      this.securityMetrics.failedAttempts,
      this.securityMetrics.connectionAttempts,
      // Add more features as needed
    );
    
    return features;
  }

  checkIceConnection(pc) {
    if (pc.iceConnectionState) {
      this.log(`ICE Connection State: ${pc.iceConnectionState}`, 'info');
      
      if (pc.iceConnectionState === 'failed' || 
          pc.iceConnectionState === 'disconnected') {
        this.log(`Connection issue detected: ${pc.iceConnectionState}`, 'warning');
      }
    }
  }

  checkEncryption(pc) {
    // Check if DTLS is being used
    const configuration = pc.getConfiguration();
    if (configuration && configuration.certificates) {
      this.log(`Using ${configuration.certificates.length} DTLS certificate(s)`, 'info');
    }
    
    // Check for secure ICE candidates
    pc.getStats().then(stats => {
      stats.forEach(report => {
        if (report.type === 'transport' && report.dtlsCipher) {
          this.log(`DTLS Cipher: ${report.dtlsCipher}`, 'success');
        }
      });
    });
  }

  updateConnectionMetrics(pc) {
    this.securityMetrics.connectionAttempts++;
    this.securityMetrics.lastActivity = new Date().toISOString();
    
    // Update connection history
    this.securityMetrics.connectionHistory.push({
      timestamp: Date.now(),
      state: pc.connectionState,
      iceState: pc.iceConnectionState
    });
    
    // Keep only the last 100 entries
    if (this.securityMetrics.connectionHistory.length > 100) {
      this.securityMetrics.connectionHistory.shift();
    }
  }

  async runSecurityScan() {
    if (!this.peerConnection) return;
    
    try {
      this.log('Running security scan...', 'info');
      await this.analyzeConnection(this.peerConnection);
      
      // Check for unusual patterns
      this.checkForSuspiciousPatterns();
      
    } catch (error) {
      this.log(`Error during security scan: ${error.message}`, 'error');
    }
  }

  checkForSuspiciousPatterns() {
    // Example: Check for too many failed connection attempts
    const recentFailures = this.securityMetrics.connectionHistory
      .filter(entry => entry.state === 'failed')
      .slice(-5); // Last 5 minutes
    
    if (recentFailures.length >= 3) {
      this.log('⚠️ Multiple connection failures detected. Possible attack?', 'warning');
    }
    
    // Add more pattern checks as needed
  }

  log(message, type = 'info') {
    const timestamp = new Date().toLocaleTimeString();
    const logEntry = `[${timestamp}] ${message}`;
    
    // Emit log event for UI
    this.emit('log', { message: logEntry, type });
    
    // Console log for debugging
    const consoleMethod = {
      info: console.info,
      warning: console.warn,
      error: console.error,
      success: console.log
    }[type] || console.log;
    
    consoleMethod(`[ClippyAI] ${logEntry}`);
  }

  // Voice feedback methods
  speak(message, priority = 'info') {
    if (!window.speechSynthesis) {
      console.warn('Speech synthesis not supported');
      return;
    }
    
    // Don't speak low-priority messages if there are high-priority ones
    if (priority === 'info' && this.hasHighPriorityMessages) {
      return;
    }
    
    const utterance = new SpeechSynthesisUtterance(message);
    
    // Set different voices/rates based on priority
    if (priority === 'warning' || priority === 'error') {
      utterance.rate = 1.1;
      utterance.pitch = 1.2;
      this.hasHighPriorityMessages = true;
      
      // Reset flag after speaking
      utterance.onend = () => {
        this.hasHighPriorityMessages = false;
      };
    }
    
    window.speechSynthesis.speak(utterance);
  }
}

export const clippyAI = new ClippyAIService();
