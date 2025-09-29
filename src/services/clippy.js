import { see } from './see';
import { webRTCService } from './webrtc';

export class ClippySecurityAssistant {
  constructor() {
    this.securityEvents = [];
    this.suspiciousPatterns = [
      { pattern: /(password|passwd|pwd)=[^&]*/gi, severity: 'high' },
      { pattern: /(ssh-rsa|ssh-dss) [A-Za-z0-9+/=]+/g, severity: 'high' },
      { pattern: /(\d{1,3}\.){3}\d{1,3}/g, severity: 'medium' },
      { pattern: /<script>.*<\/script>/gis, severity: 'critical' },
      { pattern: /(SELECT|INSERT|UPDATE|DELETE|DROP|--|;|\/\*|\*\/)/gi, severity: 'high' },
    ];
    this.initialize();
  }

  async initialize() {
    // Load any saved security patterns or configurations
    await this.loadSecurityRules();
    this.startMonitoring();
  }

  async loadSecurityRules() {
    try {
      // In a real app, this would load from a secure server
      const response = await fetch('/api/security/rules');
      if (response.ok) {
        const rules = await response.json();
        this.suspiciousPatterns = [...this.suspiciousPatterns, ...rules];
      }
    } catch (error) {
      console.warn('Failed to load security rules:', error);
    }
  }

  startMonitoring() {
    // Monitor network requests
    const originalFetch = window.fetch;
    window.fetch = async (input, init = {}) => {
      const url = typeof input === 'string' ? input : input.url;
      
      // Check request data for suspicious patterns
      if (init.body) {
        const body = typeof init.body === 'string' ? init.body : JSON.stringify(init.body);
        this.analyzeForThreats(body, 'outgoing_request', { url });
      }

      const response = await originalFetch(input, init);
      
      // Clone the response so we can read it without consuming it
      const clonedResponse = response.clone();
      
      // Check response data for suspicious patterns
      try {
        const data = await clonedResponse.text();
        this.analyzeForThreats(data, 'incoming_response', { 
          url,
          status: response.status 
        });
      } catch (error) {
        console.warn('Failed to analyze response:', error);
      }

      return response;
    };

    // Monitor WebRTC connections
    this.monitorWebRTC();
  }

  monitorWebRTC() {
    // Monitor WebRTC peer connections
    const originalCreateOffer = RTCPeerConnection.prototype.createOffer;
    RTCPeerConnection.prototype.createOffer = async function(options) {
      // Log the offer creation
      console.log('WebRTC offer created for connection');
      return originalCreateOffer.call(this, options);
    };

    // Monitor data channels
    const originalCreateDataChannel = RTCPeerConnection.prototype.createDataChannel;
    RTCPeerConnection.prototype.createDataChannel = function(label, options) {
      console.log(`Data channel created: ${label}`);
      const channel = originalCreateDataChannel.call(this, label, options);
      
      // Monitor messages on the data channel
      const originalSend = channel.send;
      channel.send = function(data) {
        console.log(`Data sent on channel ${label}:`, data);
        return originalSend.call(this, data);
      };
      
      return channel;
    };
  }

  analyzeForThreats(content, context, metadata = {}) {
    const threats = [];
    
    // Check for suspicious patterns
    for (const { pattern, severity } of this.suspiciousPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        threats.push({
          type: 'suspicious_pattern',
          severity,
          pattern: pattern.toString(),
          matches: matches.slice(0, 5), // Limit the number of matches to return
          context,
          timestamp: new Date().toISOString(),
          metadata
        });
      }
    }

    // Check for potential encryption weaknesses
    if (context === 'outgoing_request' || context === 'incoming_response') {
      const encryptionCheck = this.checkEncryption(content);
      if (encryptionCheck) {
        threats.push(encryptionCheck);
      }
    }

    // Log and handle detected threats
    if (threats.length > 0) {
      this.handleThreats(threats);
    }

    return threats;
  }

  checkEncryption(content) {
    // Check for plaintext sensitive data
    const sensitivePatterns = [
      { pattern: /(password|pwd|secret|api[_-]?key|token)[=:][^\s&'"]+/gi, type: 'sensitive_data_exposure' },
      { pattern: /(bearer\s+[a-zA-Z0-9\-_.]+)/gi, type: 'exposed_token' },
      { pattern: /(\d[ -]*?){13,16}/g, type: 'credit_card_number' },
    ];

    for (const { pattern, type } of sensitivePatterns) {
      if (pattern.test(content)) {
        return {
          type,
          severity: 'critical',
          message: `Potential sensitive data exposure detected (${type})`,
          timestamp: new Date().toISOString(),
          recommendation: 'Ensure sensitive data is properly encrypted before transmission.'
        };
      }
    }
    return null;
  }

  async handleThreats(threats) {
    // Log the threats
    this.securityEvents.push(...threats);
    
    // Take appropriate action based on threat severity
    for (const threat of threats) {
      switch (threat.severity) {
        case 'critical':
          await this.handleCriticalThreat(threat);
          break;
        case 'high':
          await this.handleHighThreat(threat);
          break;
        case 'medium':
          await this.handleMediumThreat(threat);
          break;
        default:
          console.warn('Unhandled threat severity:', threat);
      }
    }

    // Notify the user if needed
    if (threats.some(t => ['critical', 'high'].includes(t.severity))) {
      this.notifyUser(threats);
    }
  }

  async handleCriticalThreat(threat) {
    console.error('CRITICAL THREAT DETECTED:', threat);
    // Rotate encryption keys if a breach is detected
    if (threat.type === 'encryption_breach') {
      await see.rotateLayer();
    }
    // TODO: Implement additional critical threat handling
  }

  async handleHighThreat(threat) {
    console.warn('High severity threat detected:', threat);
    // TODO: Implement high threat handling
  }

  async handleMediumThreat(threat) {
    console.info('Medium severity threat detected:', threat);
    // TODO: Implement medium threat handling
  }

  notifyUser(threats) {
    // In a real app, this would show a notification to the user
    const notification = new Notification('Security Alert', {
      body: `${threats.length} security ${threats.length === 1 ? 'issue' : 'issues'} detected`,
      icon: '/icons/security-alert.png'
    });

    notification.onclick = () => {
      // Show security dashboard or details
      console.log('Show security dashboard');
    };
  }

  // Generate a security report
  generateSecurityReport() {
    const now = new Date();
    const last24h = new Date(now.getTime() - (24 * 60 * 60 * 1000));
    
    const recentEvents = this.securityEvents.filter(
      event => new Date(event.timestamp) > last24h
    );
    
    const severityCounts = recentEvents.reduce((acc, event) => {
      acc[event.severity] = (acc[event.severity] || 0) + 1;
      return acc;
    }, {});
    
    return {
      timestamp: now.toISOString(),
      eventsInLast24h: recentEvents.length,
      severityBreakdown: severityCounts,
      recentThreats: recentEvents
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, 10), // Show 10 most recent threats
      recommendations: this.generateRecommendations(recentEvents)
    };
  }

  generateRecommendations(events) {
    const recommendations = new Set();
    
    if (events.some(e => e.type === 'sensitive_data_exposure')) {
      recommendations.add('Enable end-to-end encryption for sensitive data');
    }
    
    if (events.some(e => e.type === 'exposed_token')) {
      recommendations.add('Implement token-based authentication with short-lived tokens');
    }
    
    if (events.some(e => e.severity === 'critical')) {
      recommendations.add('Review security policies and consider a security audit');
    }
    
    if (events.some(e => e.type === 'suspicious_pattern' && e.severity === 'high')) {
      recommendations.add('Update input validation to block suspicious patterns');
    }
    
    return Array.from(recommendations);
  }

  // Start a security scan of the application
  async runSecurityScan() {
    console.log('Starting security scan...');
    
    // Check for insecure content
    this.checkForInsecureContent();
    
    // Check for outdated dependencies
    await this.checkDependencies();
    
    // Check encryption status
    this.checkEncryptionStatus();
    
    console.log('Security scan completed');
    return this.generateSecurityReport();
  }

  checkForInsecureContent() {
    // Check for mixed content
    const insecureElements = [];
    
    // Check images, scripts, iframes, etc.
    document.querySelectorAll('img, script, iframe, link[rel="stylesheet"]').forEach(el => {
      const src = el.src || el.href;
      if (src && src.startsWith('http://') && !src.startsWith('http://localhost')) {
        insecureElements.push({
          element: el.tagName,
          src,
          type: 'insecure_content'
        });
      }
    });
    
    if (insecureElements.length > 0) {
      this.handleThreats([{
        type: 'insecure_content',
        severity: 'high',
        message: 'Insecure content detected',
        details: insecureElements,
        timestamp: new Date().toISOString(),
        recommendation: 'Load all resources over HTTPS to prevent man-in-the-middle attacks.'
      }]);
    }
  }

  async checkDependencies() {
    try {
      // In a real app, this would check against a vulnerability database
      const response = await fetch('/api/dependencies');
      if (response.ok) {
        const dependencies = await response.json();
        const vulnerableDeps = dependencies.filter(dep => dep.vulnerabilities && dep.vulnerabilities.length > 0);
        
        if (vulnerableDeps.length > 0) {
          this.handleThreats([{
            type: 'vulnerable_dependencies',
            severity: 'high',
            message: `${vulnerableDeps.length} vulnerable ${vulnerableDeps.length === 1 ? 'dependency' : 'dependencies'} found`,
            details: vulnerableDeps,
            timestamp: new Date().toISOString(),
            recommendation: 'Update vulnerable dependencies to their latest secure versions.'
          }]);
        }
      }
    } catch (error) {
      console.warn('Failed to check dependencies:', error);
    }
  }

  checkEncryptionStatus() {
    // Check if the current page is served over HTTPS
    if (window.location.protocol !== 'https:' && !window.location.hostname.match(/^localhost|127\.0\.0\.1$/)) {
      this.handleThreats([{
        type: 'insecure_connection',
        severity: 'high',
        message: 'Connection is not secure',
        details: {
          protocol: window.location.protocol,
          hostname: window.location.hostname
        },
        timestamp: new Date().toISOString(),
        recommendation: 'Always use HTTPS to encrypt all communications.'
      }]);
    }
    
    // Check if Web Crypto API is available
    if (!window.crypto || !window.crypto.subtle) {
      this.handleThreats([{
        type: 'crypto_unavailable',
        severity: 'medium',
        message: 'Web Crypto API not available',
        timestamp: new Date().toISOString(),
        recommendation: 'Ensure your application is served over HTTPS to enable cryptographic operations.'
      }]);
    }
  }
}

// Singleton instance
export const clippy = new ClippySecurityAssistant();

// Auto-initialize if running in a browser
if (typeof window !== 'undefined') {
  window.addEventListener('DOMContentLoaded', () => {
    // Request notification permission
    if (window.Notification && Notification.permission !== 'denied') {
      Notification.requestPermission();
    }
    
    // Start Clippy
    clippy.initialize();
  });
}
