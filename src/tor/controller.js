import TorManager from './index.js';
import TorBrowser from './browser.js';
import { EventEmitter } from 'events';

class TorController extends EventEmitter {
  constructor(options = {}) {
    super();
    
    this.options = {
      torBrowserPath: '',
      torDataPath: path.join(process.cwd(), 'tor-data'),
      profilePath: path.join(process.cwd(), 'tor-profiles'),
      ...options,
      torOptions: {
        controlPort: 9051,
        socksPort: 9050,
        httpTunnelPort: 9080,
        ...(options.torOptions || {})
      },
      browserOptions: {
        proxyPort: 9150,
        controlPort: 9151,
        ...(options.browserOptions || {})
      }
    };
    
    this.tor = new TorManager(this.options.torOptions);
    this.browser = new TorBrowser({
      torBrowserPath: this.options.torBrowserPath,
      profilePath: this.options.profilePath,
      torDataPath: this.options.torDataPath,
      ...this.options.browserOptions
    });
    
    this.isInitialized = false;
  }
  
  /**
   * Initialize the Tor controller
   */
  async init() {
    if (this.isInitialized) return;
    
    try {
      // Start Tor daemon
      await this.tor.start();
      
      // Start bandwidth monitoring
      this.tor.startBandwidthMonitoring();
      
      // Set up event listeners
      this.setupEventListeners();
      
      this.isInitialized = true;
      this.emit('ready');
      return true;
    } catch (error) {
      console.error('Failed to initialize Tor controller:', error);
      this.emit('error', error);
      throw error;
    }
  }
  
  /**
   * Start Tor Browser
   * @param {string} [profileName='default'] - Profile name to use
   */
  async startBrowser(profileName = 'default') {
    if (!this.isInitialized) {
      await this.init();
    }
    
    try {
      await this.browser.start(profileName);
      this.emit('browser:started', { profileName });
      return true;
    } catch (error) {
      console.error('Failed to start Tor Browser:', error);
      this.emit('error', error);
      throw error;
    }
  }
  
  /**
   * Stop Tor Browser
   */
  async stopBrowser() {
    try {
      await this.browser.stop();
      this.emit('browser:stopped');
      return true;
    } catch (error) {
      console.error('Failed to stop Tor Browser:', error);
      this.emit('error', error);
      throw error;
    }
  }
  
  /**
   * Create a new identity
   */
  async newIdentity() {
    try {
      await this.tor.newIdentity();
      this.emit('identity:rotated');
      return true;
    } catch (error) {
      console.error('Failed to create new identity:', error);
      this.emit('error', error);
      throw error;
    }
  }
  
  /**
   * Get current status
   */
  async getStatus() {
    try {
      const [torStatus, browserStatus] = await Promise.all([
        this.tor.getStatus(),
        {
          isRunning: this.browser.isRunning,
          profiles: this.browser.listProfiles()
        }
      ]);
      
      return {
        tor: torStatus,
        browser: browserStatus,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Failed to get status:', error);
      throw error;
    }
  }
  
  /**
   * Set up event listeners
   */
  setupEventListeners() {
    // Tor events
    this.tor.on('circuit:created', (circuit) => {
      this.emit('tor:circuit:created', circuit);
    });
    
    this.tor.on('identity:rotated', (identity) => {
      this.emit('tor:identity:rotated', identity);
    });
    
    this.tor.on('bandwidth:update', (stats) => {
      this.emit('tor:bandwidth:update', stats);
    });
    
    // Browser events
    this.browser.on('browser:started', (details) => {
      this.emit('browser:started', details);
    });
    
    this.browser.on('browser:stopped', () => {
      this.emit('browser:stopped');
    });
  }
  
  /**
   * Clean up resources
   */
  async cleanup() {
    try {
      await this.browser.stop();
      await this.tor.stop();
      this.removeAllListeners();
      this.isInitialized = false;
      this.emit('cleanup');
      return true;
    } catch (error) {
      console.error('Error during cleanup:', error);
      this.emit('error', error);
      throw error;
    }
  }
}

export default TorController;
