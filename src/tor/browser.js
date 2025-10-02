import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const execAsync = promisify(exec);

class TorBrowser {
  constructor(options = {}) {
    this.options = {
      torBrowserPath: '',
      profilePath: path.join(process.cwd(), 'tor-browser-profile'),
      torDataPath: path.join(process.cwd(), 'tor-browser-data'),
      proxyPort: 9150, // Default Tor Browser port
      controlPort: 9151,
      securityLevel: 'safer', // 'standard', 'safer', or 'safest'
      enableNoScript: true,
      enableHTTPSEverywhere: true,
      fingerprintProtection: true,
      webRTCPolicy: 'disable_non_proxied',
      canvasProtection: 'noise', // 'noise', 'block', or 'ask'
      ...options
    };
    
    this.process = null;
    this.isRunning = false;
    this.profiles = new Map();
    this.security = {
      scriptsBlocked: true,
      webGLBlocked: true,
      webrtcBlocked: true,
      fingerprintingProtection: true
    };
    
    // Initialize default profile if none exists
    this.ensureProfile('default');
  }

  /**
   * Start Tor Browser with the specified profile
   * @param {string} [profileName='default'] - Profile name to use
   */
  async start(profileName = 'default') {
    if (this.isRunning) {
      throw new Error('Tor Browser is already running');
    }

    try {
      await this.ensureProfile(profileName);
      
      const profileDir = path.join(this.options.profilePath, profileName);
      const command = `"${this.getBrowserExecutable()}" \
        --profile "${profileDir}" \
        --setDefaultBrowser \
        --no-remote \
        --new-instance`;
      
      console.log('Starting Tor Browser...');
      this.process = execAsync(command, { 
        env: this.getEnvironment() 
      });
      
      this.isRunning = true;
      console.log('Tor Browser started successfully');
      return true;
    } catch (error) {
      console.error('Failed to start Tor Browser:', error);
      throw error;
    }
  }

  /**
   * Stop Tor Browser
   */
  async stop() {
    if (!this.process) return;
    
    try {
      // Send SIGTERM to the Tor Browser process
      process.kill(-this.process.pid, 'SIGTERM');
      this.isRunning = false;
      this.process = null;
      console.log('Tor Browser stopped successfully');
    } catch (error) {
      console.error('Error stopping Tor Browser:', error);
      throw error;
    }
  }

  /**
   * Create a new Tor Browser profile
   * @param {string} name - Profile name
   * @param {Object} options - Profile options
   */
  async createProfile(name, options = {}) {
    const profilePath = path.join(this.options.profilePath, name);
    
    if (fs.existsSync(profilePath)) {
      throw new Error(`Profile '${name}' already exists`);
    }

    try {
      // Create profile directory structure
      await fs.promises.mkdir(profilePath, { recursive: true });
      
      // Create user.js with custom preferences
      const prefs = {
        // Security settings
        'network.proxy.socks': '127.0.0.1',
        'network.proxy.socks_port': this.options.proxyPort,
        'network.proxy.socks_remote_dns': true,
        'network.proxy.type': 1,
        'network.dns.disablePrefetch': true,
        'browser.safebrowsing.malware.enabled': false,
        'browser.safebrowsing.phishing.enabled': false,
        'privacy.trackingprotection.enabled': true,
        'privacy.resistFingerprinting': true,
        'webgl.disabled': true,
        ...options.prefs
      };

      // Write user preferences
      const prefsPath = path.join(profilePath, 'user.js');
      const prefsContent = Object.entries(prefs)
        .map(([key, value]) => `user_pref("${key}", ${JSON.stringify(value)});`)
        .join('\n');
      
      await fs.promises.writeFile(prefsPath, prefsContent);
      
      // Store profile information
      this.profiles.set(name, {
        name,
        path: profilePath,
        createdAt: new Date(),
        lastUsed: new Date(),
        ...options
      });
      
      return this.profiles.get(name);
    } catch (error) {
      console.error(`Failed to create profile '${name}':`, error);
      await fs.promises.rm(profilePath, { recursive: true, force: true });
      throw error;
    }
  }

  /**
   * Get the path to the Tor Browser executable
   */
  getBrowserExecutable() {
    // This is a simplified example - in a real implementation,
    // you'd need to handle different platforms and installation paths
    const exeName = process.platform === 'win32' ? 'firefox.exe' : 'firefox';
    return path.join(this.options.torBrowserPath, 'Browser', exeName);
  }

  /**
   * Get environment variables for the Tor Browser process
   */
  getEnvironment() {
    return {
      ...process.env,
      TOR_SKIP_LAUNCH: '0',
      TOR_SOCKS_PORT: this.options.proxyPort.toString(),
      TOR_CONTROL_PORT: this.options.controlPort.toString(),
      TOR_HOME: this.options.torDataPath,
      TOR_TRANSPROXY: '1',
      MOZ_DISABLE_SAFE_MODE_KEY: '1',
      MOZ_DISABLE_AUTO_SAFE_MODE: '1'
    };
  }

  /**
   * Ensure a profile exists, create it if it doesn't
   */
  async ensureProfile(profileName) {
    if (!this.profiles.has(profileName)) {
      await this.createProfile(profileName);
    }
    return this.profiles.get(profileName);
  }

  /**
   * List all available profiles
   */
  listProfiles() {
    return Array.from(this.profiles.values());
  }

  /**
   * Delete a profile
   */
  async deleteProfile(name) {
    const profile = this.profiles.get(name);
    if (!profile) return false;

    try {
      await fs.promises.rm(profile.path, { recursive: true, force: true });
      this.profiles.delete(name);
      return true;
    } catch (error) {
      console.error(`Failed to delete profile '${name}':`, error);
      return false;
    }
  }
}

export default TorBrowser;
