import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const execAsync = promisify(exec);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

class TorManager {
  constructor(options = {}) {
    this.options = {
      torPath: 'tor', // Path to Tor executable or 'tor' if in PATH
      dataDir: path.join(process.cwd(), 'tor-data'),
      controlPort: 9051,
      socksPort: 9050,
      httpTunnelPort: 9080,
      ...options
    };
    
    this.process = null;
    this.isRunning = false;
    this.identity = null;
    this.circuitId = null;
    
    // Ensure data directory exists
    if (!fs.existsSync(this.options.dataDir)) {
      fs.mkdirSync(this.options.dataDir, { recursive: true });
    }
  }

  async start() {
    if (this.isRunning) {
      throw new Error('Tor is already running');
    }

    const torrcPath = path.join(this.options.dataDir, 'torrc');
    const torDataDir = path.join(this.options.dataDir, 'data');
    
    // Create torrc configuration
    const torrc = [
      `SocksPort ${this.options.socksPort}`,
      `ControlPort ${this.options.controlPort}`,
      `HTTPTunnelPort ${this.options.httpTunnelPort}`,
      `DataDirectory ${torDataDir}`,
      'ExitNodes {us}, {gb}, {de}',
      'StrictNodes 1',
      'NewCircuitPeriod 15',
      'MaxCircuitDirtiness 10',
      'CircuitBuildTimeout 10',
      'MaxCircuitDirtiness 600',
      'MaxClientCircuitsPending 16',
      'UseEntryGuards 1',
      'EnforceDistinctSubnets 1',
      'Log notice file ' + path.join(this.options.dataDir, 'tor-notices.log'),
      'Log info file ' + path.join(this.options.dataDir, 'tor-info.log'),
      'Log debug file ' + path.join(this.options.dataDir, 'tor-debug.log'),
      'AvoidDiskWrites 1',
      'SafeLogging 1',
      'WarnPlaintextPorts 23,109,110,143,80'
    ].join('\n');

    fs.writeFileSync(torrcPath, torrc);

    try {
      // Start Tor process
      const { stderr } = await execAsync(
        `"${this.options.torPath}" -f "${torrcPath}"`,
        { 
          windowsHide: true,
          detached: true 
        }
      );

      this.process = stderr;
      this.isRunning = true;
      
      // Wait for Tor to bootstrap
      await this.waitForBootstrap();
      
      // Get a new identity
      await this.newIdentity();
      
      return true;
    } catch (error) {
      console.error('Failed to start Tor:', error);
      this.isRunning = false;
      throw error;
    }
  }

  async stop() {
    if (!this.isRunning) return;
    
    try {
      await this.sendSignal('SIGNAL HALT');
      this.process = null;
      this.isRunning = false;
      return true;
    } catch (error) {
      console.error('Error stopping Tor:', error);
      throw error;
    }
  }

  async restart() {
    await this.stop();
    return this.start();
  }

  async newIdentity() {
    if (!this.isRunning) {
      throw new Error('Tor is not running');
    }

    try {
      // Signal Tor to create new circuit
      await this.sendSignal('SIGNAL NEWNYM');
      
      // Wait for circuit to be established
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Get new identity information
      const { stdout } = await execAsync(`tor-resolve -x icanhazip.com ${this.options.socksPort}`);
      this.identity = stdout.trim();
      
      // Get circuit ID
      await this.updateCircuitInfo();
      
      return this.identity;
    } catch (error) {
      console.error('Failed to get new identity:', error);
      throw error;
    }
  }

  async getCurrentIp() {
    if (!this.isRunning) {
      throw new Error('Tor is not running');
    }

    try {
      const { stdout } = await execAsync(`tor-resolve -x icanhazip.com ${this.options.socksPort}`);
      return stdout.trim();
    } catch (error) {
      console.error('Failed to get current IP:', error);
      throw error;
    }
  }

  async getCircuitInfo() {
    if (!this.isRunning) return null;
    
    try {
      const { stdout } = await execAsync(
        `torify curl -s --socks5-hostname 127.0.0.1:${this.options.socksPort} https://check.torproject.org/api/address`
      );
      
      return JSON.parse(stdout);
    } catch (error) {
      console.error('Failed to get circuit info:', error);
      return null;
    }
  }

  async updateCircuitInfo() {
    const info = await this.getCircuitInfo();
    if (info) {
      this.circuitId = info.circuit_id;
      this.identity = info.ip;
    }
    return info;
  }

  async waitForBootstrap() {
    const maxAttempts = 30;
    let attempts = 0;
    
    while (attempts < maxAttempts) {
      try {
        const { stdout } = await execAsync(
          `echo 'GETINFO status/bootstrap-phase' | nc 127.0.0.1 ${this.options.controlPort}`
        );
        
        if (stdout.includes('BOOTSTRAP PROGRESS=100')) {
          return true;
        }
        
        attempts++;
        await new Promise(resolve => setTimeout(resolve, 1000));
      } catch (error) {
        attempts++;
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
    
    throw new Error('Tor bootstrap timeout');
  }

  async sendSignal(signal) {
    return new Promise((resolve, reject) => {
      const cmd = `echo '${signal}' | nc 127.0.0.1 ${this.options.controlPort}`;
      
      exec(cmd, (error, stdout, stderr) => {
        if (error) {
          reject(new Error(`Failed to send signal: ${stderr || error.message}`));
        } else {
          resolve(stdout);
        }
      });
    });
  }

  getSocksProxy() {
    return {
      host: '127.0.0.1',
      port: this.options.socksPort,
      type: 'socks5'
    };
  }

  getHttpProxy() {
    return `http://127.0.0.1:${this.options.httpTunnelPort}`;
  }

  getStatus() {
    return {
      isRunning: this.isRunning,
      identity: this.identity,
      circuitId: this.circuitId,
      socksPort: this.options.socksPort,
      controlPort: this.options.controlPort,
      httpTunnelPort: this.options.httpTunnelPort
    };
  }
}

export default TorManager;
