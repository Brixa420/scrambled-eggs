<template>
  <div class="mfa-setup">
    <div v-if="!setupComplete" class="setup-container">
      <h2>Set Up Two-Factor Authentication</h2>
      
      <!-- Step 1: Choose Method -->
      <div v-if="currentStep === 'choose-method'" class="step">
        <p>Choose a method to set up two-factor authentication:</p>
        
        <div class="method-options">
          <div 
            v-for="method in availableMethods" 
            :key="method.value"
            class="method-option"
            :class="{ 'selected': selectedMethod === method.value }"
            @click="selectMethod(method.value)"
          >
            <div class="method-icon">
              <i :class="method.icon"></i>
            </div>
            <div class="method-details">
              <h3>{{ method.label }}</h3>
              <p>{{ method.description }}</p>
            </div>
          </div>
        </div>
        
        <div class="form-actions">
          <button 
            class="btn btn-primary" 
            :disabled="!selectedMethod"
            @click="startSetup"
          >
            Continue
          </button>
          <button 
            class="btn btn-link" 
            @click="$emit('cancel')"
          >
            Cancel
          </button>
        </div>
      </div>
      
      <!-- Step 2: Setup TOTP -->
      <div v-else-if="currentStep === 'setup-totp'" class="step">
        <h3>Set Up Authenticator App</h3>
        <p>Scan the QR code with your authenticator app or enter the code manually.</p>
        
        <div class="totp-setup">
          <div class="qr-code">
            <img :src="totpData.qrCodeUrl" alt="TOTP QR Code">
          </div>
          
          <div class="manual-setup">
            <p>Or enter this code manually:</p>
            <div class="secret-code">
              <code>{{ totpData.secret }}</code>
              <button 
                class="btn btn-sm btn-icon" 
                @click="copyToClipboard(totpData.secret)"
                title="Copy to clipboard"
              >
                <i class="fas fa-copy"></i>
              </button>
            </div>
            
            <div class="form-group">
              <label for="totp-code">Enter the 6-digit code from your app:</label>
              <input 
                id="totp-code"
                v-model="totpCode"
                type="text" 
                inputmode="numeric" 
                pattern="[0-9]*" 
                maxlength="6"
                placeholder="123456"
                class="form-control"
              />
              <small class="form-text text-muted">
                After scanning the QR code, enter the 6-digit code from your authenticator app.
              </small>
            </div>
            
            <div class="form-actions">
              <button 
                class="btn btn-primary" 
                :disabled="!totpCode || totpCode.length !== 6 || verifying"
                @click="verifyTotp"
              >
                <span v-if="verifying">
                  <i class="fas fa-spinner fa-spin"></i> Verifying...
                </span>
                <span v-else>Verify & Continue</span>
              </button>
              <button 
                class="btn btn-link" 
                @click="currentStep = 'choose-method'"
                :disabled="verifying"
              >
                Back
              </button>
            </div>
          </div>
        </div>
      </div>
      
      <!-- Step 3: Setup SMS -->
      <div v-else-if="currentStep === 'setup-sms'" class="step">
        <h3>Set Up SMS Authentication</h3>
        <p>We'll send a verification code to your phone number.</p>
        
        <div class="form-group">
          <label for="phone-number">Phone Number</label>
          <input 
            id="phone-number"
            v-model="phoneNumber"
            type="tel" 
            placeholder="+1234567890" 
            class="form-control"
            :disabled="verificationSent"
          />
          <small class="form-text text-muted">
            Enter your phone number with country code (e.g., +1234567890)
          </small>
        </div>
        
        <div v-if="verificationSent" class="verification-code">
          <div class="form-group">
            <label for="sms-code">Verification Code</label>
            <input 
              id="sms-code"
              v-model="smsCode"
              type="text" 
              inputmode="numeric" 
              pattern="[0-9]*" 
              maxlength="6"
              placeholder="123456"
              class="form-control"
            />
            <small class="form-text text-muted">
              Enter the 6-digit code sent to your phone
            </small>
          </div>
          
          <div class="form-actions">
            <button 
              class="btn btn-primary" 
              :disabled="!smsCode || smsCode.length !== 6 || verifying"
              @click="verifySms"
            >
              <span v-if="verifying">
                <i class="fas fa-spinner fa-spin"></i> Verifying...
              </span>
              <span v-else>Verify & Continue</span>
            </button>
            <button 
              class="btn btn-link" 
              @click="resendCode"
              :disabled="canResendIn > 0"
            >
              <span v-if="canResendIn > 0">
                Resend code in {{ canResendIn }}s
              </span>
              <span v-else>Resend code</span>
            </button>
          </div>
        </div>
        
        <div v-else class="form-actions">
          <button 
            class="btn btn-primary" 
            :disabled="!isValidPhoneNumber || sending"
            @click="sendVerificationCode"
          >
            <span v-if="sending">
              <i class="fas fa-spinner fa-spin"></i> Sending...
            </span>
            <span v-else>Send Verification Code</span>
          </button>
          <button 
            class="btn btn-link" 
            @click="currentStep = 'choose-method'"
            :disabled="sending"
          >
            Back
          </button>
        </div>
      </div>
      
      <!-- Step 4: Backup Codes -->
      <div v-else-if="currentStep === 'backup-codes'" class="step">
        <h3>Save Your Backup Codes</h3>
        <div class="alert alert-warning">
          <i class="fas fa-exclamation-triangle"></i>
          <strong>Important:</strong> Save these backup codes in a safe place. You'll need them if you lose access to your authenticator app.
        </div>
        
        <div class="backup-codes">
          <div v-for="(code, index) in backupCodes" :key="index" class="backup-code">
            {{ code }}
          </div>
        </div>
        
        <div class="form-actions">
          <button 
            class="btn btn-primary" 
            @click="copyBackupCodes"
          >
            <i class="fas fa-copy"></i> Copy Codes
          </button>
          <button 
            class="btn btn-secondary" 
            @click="downloadBackupCodes"
          >
            <i class="fas fa-download"></i> Download
          </button>
          <button 
            class="btn btn-success" 
            @click="finishSetup"
          >
            I've Saved My Codes
          </button>
        </div>
      </div>
    </div>
    
    <!-- Setup Complete -->
    <div v-else class="setup-complete">
      <div class="success-message">
        <i class="fas fa-check-circle"></i>
        <h3>Two-Factor Authentication is Now Active</h3>
        <p>Your account is now more secure with two-factor authentication enabled.</p>
      </div>
      
      <div class="next-steps">
        <h4>What's Next?</h4>
        <ul>
          <li>Make sure you've saved your backup codes in a safe place</li>
          <li>Download an authenticator app if you haven't already</li>
          <li>Review your security settings</li>
        </ul>
      </div>
      
      <div class="form-actions">
        <button 
          class="btn btn-primary" 
          @click="$emit('complete')"
        >
          Done
        </button>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'MfaSetup',
  data() {
    return {
      currentStep: 'choose-method',
      selectedMethod: null,
      totpData: {
        secret: '',
        qrCodeUrl: '',
      },
      totpCode: '',
      phoneNumber: '',
      smsCode: '',
      verificationSent: false,
      canResendIn: 0,
      resendTimer: null,
      backupCodes: [],
      setupComplete: false,
      loading: false,
      verifying: false,
      sending: false,
      
      availableMethods: [
        {
          value: 'totp',
          label: 'Authenticator App',
          icon: 'fas fa-mobile-alt',
          description: 'Use an app like Google Authenticator or Authy',
        },
        {
          value: 'sms',
          label: 'Text Message (SMS)',
          icon: 'fas fa-sms',
          description: 'Receive verification codes via SMS',
        },
      ],
    };
  },
  computed: {
    isValidPhoneNumber() {
      // Simple phone number validation (starts with + and has at least 8 digits)
      return /^\+[0-9]{8,}$/.test(this.phoneNumber);
    },
  },
  methods: {
    selectMethod(method) {
      this.selectedMethod = method;
    },
    
    async startSetup() {
      if (this.selectedMethod === 'totp') {
        this.setupTotp();
      } else if (this.selectedMethod === 'sms') {
        this.currentStep = 'setup-sms';
      }
    },
    
    async setupTotp() {
      this.loading = true;
      try {
        // Call API to get TOTP setup data
        const response = await this.$api.post('/mfa/setup', {
          method: 'totp',
        });
        
        this.totpData = {
          secret: response.data.secret,
          qrCodeUrl: response.data.qr_code_url,
        };
        
        this.currentStep = 'setup-totp';
      } catch (error) {
        this.$notify({
          type: 'error',
          title: 'Error',
          text: 'Failed to set up authenticator app. Please try again.',
        });
        console.error('Error setting up TOTP:', error);
      } finally {
        this.loading = false;
      }
    },
    
    async verifyTotp() {
      if (!this.totpCode || this.totpCode.length !== 6) return;
      
      this.verifying = true;
      try {
        // Call API to verify TOTP code
        const response = await this.$api.post('/mfa/verify', {
          method: 'totp',
          code: this.totpCode,
        });
        
        // If backup codes are returned, show them to the user
        if (response.data.backup_codes && response.data.backup_codes.length > 0) {
          this.backupCodes = response.data.backup_codes;
          this.currentStep = 'backup-codes';
        } else {
          this.setupComplete = true;
        }
      } catch (error) {
        this.$notify({
          type: 'error',
          title: 'Verification Failed',
          text: 'The code you entered is invalid or has expired. Please try again.',
        });
        console.error('Error verifying TOTP code:', error);
      } finally {
        this.verifying = false;
      }
    },
    
    async sendVerificationCode() {
      if (!this.isValidPhoneNumber) return;
      
      this.sending = true;
      try {
        // Call API to send verification code
        await this.$api.post('/mfa/setup', {
          method: 'sms',
          phone_number: this.phoneNumber,
        });
        
        this.verificationSent = true;
        this.startResendTimer();
      } catch (error) {
        this.$notify({
          type: 'error',
          title: 'Error',
          text: 'Failed to send verification code. Please try again.',
        });
        console.error('Error sending verification code:', error);
      } finally {
        this.sending = false;
      }
    },
    
    async verifySms() {
      if (!this.smsCode || this.smsCode.length !== 6) return;
      
      this.verifying = true;
      try {
        // Call API to verify SMS code
        const response = await this.$api.post('/mfa/verify', {
          method: 'sms',
          code: this.smsCode,
        });
        
        // If backup codes are returned, show them to the user
        if (response.data.backup_codes && response.data.backup_codes.length > 0) {
          this.backupCodes = response.data.backup_codes;
          this.currentStep = 'backup-codes';
        } else {
          this.setupComplete = true;
        }
      } catch (error) {
        this.$notify({
          type: 'error',
          title: 'Verification Failed',
          text: 'The code you entered is invalid or has expired. Please try again.',
        });
        console.error('Error verifying SMS code:', error);
      } finally {
        this.verifying = false;
      }
    },
    
    resendCode() {
      if (this.canResendIn > 0) return;
      
      this.smsCode = '';
      this.sendVerificationCode();
    },
    
    startResendTimer() {
      this.canResendIn = 60; // 60 seconds
      
      this.resendTimer = setInterval(() => {
        this.canResendIn--;
        
        if (this.canResendIn <= 0) {
          clearInterval(this.resendTimer);
          this.resendTimer = null;
        }
      }, 1000);
    },
    
    copyToClipboard(text) {
      navigator.clipboard.writeText(text).then(() => {
        this.$notify({
          type: 'success',
          title: 'Copied',
          text: 'Copied to clipboard',
        });
      }).catch(err => {
        console.error('Failed to copy text:', err);
      });
    },
    
    copyBackupCodes() {
      const text = this.backupCodes.join('\n');
      this.copyToClipboard(text);
    },
    
    downloadBackupCodes() {
      const text = `Scrambled Eggs - Backup Codes\n\n` +
        `IMPORTANT: Keep these codes in a safe place.\n` +
        `Each code can only be used once.\n\n` +
        this.backupCodes.join('\n');
      
      const blob = new Blob([text], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'scrambled-eggs-backup-codes.txt';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    },
    
    finishSetup() {
      this.setupComplete = true;
    },
  },
  beforeDestroy() {
    if (this.resendTimer) {
      clearInterval(this.resendTimer);
    }
  },
};
</script>

<style scoped>
.mfa-setup {
  max-width: 600px;
  margin: 0 auto;
  padding: 20px;
  background: #fff;
  border-radius: 8px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

h2, h3, h4 {
  color: #333;
  margin-bottom: 1rem;
}

.method-options {
  display: grid;
  gap: 1rem;
  margin: 1.5rem 0;
}

.method-option {
  display: flex;
  align-items: center;
  padding: 1rem;
  border: 1px solid #ddd;
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s;
}

.method-option:hover {
  border-color: #4a90e2;
  background-color: #f8f9fa;
}

.method-option.selected {
  border-color: #4a90e2;
  background-color: #f0f7ff;
}

.method-icon {
  font-size: 24px;
  margin-right: 1rem;
  color: #4a90e2;
  width: 40px;
  text-align: center;
}

.method-details h3 {
  margin: 0 0 0.25rem;
  font-size: 1rem;
}

.method-details p {
  margin: 0;
  color: #666;
  font-size: 0.9rem;
}

.totp-setup {
  display: flex;
  flex-direction: column;
  gap: 2rem;
  margin: 1.5rem 0;
}

@media (min-width: 768px) {
  .totp-setup {
    flex-direction: row;
  }
}

.qr-code {
  text-align: center;
  padding: 1rem;
  background: #fff;
  border: 1px solid #eee;
  border-radius: 6px;
  align-self: flex-start;
}

.qr-code img {
  max-width: 200px;
  height: auto;
}

.manual-setup {
  flex: 1;
}

.secret-code {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin: 1rem 0;
  padding: 0.75rem;
  background: #f8f9fa;
  border: 1px dashed #dee2e6;
  border-radius: 4px;
  font-family: monospace;
  font-size: 1.1rem;
  letter-spacing: 1px;
}

.backup-codes {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
  gap: 0.75rem;
  margin: 1.5rem 0;
}

.backup-code {
  padding: 0.5rem;
  background: #f8f9fa;
  border: 1px solid #dee2e6;
  border-radius: 4px;
  font-family: monospace;
  text-align: center;
  font-size: 0.9rem;
}

.form-actions {
  display: flex;
  gap: 0.75rem;
  margin-top: 1.5rem;
  padding-top: 1rem;
  border-top: 1px solid #eee;
}

.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  border: 1px solid transparent;
  border-radius: 4px;
  font-size: 0.9rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary {
  background-color: #4a90e2;
  color: white;
  border-color: #4a90e2;
}

.btn-primary:hover:not(:disabled) {
  background-color: #3a7bc8;
  border-color: #3a7bc8;
}

.btn-primary:disabled {
  opacity: 0.7;
  cursor: not-allowed;
}

.btn-link {
  background: none;
  border: none;
  color: #4a90e2;
  text-decoration: underline;
  padding: 0.5rem 1rem;
}

.btn-link:hover {
  color: #3a7bc8;
  text-decoration: none;
}

.setup-complete {
  text-align: center;
  padding: 2rem 0;
}

.success-message i {
  font-size: 4rem;
  color: #28a745;
  margin-bottom: 1rem;
}

.success-message h3 {
  color: #28a745;
  margin-bottom: 1rem;
}

.next-steps {
  text-align: left;
  margin: 2rem auto;
  max-width: 400px;
  padding: 1.5rem;
  background: #f8f9fa;
  border-radius: 6px;
}

.next-steps h4 {
  margin-top: 0;
  margin-bottom: 1rem;
  font-size: 1.1rem;
}

.next-steps ul {
  margin: 0;
  padding-left: 1.25rem;
}

.next-steps li {
  margin-bottom: 0.5rem;
  color: #555;
}
</style>
