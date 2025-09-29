<template>
  <div class="mfa-verification">
    <div class="card">
      <div class="card-header">
        <h2>Two-Factor Authentication</h2>
      </div>
      <div class="card-body">
        <div v-if="verificationMethod === 'totp'" class="method-totp">
          <p>Enter the 6-digit code from your authenticator app</p>
          <div class="otp-inputs">
            <input
              v-for="i in 6"
              :key="i"
              ref="otpInputs"
              v-model="otp[i-1]"
              type="text"
              maxlength="1"
              @input="onOtpInput(i-1, $event)"
              @keydown.delete="onOtpKeydown(i-1, $event)"
              @paste="onPaste"
              :class="{ 'is-invalid': error }"
            />
          </div>
        </div>

        <div v-else-if="verificationMethod === 'backup'" class="method-backup">
          <p>Enter one of your backup codes</p>
          <div class="form-group">
            <input
              v-model="backupCode"
              type="text"
              class="form-control"
              :class="{ 'is-invalid': error }"
              placeholder="Backup code"
              @keyup.enter="verifyBackupCode"
            />
          </div>
          <button 
            class="btn btn-primary" 
            @click="verifyBackupCode"
            :disabled="!backupCode || loading"
          >
            <span v-if="loading" class="spinner-border spinner-border-sm"></span>
            Verify Backup Code
          </button>
        </div>

        <!-- Lockout Message -->
        <div v-if="isLocked" class="alert alert-warning mt-3">
          <div class="d-flex justify-content-between align-items-center">
            <span>Too many failed attempts. Please try again in {{ formatTime(countdown) }}</span>
          </div>
          <div class="progress mt-2" style="height: 5px;">
            <div 
              class="progress-bar bg-warning" 
              role="progressbar" 
              :style="{ width: lockoutProgress + '%' }"
              :aria-valuenow="lockoutProgress" 
              aria-valuemin="0" 
              aria-valuemax="100">
            </div>
          </div>
        </div>

        <!-- Error Message -->
        <div v-else-if="error" class="alert alert-danger mt-3">
          <div>{{ error }}</div>
          <div v-if="remainingAttempts < 5" class="mt-2 small">
            <i class="fas fa-info-circle"></i> {{ remainingAttemptsText }}
          </div>
        </div>

        <div class="mt-4 text-center">
          <button 
            v-if="verificationMethod === 'totp'" 
            class="btn btn-link"
            @click="switchToBackup"
          >
            Use a backup code instead
          </button>
          <button 
            v-else 
            class="btn btn-link"
            @click="verificationMethod = 'totp'"
          >
            Use authenticator app
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'MfaVerification',
  props: {
    mfaRequired: {
      type: Boolean,
      default: false
    },
    email: {
      type: String,
      required: true
    },
    password: {
      type: String,
      required: true
    }
  },
  data() {
    return {
      verificationMethod: 'totp',
      otp: Array(6).fill(''),
      backupCode: '',
      loading: false,
      error: '',
      remainingAttempts: 5,
      lockoutUntil: null,
      lockoutTimer: null,
      countdown: 0
    };
  },
    otp: {
      handler(newVal) {
        // Auto-submit when all OTP digits are entered
        if (newVal.every(digit => digit !== '') && this.verificationMethod === 'totp') {
          this.verifyTotp();
        }
      },
      deep: true
    },
    lockoutTimeLeft: {
      immediate: true,
      handler(seconds) {
        if (this.lockoutTimer) {
          clearInterval(this.lockoutTimer);
          this.lockoutTimer = null;
        }
        
        if (seconds > 0) {
          this.countdown = seconds;
          this.lockoutTimer = setInterval(() => {
            this.countdown--;
            if (this.countdown <= 0) {
              clearInterval(this.lockoutTimer);
              this.lockoutTimer = null;
              this.lockoutUntil = null;
              this.remainingAttempts = 5; // Reset attempts after lockout expires
            }
          }, 1000);
        }
      }
    }
  },
  mounted() {
    if (this.mfaRequired) {
      this.focusFirstInput();
    }
    
    // Clean up interval on component destroy
    this.$once('hook:beforeDestroy', () => {
      if (this.lockoutTimer) {
        clearInterval(this.lockoutTimer);
      }
    });
  }
  },
  methods: {
    formatTime(seconds) {
      const mins = Math.floor(seconds / 60);
      const secs = seconds % 60;
{{ ... }}
      
      await this.verifyMfa('backup', this.backupCode.trim());
    },
    
    async verifyMfa(method, code) {
      // Don't proceed if locked out
      if (this.isLocked) {
        this.error = 'Please wait until the lockout period ends before trying again.';
        return;
      }

      this.loading = true;
      this.error = '';

      try {
        const response = await this.$http.post('/api/v1/auth/mfa/verify', {
          method,
          code,
          device_name: 'Web Browser',
          remember_me: true
        });

        // Reset state on success
        this.remainingAttempts = 5;
        this.lockoutUntil = null;
        
        // Emit success event with the response
        this.$emit('verified', response.data);
      } catch (error) {
        const response = error.response?.data;
        
        // Handle lockout
        if (error.response?.status === 403 && response?.retry_after) {
          this.lockoutUntil = new Date(Date.now() + (response.retry_after * 1000));
          this.remainingAttempts = 0;
          this.error = 'Too many failed attempts. Your account has been temporarily locked.';
        } 
        // Handle failed attempt (but not locked out yet)
        else if (error.response?.status === 400) {
          this.remainingAttempts = response?.remaining_attempts || this.remainingAttempts - 1;
          this.error = response?.message || 'Invalid verification code. Please try again.';
          
          // Clear OTP on error for better UX
          if (method === 'totp') {
            this.otp = Array(6).fill('');
            this.$nextTick(() => this.focusFirstInput());
          }
        } 
        // Handle other errors
        else {
          this.error = response?.detail || 'Verification failed. Please try again.';
          if (method === 'totp') {
            this.otp = Array(6).fill('');
            this.$nextTick(() => this.focusFirstInput());
          }
        }
      } finally {
        this.loading = false;
      }
    }
  }
{{ ... }}
</script>

<style scoped>
.otp-inputs {
  display: flex;
  justify-content: center;
  gap: 10px;
  margin: 20px 0;
}

.otp-inputs input {
  width: 45px;
  height: 60px;
  text-align: center;
  font-size: 24px;
  border: 2px solid #dee2e6;
  border-radius: 8px;
  transition: all 0.3s;
}

.otp-inputs input:focus {
  border-color: #80bdff;
  box-shadow: 0 0 0 0.2rem rgba(0, 123, 255, 0.25);
  outline: none;
}

.otp-inputs input.is-invalid {
  border-color: #dc3545;
}

.otp-inputs input.is-locked {
  background-color: #f8f9fa;
  cursor: not-allowed;
}

.progress {
  background-color: #ffe8a1;
  border-radius: 10px;
}

.progress-bar {
  transition: width 1s linear;
}

.btn:disabled {
  cursor: not-allowed;
}

.alert {
  border-radius: 8px;
}

.alert-warning {
  background-color: #fff3cd;
  border-color: #ffeeba;
  color: #856404;
}

.small {
  font-size: 0.85em;
  opacity: 0.9;
}

.fa-info-circle {
  margin-right: 5px;
}
.mfa-verification {
  max-width: 400px;
  margin: 2rem auto;
}

.card {
  border: none;
  box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.1);
}

.card-header {
  background-color: #f8f9fa;
  border-bottom: 1px solid #e9ecef;
  text-align: center;
  padding: 1.5rem;
}

.card-header h2 {
  margin: 0;
  font-size: 1.5rem;
  color: #333;
}

.card-body {
  padding: 2rem;
}

.otp-inputs {
  display: flex;
  justify-content: space-between;
  margin: 1.5rem 0;
}

.otp-inputs input {
  width: 3rem;
  height: 3.5rem;
  text-align: center;
  font-size: 1.5rem;
  border: 1px solid #ced4da;
  border-radius: 4px;
  margin: 0 0.25rem;
  transition: border-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out;
}

.otp-inputs input:focus {
  border-color: #80bdff;
  outline: 0;
  box-shadow: 0 0 0 0.2rem rgba(0, 123, 255, 0.25);
  z-index: 1;
}

.otp-inputs input.is-invalid {
  border-color: #dc3545;
  background-color: #fff8f8;
}

.otp-inputs input:disabled {
  background-color: #e9ecef;
  opacity: 0.7;
  cursor: not-allowed;
}

.attempts-remaining {
  text-align: center;
  min-height: 1.5rem;
}

.alert {
  border-radius: 0.375rem;
  padding: 1rem;
  margin-bottom: 1rem;
  border: 1px solid transparent;
}

.alert-danger {
  color: #721c24;
  background-color: #f8d7da;
  border-color: #f5c6cb;
}

.alert-warning {
  color: #856404;
  background-color: #fff3cd;
  border-color: #ffeeba;
}

.btn-link {
  color: #007bff;
  text-decoration: none;
  background: none;
  border: none;
  padding: 0.25rem 0.5rem;
  font-size: 0.875rem;
}

.btn-link:hover {
  text-decoration: underline;
  color: #0056b3;
}

.btn-link:disabled {
  color: #6c757d;
  pointer-events: none;
  text-decoration: none;
}

.spinner-border {
  vertical-align: text-bottom;
}

.progress {
  height: 5px;
  border-radius: 2.5px;
  background-color: #e9ecef;
  overflow: hidden;
  margin: 0.5rem 0;
}

.progress-bar {
  height: 100%;
  transition: width 0.6s ease;
}
</style>
