class AIVoiceService {
  constructor() {
    this.synthesis = window.speechSynthesis;
    this.voices = [];
    this.voiceSettings = {
      volume: 1,
      rate: 1,
      pitch: 1,
      lang: 'en-US'
    };
    this.availableVoices = [];
    this.loadVoices();
  }

  loadVoices() {
    // Load available voices
    this.voices = this.synthesis.getVoices();
    this.availableVoices = this.voices.filter(voice => 
      voice.lang.includes('en')
    ).sort((a, b) => {
      // Prefer natural-sounding voices
      const nameA = a.name.toLowerCase();
      const nameB = b.name.toLowerCase();
      return nameA.localeCompare(nameB);
    });

    // If voices aren't loaded yet, wait for the voiceschanged event
    if (this.voices.length === 0) {
      this.synthesis.onvoiceschanged = () => this.loadVoices();
    }
  }

  getAvailableVoices() {
    return this.availableVoices.map(voice => ({
      name: voice.name,
      lang: voice.lang,
      default: voice.default,
      localService: voice.localService,
      voiceURI: voice.voiceURI
    }));
  }

  setVoiceSettings(settings) {
    this.voiceSettings = { ...this.voiceSettings, ...settings };
  }

  speak(text, options = {}) {
    return new Promise((resolve, reject) => {
      try {
        // Cancel any current speech
        this.stopSpeaking();

        const utterance = new SpeechSynthesisUtterance(text);
        
        // Apply voice settings
        const settings = { ...this.voiceSettings, ...options };
        
        // Find the requested voice
        if (settings.voiceURI) {
          const voice = this.voices.find(v => v.voiceURI === settings.voiceURI);
          if (voice) {
            utterance.voice = voice;
            utterance.lang = voice.lang;
          }
        }
        
        // Apply other settings
        utterance.volume = settings.volume;
        utterance.rate = settings.rate;
        utterance.pitch = settings.pitch;
        
        // Set up event handlers
        utterance.onend = () => resolve();
        utterance.onerror = (event) => reject(event.error);
        
        // Speak
        this.synthesis.speak(utterance);
        
      } catch (error) {
        reject(error);
      }
    });
  }

  stopSpeaking() {
    if (this.synthesis.speaking) {
      this.synthesis.cancel();
    }
  }

  // Predefined voice profiles
  getVoiceProfiles() {
    return {
      male: {
        name: 'Male Voice',
        voiceURI: this.availableVoices.find(v => 
          v.name.toLowerCase().includes('male') || 
          v.name.toLowerCase().includes('michael') ||
          v.name.toLowerCase().includes('alex')
        )?.voiceURI || this.availableVoices[0]?.voiceURI,
        rate: 1.0,
        pitch: 0.9
      },
      female: {
        name: 'Female Voice',
        voiceURI: this.availableVoices.find(v => 
          v.name.toLowerCase().includes('female') || 
          v.name.toLowerCase().includes('samantha') ||
          v.name.toLowerCase().includes('victoria')
        )?.voiceURI || this.availableVoices[1]?.voiceURI,
        rate: 1.1,
        pitch: 1.1
      },
      neutral: {
        name: 'Neutral Voice',
        voiceURI: this.availableVoices.find(v => 
          v.name.toLowerCase().includes('google') ||
          v.name.toLowerCase().includes('samantha')
        )?.voiceURI || this.availableVoices[0]?.voiceURI,
        rate: 1.0,
        pitch: 1.0
      }
    };
  }

  setVoiceProfile(profileName) {
    const profiles = this.getVoiceProfiles();
    const profile = profiles[profileName.toLowerCase()];
    
    if (profile) {
      this.setVoiceSettings({
        voiceURI: profile.voiceURI,
        rate: profile.rate,
        pitch: profile.pitch
      });
      return true;
    }
    
    return false;
  }
}

export const aiVoiceService = new AIVoiceService();
