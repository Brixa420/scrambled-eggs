import { aiVoiceService } from './AIVoiceService';
import { computerVisionService } from './ComputerVisionService';

export class AIConversationService {
  constructor() {
    this.conversationContext = [];
    this.isSpeaking = false;
    this.visionEnabled = false;
    this.videoElement = null;
    this.visionTimer = null;
    this.lastVisionUpdate = 0;
    this.visionUpdateInterval = 5000; // ms between vision updates
    this.systemPrompt = `You are Clippy, a helpful AI assistant with the ability to see and describe the world. 
You are integrated into a secure messaging application with voice capabilities.
Be concise, helpful, and friendly.`;
  }

  // Initialize the conversation with system prompt
  async initialize() {
    // Load necessary models
    try {
      await computerVisionService.loadModel();
      console.log('AI Conversation Service initialized');
      return true;
    } catch (error) {
      console.error('Failed to initialize AI Conversation Service:', error);
      return false;
    }
  }

  // Set the video element for computer vision
  setVideoElement(element) {
    this.videoElement = element;
    if (element && this.visionEnabled) {
      this.startVisionUpdates();
    } else {
      this.stopVisionUpdates();
    }
  }

  // Toggle computer vision
  toggleVision(enabled) {
    this.visionEnabled = enabled;
    if (enabled && this.videoElement) {
      this.startVisionUpdates();
    } else {
      this.stopVisionUpdates();
    }
  }

  // Start periodic vision updates
  startVisionUpdates() {
    this.stopVisionUpdates();
    
    const checkVision = async () => {
      if (!this.visionEnabled || !this.videoElement) return;
      
      try {
        const now = Date.now();
        if (now - this.lastVisionUpdate >= this.visionUpdateInterval) {
          const predictions = await computerVisionService.detectObjects(this.videoElement);
          if (predictions.length > 0) {
            const description = computerVisionService.generateObjectDescription(predictions);
            this.addToContext('system', `[Vision] ${description}`);
            this.lastVisionUpdate = now;
          }
        }
      } catch (error) {
        console.error('Error in vision update:', error);
      }
      
      this.visionTimer = setTimeout(checkVision, 1000);
    };
    
    this.visionTimer = setTimeout(checkVision, 1000);
  }

  // Stop vision updates
  stopVisionUpdates() {
    if (this.visionTimer) {
      clearTimeout(this.visionTimer);
      this.visionTimer = null;
    }
  }

  // Add a message to the conversation context
  addToContext(role, content) {
    this.conversationContext.push({ role, content });
    // Keep only the last 10 messages to manage context size
    if (this.conversationContext.length > 10) {
      this.conversationContext = this.conversationContext.slice(-10);
    }
  }

  // Generate a response to user input
  async generateResponse(userInput) {
    try {
      // Add user message to context
      this.addToContext('user', userInput);
      
      // In a real implementation, this would call an AI API
      // For now, we'll simulate a response
      const response = await this.simulateAIResponse(userInput);
      
      // Add AI response to context
      this.addToContext('assistant', response);
      
      return response;
    } catch (error) {
      console.error('Error generating AI response:', error);
      return "I'm sorry, I encountered an error processing your request.";
    }
  }

  // Simulate an AI response (replace with actual API call)
  async simulateAIResponse(userInput) {
    // Simple response simulation
    const responses = [
      "I understand you said: " + userInput + ". How can I assist you further?",
      "That's interesting! " + 
        (this.visionEnabled ? "I can see some objects in the video feed. " : "") + 
        "What would you like to know?",
      "Thanks for sharing that. Is there anything specific you'd like help with?",
      "I'm here to help! " + 
        (this.visionEnabled ? "I can also describe what I see in the video. " : "") + 
        "What can I do for you?"
    ];
    
    // Simple logic to vary responses
    const index = Math.floor(Math.random() * responses.length);
    return responses[index];
  }

  // Speak the given text
  async speak(text, options = {}) {
    if (this.isSpeaking) {
      aiVoiceService.stopSpeaking();
    }
    
    this.isSpeaking = true;
    try {
      await aiVoiceService.speak(text, options);
    } catch (error) {
      console.error('Error in text-to-speech:', error);
    } finally {
      this.isSpeaking = false;
    }
  }

  // Set the voice profile
  setVoiceProfile(profileName) {
    return aiVoiceService.setVoiceProfile(profileName);
  }

  // Get available voice profiles
  getVoiceProfiles() {
    return aiVoiceService.getVoiceProfiles();
  }

  // Clean up resources
  cleanup() {
    this.stopVisionUpdates();
    computerVisionService.dispose();
    aiVoiceService.stopSpeaking();
    this.conversationContext = [];
  }
}

// Singleton instance
export const aiConversationService = new AIConversationService();
