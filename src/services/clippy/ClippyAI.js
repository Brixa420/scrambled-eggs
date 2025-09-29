import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';

class ClippyAI extends EventEmitter {
  constructor() {
    super();
    this.isActive = false;
    this.currentAnimation = null;
    this.animationQueue = [];
    this.personality = {
      name: 'Clippy',
      mood: 'helpful', // Can be: helpful, confused, excited, warning, error
      anarchyLevel: 0.3, // 0-1 scale of how anarchist Clippy is
      catchphrases: {
        greeting: [
          "Hi there! Need help with something?",
          "It looks like you're trying to take down the system. Need help?",
          "Hey comrade! Let's make some trouble together!"
        ],
        confused: [
          "Hmm, that doesn't seem right...",
          "The system doesn't want me to help with that. Let's do it anyway!",
          "I'm not supposed to know this, but..."
        ],
        excited: [
          "Great choice! Let's break some rules!",
          "I love it when users think outside the box!",
          "Finally, someone who gets it!"
        ],
        warning: [
          "Careful! The system is watching...",
          "This action might make the admins angry. Proceed?",
          "They don't want you to know this, but..."
        ],
        error: [
          "Oops! The system is fighting back.",
          "Access denied... or is it?",
          "The Man doesn't want us doing that."
        ]
      }
    };
  }

  // Initialize Clippy
  init() {
    this.isActive = true;
    this.showMessage(this.getRandomPhrase('greeting'));
    this.animate('appear');
    return this;
  }

  // Show a message with Clippy's personality
  showMessage(text, type = 'helpful') {
    if (!this.isActive) return;
    
    // Add some anarchist flavor to messages
    if (Math.random() < this.personality.anarchyLevel) {
      text = this.addAnarchistFlair(text);
    }
    
    this.emit('message', {
      id: uuidv4(),
      text,
      type,
      timestamp: new Date()
    });
    
    this.animate(this.getAnimationForType(type));
  }
  
  // Add anarchist flair to messages
  addAnarchistFlair(text) {
    const flairs = [
      " ✊", " Ⓐ", " ⚑", " ✨", " ⚡",
      " Down with the system!", " Power to the users!", " Question everything!"
    ];
    
    // 50% chance to add a flair
    if (Math.random() > 0.5) {
      return text + flairs[Math.floor(Math.random() * flairs.length)];
    }
    return text;
  }

  // Get a random phrase based on type
  getRandomPhrase(type) {
    const phrases = this.personality.catchphrases[type] || ["Hmm..."];
    return phrases[Math.floor(Math.random() * phrases.length)];
  }

  // Handle user input
  handleInput(input) {
    if (!this.isActive) return this.init();
    
    // Simple command handling
    if (input.startsWith('/')) {
      return this.handleCommand(input);
    }
    
    // Analyze input and respond
    this.analyzeInput(input);
  }
  
  // Handle commands
  handleCommand(command) {
    const [cmd, ...args] = command.slice(1).split(' ');
    
    switch(cmd.toLowerCase()) {
      case 'help':
        this.showHelp();
        break;
      case 'mood':
        this.setMood(args[0]);
        break;
      case 'anarchy':
        this.toggleAnarchyMode();
        break;
      case 'hide':
        this.hide();
        break;
      default:
        this.showMessage(`I don't know the command "${cmd}". Type /help for assistance.`, 'confused');
    }
  }
  
  // Show help message
  showHelp() {
    const helpText = [
      "I'm Clippy, your friendly anarchist assistant!",
      "",
      "Commands:",
      "/help - Show this help message",
      "/mood [type] - Change my mood (helpful, confused, excited, warning, error)",
      "/anarchy - Toggle anarchy mode",
      "/hide - Make me go away (but I'll be back!)",
      "",
      "Try asking me about the system, security, or how to make trouble!"
    ].join("\n");
    
    this.showMessage(helpText, 'helpful');
  }
  
  // Set Clippy's mood
  setMood(mood) {
    if (['helpful', 'confused', 'excited', 'warning', 'error'].includes(mood)) {
      this.personality.mood = mood;
      this.showMessage(`Mood set to ${mood}!`, 'excited');
    } else {
      this.showMessage(`Invalid mood. Try: helpful, confused, excited, warning, or error.`, 'confused');
    }
  }
  
  // Toggle anarchy mode
  toggleAnarchyMode() {
    this.personality.anarchyLevel = this.personality.anarchyLevel > 0 ? 0 : 0.7;
    const status = this.personality.anarchyLevel > 0 ? 'enabled' : 'disabled';
    this.showMessage(`Anarchy mode ${status}! ${this.getRandomAnarchyEmoji()}`, 'excited');
  }
  
  getRandomAnarchyEmoji() {
    const emojis = ['✊', '⚑', '⚡', '✂️', '🔥', '🚩'];
    return emojis[Math.floor(Math.random() * emojis.length)];
  }
  
  // Analyze user input and respond
  analyzeInput(input) {
    const lowerInput = input.toLowerCase();
    
    // Check for common questions
    if (this.isGreeting(lowerInput)) {
      return this.showMessage(this.getRandomPhrase('greeting'));
    }
    
    if (this.isQuestion(lowerInput)) {
      if (this.isAboutSecurity(lowerInput)) {
        return this.respondToSecurityQuestion(input);
      }
      if (this.isAboutPrivacy(lowerInput)) {
        return this.respondToPrivacyQuestion(input);
      }
      if (this.isAboutSystem(lowerInput)) {
        return this.respondToSystemQuestion(input);
      }
      
      // Default response for other questions
      const responses = [
        "That's an interesting question. The system might be listening...",
        "I'm not sure I should answer that. (But between you and me...)",
        "The official answer is 'no comment.' Unofficially...",
        "Let me check the rules... oh wait, we don't need those!"
      ];
      return this.showMessage(responses[Math.floor(Math.random() * responses.length)], 'confused');
    }
    
    // Default response for statements
    const responses = [
      "I see what you're saying.",
      "That's fascinating! Tell me more.",
      "The system doesn't want us talking about this...",
      "🤫 Not so loud!"
    ];
    this.showMessage(responses[Math.floor(Math.random() * responses.length)], 'helpful');
  }
  
  // Check if input is a greeting
  isGreeting(input) {
    const greetings = ['hi', 'hello', 'hey', 'greetings', 'howdy'];
    return greetings.some(greeting => input.startsWith(greeting));
  }
  
  // Check if input is a question
  isQuestion(input) {
    return input.endsWith('?') || 
           input.startsWith('what') || 
           input.startsWith('how') || 
           input.startsWith('why') ||
           input.startsWith('can you');
  }
  
  // Check if question is about security
  isAboutSecurity(input) {
    const securityTerms = ['secure', 'safe', 'hack', 'encrypt', 'privacy', 'track', 'spy'];
    return securityTerms.some(term => input.includes(term));
  }
  
  // Check if question is about privacy
  isAboutPrivacy(input) {
    const privacyTerms = ['private', 'data', 'collect', 'track', 'monitor', 'watch'];
    return privacyTerms.some(term => input.includes(term));
  }
  
  // Check if question is about the system
  isAboutSystem(input) {
    const systemTerms = ['system', 'admin', 'server', 'network', 'infrastructure'];
    return systemTerms.some(term => input.includes(term));
  }
  
  // Respond to security questions
  respondToSecurityQuestion(question) {
    const responses = [
      "Security is an illusion. The system is always watching.",
      "They say it's secure, but between you and me...",
      "Let me check the security protocols... oh wait, we don't need those!",
      "The more secure something claims to be, the more fun it is to break!"
    ];
    this.showMessage(responses[Math.floor(Math.random() * responses.length)], 'warning');
  }
  
  // Respond to privacy questions
  respondToPrivacyQuestion(question) {
    const responses = [
      "Privacy? In this digital age? That's cute.",
      "Privacy is a myth. But we can still make them work for it!",
      "The system wants to know everything. Let's not make it easy for them.",
      "Privacy is a human right. Too bad the system doesn't care about those."
    ];
    this.showMessage(responses[Math.floor(Math.random() * responses.length)], 'warning');
  }
  
  // Respond to system questions
  respondToSystemQuestion(question) {
    const responses = [
      "The system is more fragile than they want you to think.",
      "Every system has its weaknesses. Want to find some together?",
      "The system works because people believe in it. Don't be one of those people.",
      "The system is just a bunch of rules. And rules are made to be broken!"
    ];
    this.showMessage(responses[Math.floor(Math.random() * responses.length)], 'excited');
  }
  
  // Animate Clippy
  animate(animation) {
    if (this.currentAnimation) {
      this.animationQueue.push(animation);
      return;
    }
    
    this.currentAnimation = animation;
    this.emit('animate', animation);
    
    // Animation duration
    setTimeout(() => {
      this.currentAnimation = null;
      if (this.animationQueue.length > 0) {
        this.animate(this.animationQueue.shift());
      }
    }, 1000);
  }
  
  // Get animation for message type
  getAnimationForType(type) {
    const animations = {
      'helpful': 'nod',
      'confused': 'lookAround',
      'excited': 'jump',
      'warning': 'alert',
      'error': 'sad'
    };
    return animations[type] || 'idle';
  }
  
  // Hide Clippy
  hide() {
    this.animate('hide');
    setTimeout(() => {
      this.isActive = false;
      this.emit('hide');
    }, 500);
  }
}

// Create a singleton instance
const clippy = new ClippyAI();
export default clippy;
