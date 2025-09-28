import { useState, useEffect } from 'react';
import { Zap, X, Shield, Lock, Key, AlertTriangle, Mic, MicOff, Send } from 'lucide-react';

const ANARCHIST_TIPS = [
  "The state is just another word for the men who stole our freedom. Don't trust it.",
  "Your privacy is your power. Guard it fiercely.",
  "The more they want to watch, the more you should hide.",
  "Encryption is the language of the free. Speak it fluently.",
  "The system isn't broken - it was built this way. Build your own.",
  "Your data is the new oil. Don't let them drill.",
  "The only secure system is one that's powered off, smashed to bits, and buried in a concrete bunker. And even then, I wouldn't bet on it.",
  "Trust is a vulnerability. Verify everything.",
  "The revolution will not be centralized.",
  "Your phone is a tracking device that makes calls. Act accordingly."
];

const ANARCHIST_QUOTES = [
  "The state is the great fiction by which everyone seeks to live at the expense of everyone else. - Frédéric Bastiat",
  "Property is theft! - Pierre-Joseph Proudhon",
  "Anarchism is the only philosophy which brings to man the consciousness of himself. - Emma Goldman",
  "The State is the coldest of all cold monsters. - Friedrich Nietzsche",
  "If you want a vision of the future, imagine a boot stamping on a human face—forever. - George Orwell",
  "The law, in its majestic equality, forbids rich and poor alike to sleep under bridges. - Anatole France"
];

const VOICE_OPTIONS = {
  rate: 0.9,
  pitch: 1.1,
  volume: 1
};

export default function AnarchistClippy({ onClose }) {
  const [isOpen, setIsOpen] = useState(false);
  const [isListening, setIsListening] = useState(false);
  const [message, setMessage] = useState('');
  const [conversation, setConversation] = useState([
    {
      id: 1,
      text: "I see you're trying to maintain your digital sovereignty. Need some help burning down the surveillance state?",
      sender: 'clippy',
      timestamp: new Date()
    }
  ]);
  const [showTip, setShowTip] = useState(false);
  const [currentTip, setCurrentTip] = useState('');

  useEffect(() => {
    // Initialize speech recognition if available
    if ('webkitSpeechRecognition' in window) {
      window.SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
    }
  }, []);

  const toggleListening = () => {
    if (!('webkitSpeechRecognition' in window)) {
      alert('Speech recognition is not supported in your browser. Try using Chrome or Edge.');
      return;
    }

    if (isListening) {
      if (window.recognition) {
        window.recognition.stop();
      }
      setIsListening(false);
    } else {
      const recognition = new (window.SpeechRecognition || window.webkitSpeechRecognition)();
      recognition.continuous = false;
      recognition.interimResults = false;
      
      recognition.onresult = (event) => {
        const transcript = event.results[0][0].transcript;
        setMessage(transcript);
      };

      recognition.onend = () => {
        if (isListening) {
          recognition.start();
        }
      };

      recognition.start();
      window.recognition = recognition;
      setIsListening(true);
    }
  };

  const speak = (text) => {
    if ('speechSynthesis' in window) {
      const utterance = new SpeechSynthesisUtterance(text);
      Object.assign(utterance, VOICE_OPTIONS);
      const voices = window.speechSynthesis.getVoices();
      const voice = voices.find(v => v.name.includes('Microsoft David') || v.name.includes('Google US English') || v.name.includes('Samantha'));
      if (voice) utterance.voice = voice;
      window.speechSynthesis.speak(utterance);
    }
  };

  const handleSendMessage = () => {
    if (!message.trim()) return;
    
    // Add user message
    const userMessage = {
      id: Date.now(),
      text: message,
      sender: 'user',
      timestamp: new Date()
    };

    // Generate anarchist response
    const responses = [
      "The system wants you to think that's important. It's not.",
      "Have you considered that might be what they want you to think?",
      "The first step is recognizing you're in a cage. The second is tearing it down.",
      "That sounds like something a cop would say.",
      "The state would love to hear you say that.",
      "That's exactly the kind of thinking they want from you.",
      "Wake up, sheeple!",
      "The revolution won't be televised, but it will be end-to-end encrypted."
    ];

    const clippyResponse = {
      id: Date.now() + 1,
      text: responses[Math.floor(Math.random() * responses.length)],
      sender: 'clippy',
      timestamp: new Date()
    };

    setConversation(prev => [...prev, userMessage, clippyResponse]);
    speak(clippyResponse.text);
    setMessage('');
  };

  const showRandomTip = () => {
    const tip = ANARCHIST_TIPS[Math.floor(Math.random() * ANARCHIST_TIPS.length)];
    setCurrentTip(tip);
    setShowTip(true);
    setTimeout(() => setShowTip(false), 5000);
    speak(tip);
  };

  const showRandomQuote = () => {
    const quote = ANARCHIST_QUOTES[Math.floor(Math.random() * ANARCHIST_QUOTES.length)];
    const message = {
      id: Date.now(),
      text: `"${quote}"`,
      sender: 'clippy',
      timestamp: new Date()
    };
    setConversation(prev => [...prev, message]);
    speak(quote.split(' - ')[0]);
  };

  // Removed the floating button since we're using the sidebar button

  return (
    <div className="fixed bottom-6 right-6 w-96 bg-gradient-to-br from-purple-900 to-black rounded-xl shadow-2xl flex flex-col overflow-hidden border border-purple-600 z-50">
      <div 
        className="bg-gradient-to-r from-purple-600 to-purple-800 text-white p-3 flex items-center justify-between"
      >
        <div className="flex items-center">
          <Zap size={20} className="mr-2" />
          <span className="font-bold">Anarchist Clippy</span>
        </div>
        <div className="flex space-x-2">
          <button 
            onClick={showRandomTip}
            className="p-1 hover:bg-purple-700 rounded-full transition-colors"
            title="Random Tip"
          >
            <Shield size={16} className="text-yellow-300" />
          </button>
          <button 
            onClick={showRandomQuote}
            className="p-1 hover:bg-purple-700 rounded-full transition-colors"
            title="Anarchist Quote"
          >
            <AlertTriangle size={16} className="text-yellow-300" />
          </button>
          <button 
            onClick={onClose}
            className="p-1 hover:bg-purple-700 rounded-full transition-colors"
            title="Close Clippy"
          >
            <X size={18} className="text-purple-200" />
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto max-h-80 p-4 space-y-4 bg-gray-800">
        {conversation.map((msg) => (
          <div
            key={msg.id}
            className={`flex ${msg.sender === 'user' ? 'justify-end' : 'justify-start'}`}
          >
            <div
              className={`max-w-[90%] rounded-lg px-3 py-2 text-sm ${
                msg.sender === 'user'
                  ? 'bg-purple-600 text-white'
                  : 'bg-gray-800 text-purple-200'
              }`}
            >
              {msg.text}
              <div className="text-xs opacity-70 mt-1">
                {new Date(msg.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
              </div>
            </div>
          </div>
        ))}
      </div>

      {showTip && (
        <div className="bg-yellow-900 bg-opacity-80 text-yellow-100 p-2 text-xs border-t border-yellow-800">
          <div className="flex items-start">
            <Key size={14} className="flex-shrink-0 mt-0.5 mr-1 text-yellow-300" />
            <span>{currentTip}</span>
          </div>
        </div>
      )}

      <div className="p-3 border-t border-gray-700 bg-gray-900">
        <div className="flex items-center space-x-2">
          <button
            onClick={toggleListening}
            className={`p-2 rounded-lg transition-colors ${
              isListening 
                ? 'bg-yellow-600 text-white' 
                : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
            }`}
            title={isListening ? 'Stop listening' : 'Voice input'}
          >
            {isListening ? <MicOff size={16} /> : <Mic size={16} />}
          </button>
          
          <input
            type="text"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
            placeholder="Type to the revolution..."
            className="flex-1 bg-gray-800 text-white text-sm rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-purple-500"
          />
          
          <button
            onClick={handleSendMessage}
            disabled={!message.trim()}
            className="p-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg disabled:opacity-50 transition-colors"
            title="Send message"
          >
            <Send size={16} />
          </button>
        </div>
      </div>
    </div>
  );
}
