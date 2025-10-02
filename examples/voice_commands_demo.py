"""
Voice Commands Demo for Clippy AI.

This script demonstrates how to use the voice command system with Clippy.
"""

import sys
import logging
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from brixa.ai.clippy.voice import (
    SpeechToText,
    TextToSpeech,
    command_registry,
    register_command,
    CommandType,
    process_voice_command
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize TTS and STT
tts = TextToSpeech()
stt = SpeechToText()

# Register some example commands
@register_command(
    ["hello clippy", "hi clippy", "hey clippy"],
    command_type=CommandType.ACTION,
    description="Greet Clippy"
)
def greet_clippy() -> str:
    """Respond to a greeting."""
    return "Hello! How can I help you today?"

@register_command(
    ["what can you do", "help", "list commands"],
    command_type=CommandType.QUERY,
    description="List available commands"
)
def list_commands() -> str:
    """List all available voice commands."""
    commands = command_registry.list_commands()
    if not commands:
        return "I don't have any commands registered yet."
    
    # Group commands by type
    by_type = {}
    for cmd in commands:
        if cmd['enabled']:
            by_type.setdefault(cmd['type'], []).append(cmd)
    
    response = ["Here's what I can do:"]
    for cmd_type, cmds in by_type.items():
        response.append(f"\n{cmd_type} Commands:")
        for cmd in cmds:
            patterns = ', '.join(f'"{p}"' for p in cmd['patterns'][:3])
            if len(cmd['patterns']) > 3:
                patterns += f" and {len(cmd['patterns']) - 3} more"
            response.append(f"- {cmd['description']} (e.g., {patterns})")
    
    return '\n'.join(response)

def process_audio(audio_data: bytes) -> bool:
    """Process audio data and execute any recognized commands."""
    try:
        # Convert speech to text
        text = stt.recognize_google(audio_data)
        if not text:
            return False
        
        print(f"\nRecognized: {text}")
        
        # Process the command
        result = process_voice_command(text)
        if result:
            if result.get('success', False):
                response = result.get('result', 'Command executed successfully')
                if result.get('requires_confirmation', False):
                    response = f"{response}. Is this correct?"
            else:
                response = f"Sorry, I couldn't process that command: {result.get('error', 'Unknown error')}"
            
            print(f"Response: {response}")
            tts.speak(response)
            return True
            
    except Exception as e:
        logger.error(f"Error processing audio: {e}", exc_info=True)
    
    return False

def main():
    """Run the voice command demo."""
    print("Voice Commands Demo for Clippy AI")
    print("================================")
    print("Listening for voice commands. Say 'list commands' for help or press Ctrl+C to exit.")
    
    try:
        # Start listening for voice commands
        print("\nListening...")
        stt.listen(
            on_utterance=process_audio,
            on_wake_word=lambda: print("Wake word detected!")
        )
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        stt.stop_listening()

if __name__ == "__main__":
    main()
