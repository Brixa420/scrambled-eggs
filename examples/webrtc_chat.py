""
WebRTC Chat Example

This example demonstrates how to use the WebRTC peer manager and signaling server
to create a simple peer-to-peer chat application.

To run this example:
1. Start the signaling server in one terminal:
   $ python -m app.webrtc.signaling_server

2. Run multiple instances of this script in separate terminals with different peer IDs:
   $ python examples/webrtc_chat.py --peer-id alice --room-id myroom
   $ python examples/webrtc_chat.py --peer-id bob --room-id myroom

3. Type messages in any terminal and press Enter to send them to all connected peers.
"""
import asyncio
import json
import argparse
import logging
from typing import Dict, Set, Optional, Callable, Awaitable

from app.webrtc.peer_manager import WebRTCPeerManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('webrtc_chat')

class WebRTCChat:
    """Simple WebRTC chat application."""
    
    def __init__(self, peer_id: str, room_id: str):
        """Initialize the chat application."""
        self.peer_id = peer_id
        self.room_id = room_id
        self.peer_manager = WebRTCPeerManager(peer_id, room_id)
        
        # Set up event handlers
        self.peer_manager.on_peer_connected = self._on_peer_connected
        self.peer_manager.on_peer_disconnected = self._on_peer_disconnected
        self.peer_manager.on_data_channel_message = self._on_message
    
    async def start(self) -> None:
        """Start the chat application."""
        logger.info(f"Starting WebRTC chat as {self.peer_id} in room {self.room_id}")
        
        # Connect to the signaling server
        await self.peer_manager.connect()
        
        try:
            # Start the chat input loop
            await self._input_loop()
        except asyncio.CancelledError:
            pass
        finally:
            # Clean up
            await self.peer_manager.disconnect()
    
    async def _input_loop(self) -> None:
        """Handle user input and send messages to peers."""
        loop = asyncio.get_running_loop()
        
        while True:
            try:
                # Read input asynchronously
                message = await loop.run_in_executor(
                    None, 
                    input, 
                    f"[{self.peer_id}] > "
                )
                
                if not message.strip():
                    continue
                
                # Send the message to all peers
                await self._send_message(message.strip())
                
            except (EOFError, KeyboardInterrupt):
                logger.info("Shutting down...")
                break
            except Exception as e:
                logger.error(f"Error in input loop: {e}")
                await asyncio.sleep(1)
    
    async def _send_message(self, text: str) -> None:
        """Send a chat message to all connected peers."""
        message = {
            'type': 'chat',
            'from': self.peer_id,
            'text': text,
            'timestamp': asyncio.get_event_loop().time()
        }
        
        sent_count = await self.peer_manager.broadcast(message)
        logger.info(f"Sent message to {sent_count} peer(s)")
    
    async def _on_peer_connected(self, peer_id: str) -> None:
        """Handle when a peer connects."""
        logger.info(f"Peer connected: {peer_id}")
        
        # Send a welcome message to the new peer
        welcome = {
            'type': 'system',
            'text': f"{peer_id} has joined the chat",
            'timestamp': asyncio.get_event_loop().time()
        }
        
        # Send the welcome message to all peers except the new one
        await self.peer_manager.broadcast(
            welcome,
            exclude={peer_id}
        )
        
        # Send the new peer a welcome message
        await self.peer_manager.send_message(peer_id, {
            'type': 'system',
            'text': f"Welcome to the chat, {peer_id}!",
            'timestamp': asyncio.get_event_loop().time()
        })
    
    async def _on_peer_disconnected(self, peer_id: str) -> None:
        """Handle when a peer disconnects."""
        logger.info(f"Peer disconnected: {peer_id}")
        
        # Notify other peers about the disconnection
        message = {
            'type': 'system',
            'text': f"{peer_id} has left the chat",
            'timestamp': asyncio.get_event_loop().time()
        }
        
        await self.peer_manager.broadcast(message)
    
    async def _on_message(self, peer_id: str, message: dict) -> None:
        """Handle incoming messages from peers."""
        msg_type = message.get('type')
        
        if msg_type == 'chat':
            print(f"\n[{message.get('from')}] {message.get('text')}")
            print(f"[{self.peer_id}] > ", end='', flush=True)
        elif msg_type == 'system':
            print(f"\n[SYSTEM] {message.get('text')}")
            print(f"[{self.peer_id}] > ", end='', flush=True)

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='WebRTC Chat Example')
    parser.add_argument('--peer-id', required=True, help='Unique identifier for this peer')
    parser.add_argument('--room-id', default='default', help='Room ID to join')
    parser.add_argument('--signaling-url', default='ws://localhost:8080/ws', 
                       help='URL of the signaling server')
    return parser.parse_args()

async def main():
    """Main entry point."""
    args = parse_args()
    
    # Create and start the chat application
    chat = WebRTCChat(args.peer_id, args.room_id)
    
    try:
        await chat.start()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
    finally:
        # Ensure clean shutdown
        await chat.peer_manager.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
