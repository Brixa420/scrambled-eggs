#!/usr/bin/env python3
"""
Run the WebRTC signaling server.

Usage:
    python run_signaling_server.py [--host HOST] [--port PORT] [--no-auth]

Example:
    python run_signaling_server.py --host 0.0.0.0 --port 8080
"""
import argparse
import asyncio
import logging

from app.webrtc.signaling_server import WebRTCSignalingServer

# Set up logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)


async def main():
    parser = argparse.ArgumentParser(description="Run WebRTC signaling server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on")
    parser.add_argument("--no-auth", action="store_true", help="Disable authentication")

    args = parser.parse_args()

    # Create and start the server
    server = WebRTCSignalingServer(host=args.host, port=args.port, auth_required=not args.no_auth)

    print(f"Starting WebRTC signaling server on {args.host}:{args.port}")
    print(f"Authentication {'enabled' if not args.no_auth else 'disabled'}")
    print("Press Ctrl+C to stop")

    try:
        await server.start()
    except KeyboardInterrupt:
        print("\nShutting down gracefully...")
    except Exception as e:
        logging.error(f"Server error: {e}", exc_info=True)
    finally:
        await server.stop()


if __name__ == "__main__":
    asyncio.run(main())
