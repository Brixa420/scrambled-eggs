"""
Video Platform API Module

Provides a high-level interface for video streaming and storage operations.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Callable, Awaitable

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .stream import StreamQuality
from .storage import VideoStorage, VideoMetadata
from .manager import StreamManager, StreamInfo
from ..network.p2p import P2PNetwork

logger = logging.getLogger(__name__)

# Pydantic models for request/response validation
class CreateStreamRequest(BaseModel):
    title: str
    description: str = ""
    metadata: Dict[str, Any] = {}

class StreamResponse(BaseModel):
    stream_id: str
    title: str
    description: str
    is_live: bool
    viewers: int
    quality: str
    created_at: float
    metadata: Dict[str, Any]

class VideoUploadResponse(BaseModel):
    video_id: str
    title: str
    size: int
    duration: float
    created_at: float

class VideoPlatformAPI:
    """Main API class for the video platform."""
    
    def __init__(self, p2p_network: P2PNetwork):
        self.p2p_network = p2p_network
        self.stream_manager = StreamManager(p2p_network)
        self.video_storage = VideoStorage(p2p_network)
        self.app = self._create_fastapi_app()
    
    async def initialize(self) -> None:
        """Initialize the video platform."""
        await self.video_storage.initialize()
        logger.info("Video Platform API initialized")
    
    async def close(self) -> None:
        """Clean up resources."""
        await self.stream_manager.close()
        await self.video_storage.close()
        logger.info("Video Platform API shut down")
    
    def _create_fastapi_app(self) -> FastAPI:
        """Create and configure the FastAPI application."""
        app = FastAPI(
            title="Scrambled Eggs Video Platform API",
            description="Decentralized video streaming and storage platform",
            version="0.1.0"
        )
        
        # Add startup and shutdown event handlers
        @app.on_event("startup")
        async def startup():
            await self.initialize()
        
        @app.on_event("shutdown")
        async def shutdown():
            await self.close()
        
        # API endpoints
        @app.get("/api/v1/streams", response_model=List[StreamResponse])
        async def list_streams() -> List[StreamResponse]:
            """List all available streams."""
            streams = await self.stream_manager.list_streams()
            return [
                StreamResponse(
                    stream_id=stream.stream_id,
                    title=stream.title,
                    description=stream.description,
                    is_live=stream.is_live,
                    viewers=len(stream.viewers),
                    quality=StreamQuality.MEDIUM.value,  # Default quality
                    created_at=stream.created_at,
                    metadata=stream.metadata
                )
                for stream in streams
            ]
        
        @app.post("/api/v1/streams", response_model=StreamResponse)
        async def create_stream(request: CreateStreamRequest) -> StreamResponse:
            """Create a new video stream."""
            stream_id = await self.stream_manager.create_stream(
                stream_id=f"stream_{int(time.time())}",
                title=request.title,
                description=request.description,
                owner="self",  # In a real app, this would be the authenticated user
                metadata=request.metadata
            )
            
            # Get the created stream info
            stream_info = await self.stream_manager.get_stream_info(stream_id)
            if not stream_info:
                raise HTTPException(status_code=500, detail="Failed to create stream")
            
            return StreamResponse(
                stream_id=stream_info.stream_id,
                title=stream_info.title,
                description=stream_info.description,
                is_live=stream_info.is_live,
                viewers=len(stream_info.viewers),
                quality=StreamQuality.MEDIUM.value,
                created_at=stream_info.created_at,
                metadata=stream_info.metadata
            )
        
        @app.websocket("/ws/stream/{stream_id}")
        async def websocket_stream(websocket: WebSocket, stream_id: str):
            """WebSocket endpoint for video streaming."""
            await websocket.accept()
            peer_id = str(id(websocket))
            
            try:
                # Handle WebRTC signaling
                while True:
                    data = await websocket.receive_json()
                    message_type = data.get("type")
                    
                    if message_type == "offer":
                        # Handle WebRTC offer from client
                        await self.stream_manager._handle_stream_offer(peer_id, {
                            "stream_id": stream_id,
                            "sdp": data["sdp"],
                            "type": "offer"
                        })
                    elif message_type == "answer":
                        # Handle WebRTC answer from client
                        await self.stream_manager._handle_stream_answer(peer_id, {
                            "stream_id": stream_id,
                            "sdp": data["sdp"],
                            "type": "answer"
                        })
                    elif message_type == "ice-candidate":
                        # Handle ICE candidate
                        await self.stream_manager._handle_ice_candidate(peer_id, {
                            "stream_id": stream_id,
                            "candidate": data["candidate"],
                            "sdpMid": data.get("sdpMid"),
                            "sdpMLineIndex": data.get("sdpMLineIndex")
                        })
                    elif message_type == "quality-change":
                        # Handle quality change request
                        await self.stream_manager._handle_quality_change(peer_id, {
                            "stream_id": stream_id,
                            "quality": data["quality"]
                        })
                    
            except WebSocketDisconnect:
                # Clean up on disconnect
                await self.stream_manager.remove_viewer(stream_id, peer_id)
                logger.info(f"Viewer {peer_id} disconnected from stream {stream_id}")
            except Exception as e:
                logger.error(f"WebSocket error: {e}")
                await websocket.close(code=1011)
        
        @app.post("/api/v1/videos/upload", response_model=VideoUploadResponse)
        async def upload_video(
            file: UploadFile,
            title: str,
            description: str = ""
        ) -> VideoUploadResponse:
            """Upload a video file for storage and later streaming."""
            try:
                # Save the uploaded file temporarily
                temp_path = f"/tmp/{file.filename}"
                with open(temp_path, "wb") as buffer:
                    content = await file.read()
                    buffer.write(content)
                
                # Store the video
                video_id = await self.video_storage.store_video(
                    file_path=temp_path,
                    title=title,
                    description=description,
                    owner="self"  # In a real app, this would be the authenticated user
                )
                
                # Get video metadata
                metadata = await self.video_storage.get_video_metadata(video_id)
                if not metadata:
                    raise HTTPException(status_code=500, detail="Failed to retrieve video metadata")
                
                # Clean up temp file
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
                
                return VideoUploadResponse(
                    video_id=video_id,
                    title=metadata.title,
                    size=metadata.size,
                    duration=metadata.duration,
                    created_at=metadata.created_at
                )
                
            except Exception as e:
                logger.error(f"Failed to upload video: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.get("/api/v1/videos/{video_id}/stream")
        async def stream_video(video_id: str):
            """Stream a video by its ID."""
            # In a real implementation, this would set up the appropriate
            # streaming response with proper content type and headers
            return {"message": f"Streaming video {video_id}"}
        
        return app

# Helper function to create and run the API server
async def run_api_server(host: str = "0.0.0.0", port: int = 8000):
    """Run the video platform API server."""
    # In a real application, you would initialize the P2P network properly
    p2p_network = P2PNetwork()
    
    # Create and initialize the API
    api = VideoPlatformAPI(p2p_network)
    await api.initialize()
    
    # Run the FastAPI app with uvicorn
    import uvicorn
    config = uvicorn.Config(
        api.app,
        host=host,
        port=port,
        log_level="info"
    )
    server = uvicorn.Server(config)
    
    try:
        await server.serve()
    finally:
        await api.close()

if __name__ == "__main__":
    import asyncio
    asyncio.run(run_api_server())
