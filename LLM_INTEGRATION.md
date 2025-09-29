# LLM Integration Guide

This document provides an overview of the LLM (Large Language Model) integration in the chat application, including setup, configuration, and usage.

## Features

- **Real-time Chat**: WebSocket-based real-time messaging
- **LLM Integration**: Seamless integration with Llama 3 model via Ollama
- **Error Handling**: Comprehensive error handling and user feedback
- **Loading States**: Visual indicators for message sending and LLM processing
- **Typing Indicators**: Shows when other users are typing
- **Message Status**: Tracks message delivery status (sending, delivered, error)
- **Rate Limiting**: Prevents API abuse
- **Response Caching**: Improves performance by caching LLM responses

## Prerequisites

1. Install [Ollama](https://ollama.ai/) and pull the Llama 3 model:
   ```bash
   ollama pull llama3
   ```

2. Start the Ollama server:
   ```bash
   ollama serve
   ```

## Configuration

### Backend (Flask)

Environment variables for the backend (in `.env`):

```env
# LLM Service Configuration
OLLAMA_BASE_URL=http://localhost:11434
LLM_MODEL=llama3
LLM_TIMEOUT=30  # seconds
LLM_MAX_RETRIES=3
LLM_RATE_LIMIT=10  # requests per minute

# Database
DATABASE_URL=sqlite:///chat.db

# Flask
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key
```

### Frontend (React)

Copy the example environment file and update as needed:

```bash
cp frontend/.env.example frontend/.env
```

## API Endpoints

### WebSocket Events

- `connect`: Establishes WebSocket connection
- `disconnect`: Handles client disconnection
- `join_room`: Joins a chat room
- `leave_room`: Leaves a chat room
- `send_message`: Sends a new message
- `typing`: Indicates when a user is typing

### HTTP Endpoints

- `GET /api/chat/history`: Get chat history
- `POST /api/chat/message`: Send a new message
- `GET /api/llm/models`: List available LLM models
- `POST /api/llm/generate`: Generate a response using LLM

## Error Handling

The application provides detailed error messages for common issues:

- **Connection Errors**: When unable to connect to the WebSocket server
- **Rate Limiting**: When too many requests are made
- **LLM Errors**: When the LLM service is unavailable or returns an error
- **Authentication**: When user is not authenticated

## Performance Optimization

- **Response Caching**: LLM responses are cached to improve performance
- **Rate Limiting**: Prevents API abuse and ensures fair usage
- **Background Processing**: LLM responses are generated in background tasks
- **Efficient Updates**: Only necessary UI components are re-rendered

## Monitoring and Logging

Logs are written to the console with different log levels:

- `INFO`: General application events
- `WARNING`: Non-critical issues
- `ERROR`: Critical errors that need attention

## Testing

To test the LLM integration:

1. Start the backend server:
   ```bash
   python app.py
   ```

2. Start the frontend development server:
   ```bash
   cd frontend
   npm start
   ```

3. Open the application in your browser and test the chat functionality.

## Troubleshooting

### LLM Service Not Responding

1. Ensure Ollama is running:
   ```bash
   ollama serve
   ```

2. Verify the model is downloaded:
   ```bash
   ollama list
   ```

3. Check the Ollama logs for errors.

### WebSocket Connection Issues

1. Verify the WebSocket URL is correct in the frontend configuration.
2. Check for CORS issues in the browser console.
3. Ensure the backend server is running and accessible.

## Security Considerations

- All sensitive configuration is stored in environment variables
- WebSocket connections are secured with CORS and authentication
- Rate limiting prevents abuse of the LLM service
- User input is properly sanitized before processing

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
