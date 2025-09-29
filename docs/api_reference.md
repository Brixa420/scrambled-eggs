# LLM Integration API Reference

## LLMChatService

### Initialization

```python
from app.services import llm_chat_service

# Initialize the service
await llm_chat_service.initialize()
```

### Methods

#### `create_conversation(conversation_id: str, system_prompt: Optional[str] = None) -> Dict`
Creates a new conversation context.

**Parameters:**
- `conversation_id`: Unique identifier for the conversation
- `system_prompt`: Optional custom system prompt for the conversation

**Returns:**
```python
{
    "messages": [],
    "system_prompt": "Your custom prompt",
    "created_at": "2023-01-01T12:00:00.000000",
    "updated_at": "2023-01-01T12:00:00.000000"
}
```

#### `generate_response(conversation_id: str, user_input: str, max_tokens: int = 500, temperature: float = 0.7, **kwargs) -> Dict`
Generates a response to the user's input.

**Parameters:**
- `conversation_id`: ID of the conversation
- `user_input`: User's message
- `max_tokens`: Maximum length of the response
- `temperature`: Controls randomness (0.0 to 1.0)
- `**kwargs`: Additional LLM parameters

**Returns:**
```python
{
    "success": bool,
    "response": str,  # Generated response
    "conversation_id": str,
    "message_id": str
}
```

#### `process_chat_message(message: Dict, on_response: Callable) -> None`
Processes an incoming chat message asynchronously.

**Parameters:**
- `message`: Dictionary containing:
  ```python
  {
      "conversation_id": str,
      "content": str,
      "metadata": Dict  # Optional additional data
  }
  ```
- `on_response`: Async callback function that receives the response

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Base URL for Ollama API |
| `LLM_MODEL` | `llama3` | Model to use for generation |
| `LLM_TIMEOUT` | `30` | Request timeout in seconds |
| `LLM_MAX_RETRIES` | `3` | Maximum retry attempts |
| `LLM_RATE_LIMIT` | `10` | Requests per minute |

## Error Handling

All methods return responses with a `success` flag. Check this flag before processing the response.

**Error Response Example:**
```python
{
    "success": False,
    "error": "Error message",
    "conversation_id": "convo_123"
}
```

## WebSocket Events

### Incoming Events

#### `llm_request`
Request an LLM response.

**Payload:**
```typescript
{
  conversation_id: string;
  message: string;
  metadata?: Record<string, any>;
}
```

### Outgoing Events

#### `llm_response`
Contains the generated response.

**Payload:**
```typescript
{
  success: boolean;
  conversation_id: string;
  response?: string;
  error?: string;
  message_id?: string;
}
```

#### `llm_error`
Error during processing.

**Payload:**
```typescript
{
  error: string;
  conversation_id: string;
  timestamp: string;
}
```
