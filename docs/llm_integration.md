# Local LLM Integration

This document explains how to use the Local LLM Integration in the Scrambled Eggs application.

## Prerequisites

1. Install Ollama from [ollama.ai](https://ollama.ai/)
2. Pull a model (e.g., `llama3`):
   ```bash
   ollama pull llama3
   ```
3. Start the Ollama server:
   ```bash
   ollama serve
   ```

## Quick Start

1. Run the example script:
   ```bash
   python examples/llm_chat_example.py
   ```

## Integration with Chat

### Initialization

```python
from app.services.llm_chat_service import llm_chat_service

# Initialize the service
await llm_chat_service.initialize()
```

### Creating a Conversation

```python
# Create a new conversation with a custom system prompt
conversation_id = "user_123"
system_prompt = "You are a helpful assistant."
llm_chat_service.create_conversation(conversation_id, system_prompt)
```

### Processing Messages

```python
async def handle_response(response):
    if response["success"]:
        print("Assistant:", response["response"]["content"])
    else:
        print("Error:", response.get("error"))

# Process a user message
await llm_chat_service.process_chat_message(
    {
        "conversation_id": conversation_id,
        "content": "Hello, how are you?",
        "metadata": {
            "user_id": "user_123",
            "timestamp": "2023-01-01T12:00:00Z"
        }
    },
    handle_response
)
```

## Configuration

Set these environment variables to configure the LLM service:

- `OLLAMA_BASE_URL`: Base URL for the Ollama API (default: `http://localhost:11434`)
- `LLM_MODEL`: Model to use (default: `llama3`)
- `LLM_TIMEOUT`: Request timeout in seconds (default: `30`)
- `LLM_MAX_RETRIES`: Maximum number of retry attempts (default: `3`)
- `LLM_RATE_LIMIT`: Maximum requests per minute (default: `10`)

## Best Practices

1. **Error Handling**: Always check the `success` flag in the response.
2. **Conversation Management**: Reuse conversation IDs for continuous context.
3. **Rate Limiting**: Respect the rate limits to avoid overwhelming the LLM server.
4. **Prompt Engineering**: Craft clear and specific system prompts for better responses.

## Troubleshooting

- **Connection Issues**: Ensure the Ollama server is running and accessible.
- **Model Not Found**: Verify the model name is correct and the model is downloaded.
- **Timeouts**: Increase the `LLM_TIMEOUT` if requests are timing out.
- **Rate Limiting**: If you hit rate limits, reduce the request frequency or increase `LLM_RATE_LIMIT`.
