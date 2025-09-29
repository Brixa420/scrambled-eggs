# LLM Integration User Guide

## Getting Started

### Prerequisites
- Python 3.8+
- Ollama installed and running
- Required Python packages (install with `pip install -r requirements.txt`)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/scrambled-eggs.git
   cd scrambled-eggs
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Start the Ollama server (if not already running):
   ```bash
   ollama serve
   ```

## Basic Usage

### Initializing the Service

```python
from app.services import llm_chat_service
import asyncio

async def main():
    await llm_chat_service.initialize()
    
    # Your code here

asyncio.run(main())
```

### Creating a Chat Interface

Here's a simple command-line chat interface:

```python
# simple_chat.py
import asyncio
from app.services import llm_chat_service

async def chat():
    await llm_chat_service.initialize()
    
    conversation_id = "my_chat"
    llm_chat_service.create_conversation(
        conversation_id,
        "You are a helpful assistant."
    )
    
    print("Chat started! Type 'exit' to quit.")
    
    while True:
        user_input = input("\nYou: ")
        if user_input.lower() in ('exit', 'quit'):
            break
            
        response = await llm_chat_service.generate_response(
            conversation_id,
            user_input
        )
        
        if response["success"]:
            print(f"\nAssistant: {response['response']}")
        else:
            print(f"\nError: {response.get('error', 'Unknown error')}")

if __name__ == "__main__":
    asyncio.run(chat())
```

## Advanced Features

### Customizing the Model

You can change the model by setting the `LLM_MODEL` environment variable:

```bash
export LLM_MODEL=llama2  # or any other model you have installed
python your_script.py
```

### Adjusting Generation Parameters

```python
response = await llm_chat_service.generate_response(
    conversation_id="my_chat",
    user_input="Tell me a story",
    max_tokens=1000,     # Longer response
    temperature=0.8,     # More creative
    top_p=0.9,          # Nucleus sampling
    frequency_penalty=0.5  # Reduce repetition
)
```

### Handling Multiple Conversations

```python
# Create separate conversations
llm_chat_service.create_conversation("work_chat", "You are a professional assistant.")
llm_chat_service.create_conversation("casual_chat", "You are a friendly companion.")

# Switch between conversations
work_response = await llm_chat_service.generate_response("work_chat", "Draft an email...")
casual_response = await llm_chat_service.generate_response("casual_chat", "Tell me a joke")
```

## Best Practices

1. **Conversation Management**
   - Reuse conversation IDs for continuous context
   - Clear old conversations when no longer needed
   - Monitor conversation length to manage memory usage

2. **Error Handling**
   ```python
   try:
       response = await llm_chat_service.generate_response(conversation_id, user_input)
       if not response["success"]:
           print(f"Error: {response.get('error')}")
   except Exception as e:
       print(f"Unexpected error: {str(e)}")
   ```

3. **Performance**
   - Use streaming for long responses
   - Implement client-side caching when appropriate
   - Consider batching multiple requests when possible

## Troubleshooting

### Common Issues

1. **Connection Refused**
   - Ensure Ollama server is running
   - Check `OLLAMA_BASE_URL` is correct

2. **Model Not Found**
   - Verify the model name is correct
   - Pull the model: `ollama pull <model_name>`

3. **Slow Responses**
   - Reduce `max_tokens`
   - Check server load
   - Consider a more powerful machine for the LLM server

### Getting Help

If you encounter issues:
1. Check the logs for error messages
2. Verify your Ollama installation
3. Consult the [API Reference](./api_reference.md)
4. Open an issue on GitHub
