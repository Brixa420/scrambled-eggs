"""
LLM Chat Service for integrating local LLM with chat functionality.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, AsyncGenerator, Awaitable, Callable, Dict, Optional, Union

from app.services.llm_service import LLMService

logger = logging.getLogger(__name__)


class LLMChatService:
    """
    Service to handle LLM integration with chat functionality.
    Provides methods for generating responses, managing conversation context,
    and handling LLM-related chat features.
    """

    def __init__(self, llm_service: Optional[LLMService] = None):
        """
        Initialize the LLM Chat Service.

        Args:
            llm_service: Optional pre-initialized LLMService instance
        """
        self.llm = llm_service or LLMService()
        self.conversations: Dict[str, Dict] = {}
        self.system_prompt = """
        You are a helpful AI assistant. Your responses should be concise, 
        informative, and helpful. You can use markdown formatting when appropriate.
        """

    async def initialize(self) -> bool:
        """
        Initialize the service and test the LLM connection.

        Returns:
            bool: True if initialization was successful, False otherwise
        """
        if not self._initialized:
            try:
                self._initialized = await self.llm._test_connection()
            except ConnectionError:
                logger.error("Failed to connect to LLM service")
                return False
            logger.info("LLM Chat Service initialized successfully")
        return self._initialized

    async def close(self):
        """Clean up resources."""
        if hasattr(self.llm, "close"):
            await self.llm.close()
            logger.info("LLM service closed")

    def create_conversation(
        self, conversation_id: str, system_prompt: Optional[str] = None
    ) -> Dict:
        """
        Create a new conversation context.

        Args:
            conversation_id: Unique identifier for the conversation
            system_prompt: Optional custom system prompt

        Returns:
            The created conversation context
        """
        self.conversations[conversation_id] = {
            "messages": [],
            "system_prompt": system_prompt or self.system_prompt,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
        }
        return self.conversations[conversation_id]

    async def generate_response(
        self,
        conversation_id: str,
        user_input: str,
        max_tokens: int = 500,
        temperature: float = 0.7,
        stream: bool = False,
        **kwargs,
    ) -> Union[Dict[str, Any], AsyncGenerator[Dict[str, Any], None]]:
        """
        Generate a response to the user's input.

        Args:
            conversation_id: ID of the conversation
            user_input: User's input message
            max_tokens: Maximum number of tokens in the response
            temperature: Sampling temperature (0.0 to 1.0)
            stream: Whether to stream the response
            **kwargs: Additional parameters for the LLM

        Returns:
            If stream=True: Async generator yielding response chunks
            If stream=False: Dictionary containing the full response and metadata
        """
        if conversation_id not in self.conversations:
            self.create_conversation(conversation_id)

        conversation = self.conversations[conversation_id]

        # Add user message to conversation history
        user_message = {
            "role": "user",
            "content": user_input,
            "timestamp": datetime.utcnow().isoformat(),
        }
        conversation["messages"].append(user_message)

        try:
            # Prepare the prompt with conversation history
            messages = [{"role": "system", "content": conversation["system_prompt"]}]
            messages.extend(conversation["messages"][-10:])  # Last 10 messages for context

            # Format messages for the LLM
            prompt = "\n".join(f"{m['role']}: {m['content']}" for m in messages)

            if stream:
                # Return an async generator for streaming responses
                return self._stream_response(
                    conversation_id=conversation_id,
                    prompt=prompt,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    **kwargs,
                )
            else:
                # Generate response using the LLM service (non-streaming)
                response = await self.llm.generate_response(
                    prompt=prompt,
                    system_prompt=conversation["system_prompt"],
                    max_tokens=max_tokens,
                    temperature=temperature,
                    stream=False,
                    **kwargs,
                )

                # Add assistant's response to conversation history
                assistant_message = {
                    "role": "assistant",
                    "content": response,
                    "timestamp": datetime.utcnow().isoformat(),
                }
                conversation["messages"].append(assistant_message)
                conversation["updated_at"] = datetime.utcnow().isoformat()

                return {
                    "success": True,
                    "response": response,
                    "conversation_id": conversation_id,
                    "message_id": f"msg_{len(conversation['messages'])}",
                }

        except Exception as e:
            logger.error(f"Error generating LLM response: {str(e)}")
            if stream:

                async def error_generator():
                    yield {
                        "chunk": "An error occurred while generating the response.",
                        "done": True,
                        "error": str(e),
                        "conversation_id": conversation_id,
                    }

                return error_generator()
            else:
                return {"success": False, "error": str(e), "conversation_id": conversation_id}

    async def _stream_response(
        self, conversation_id: str, prompt: str, **kwargs
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Stream the LLM response and update conversation history."""
        conversation = self.conversations[conversation_id]
        full_response = ""

        try:
            # Stream the response from the LLM
            async for chunk in self.llm.generate_response(
                prompt=prompt, system_prompt=conversation["system_prompt"], stream=True, **kwargs
            ):
                if chunk.get("done"):
                    # Final chunk with metadata
                    if not chunk.get("error"):
                        # Add the complete response to conversation history
                        assistant_message = {
                            "role": "assistant",
                            "content": full_response,
                            "timestamp": datetime.utcnow().isoformat(),
                        }
                        conversation["messages"].append(assistant_message)
                        conversation["updated_at"] = datetime.utcnow().isoformat()

                        yield {
                            "chunk": "",
                            "done": True,
                            "conversation_id": conversation_id,
                            "message_id": f"msg_{len(conversation['messages'])}",
                            "metadata": chunk.get("metadata", {}),
                        }
                    else:
                        yield {
                            "chunk": "",
                            "done": True,
                            "error": chunk.get("error", "Unknown error"),
                            "conversation_id": conversation_id,
                        }
                    break

                # Yield the response chunk
                chunk_text = chunk.get("chunk", "")
                if chunk_text:
                    full_response += chunk_text
                    yield {"chunk": chunk_text, "done": False, "conversation_id": conversation_id}

        except Exception as e:
            logger.error(f"Error in response streaming: {str(e)}")
            yield {"chunk": "", "done": True, "error": str(e), "conversation_id": conversation_id}

    async def process_chat_message(
        self, message: Dict[str, Any], on_response: Callable[[Dict], Awaitable[None]]
    ) -> None:
        """
        Process an incoming chat message and generate a response.

        Args:
            message: The incoming message dictionary
            on_response: Async callback function to handle the response
        """
        conversation_id = message.get("conversation_id", "default")
        user_input = message.get("content", "")
        stream = message.get("stream", False)

        if not user_input.strip():
            await on_response(
                {
                    "success": False,
                    "error": "Empty message content",
                    "conversation_id": conversation_id,
                    "type": "error",
                }
            )
            return

        try:
            if stream:
                # Handle streaming response
                response_generator = await self.generate_response(
                    conversation_id=conversation_id,
                    user_input=user_input,
                    max_tokens=500,
                    temperature=0.7,
                    stream=True,
                )

                # Send chunks as they arrive
                async for chunk in response_generator:
                    chunk["type"] = "assistant_chunk" if not chunk.get("done") else "assistant_done"
                    await on_response(chunk)
            else:
                # Handle non-streaming response
                result = await self.generate_response(
                    conversation_id=conversation_id,
                    user_input=user_input,
                    max_tokens=500,
                    temperature=0.7,
                    stream=False,
                )

                # Format the response
                response = {
                    "type": "assistant_message",
                    "conversation_id": conversation_id,
                    "content": result.get("response", "I'm sorry, I couldn't generate a response."),
                    "message_id": result.get("message_id"),
                    "timestamp": datetime.utcnow().isoformat(),
                }

                # Send the response via the callback
                await on_response(
                    {"success": True, "response": response, "type": "assistant_message"}
                )

        except Exception as e:
            logger.error(f"Error processing chat message: {str(e)}")
            error_response = {
                "success": False,
                "error": str(e),
                "conversation_id": conversation_id,
                "type": "error",
            }

            if stream:
                error_response.update(
                    {"chunk": "An error occurred while generating the response.", "done": True}
                )

            await on_response(error_response)


# Singleton instance
llm_chat_service = LLMChatService()


async def example_usage():
    """
    Example of how to use the LLMChatService with both streaming and non-streaming responses.

    This function demonstrates:
    1. Initializing the LLM service
    2. Creating a conversation
    3. Sending a non-streaming message
    4. Sending a streaming message
    5. Viewing conversation history
    """
    # Configure logging to show all levels
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler("llm_chat_example.log")],
    )

    logger.info("=" * 80)
    logger.info("STARTING LLM CHAT SERVICE EXAMPLE")
    logger.info("=" * 80)

    service = LLMChatService()

    try:
        # Initialize the service
        logger.info("\n[1/5] Initializing LLM service...")
        try:
            init_result = await service.initialize()
            if not init_result:
                logger.error(
                    "❌ Failed to initialize LLM service. Please check if the LLM server is running."
                )
                logger.info("💡 Make sure Ollama is installed and running with: ollama serve")
                return
            logger.info("✅ LLM service initialized successfully")
        except Exception as e:
            logger.error(f"❌ Error initializing LLM service: {str(e)}", exc_info=True)
            return

        # Create a new conversation
        conversation_id = "test_convo_1"
        service.create_conversation(conversation_id)
        logger.info(f"Created conversation: {conversation_id}")

        # Test non-streaming response
        print("\n=== Testing non-streaming response ===")
        response = await service.generate_response(
            conversation_id=conversation_id, user_input="Hello, how are you?", stream=False
        )
        if isinstance(response, dict):
            print(f"Response: {response.get('response', 'No response')}")
        else:
            print(f"Unexpected response format: {response}")

        # Test streaming response
        print("\n=== Testing streaming response ===")
        print("Response (streaming): ", end="", flush=True)

        try:
            response_gen = await service.generate_response(
                conversation_id=conversation_id,
                user_input="Tell me about artificial intelligence",
                stream=True,
            )

            if isinstance(response_gen, dict):
                # Handle non-streaming response (error case)
                print(f"\nError: {response_gen.get('error', 'Unknown error')}")
            else:
                # Handle streaming response
                full_response = ""
                async for chunk in response_gen:
                    if chunk.get("chunk"):
                        print(chunk["chunk"], end="", flush=True)
                        full_response += chunk["chunk"]
                    if chunk.get("done"):
                        if "error" in chunk:
                            print(f"\nError: {chunk['error']}")
                        else:
                            print("\n\nResponse complete!")

                # Show the full response at the end
                print("\n\nFull response:")
                print(full_response)
        except Exception as e:
            logger.error(f"Error during streaming: {e}")

        # Test conversation history
        print("\n=== Testing conversation history ===")
        history_response = await service.generate_response(
            conversation_id=conversation_id,
            user_input="What was the last thing I asked about?",
            stream=False,
        )

        if isinstance(history_response, dict):
            print(f"Response: {history_response.get('response', 'No response')}")

        # Show conversation history
        print("\n=== Conversation history ===")
        if conversation_id in service.conversations:
            for msg in service.conversations[conversation_id].get("messages", []):
                role = msg.get("role", "unknown").capitalize()
                content = msg.get("content", "")
                print(f"{role}: {content}")

    except Exception as e:
        logger.error(f"Error in example usage: {e}", exc_info=True)
    finally:
        # Clean up resources
        logger.info("Cleaning up resources...")
        await service.close()
        logger.info("Example completed")


if __name__ == "__main__":
    import asyncio
    import logging

    # Configure logging
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Create a new event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        # Run the example
        loop.run_until_complete(example_usage())
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        # Clean up the event loop
        loop.close()
