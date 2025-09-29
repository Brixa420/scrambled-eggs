"""
Example script demonstrating the LLM Chat Service.

This script shows how to use the LLMChatService to have a conversation with the local LLM.
"""

import asyncio
import logging

from app.services.llm_chat_service import LLMChatService, llm_chat_service

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


async def main():
    """Run the LLM chat example."""
    try:
        # Initialize the LLM Chat Service
        logger.info("Initializing LLM Chat Service...")
        await llm_chat_service.initialize()

        # Create a new conversation with a custom system prompt
        conversation_id = "example_chat"
        system_prompt = """
        You are a helpful AI assistant. Your name is ScrambledEggs Assistant.
        Be concise, friendly, and helpful in your responses.
        """
        llm_chat_service.create_conversation(conversation_id, system_prompt)
        logger.info(f"Created new conversation: {conversation_id}")

        # Define a callback function to handle responses
        async def handle_response(response):
            if response["success"]:
                assistant_message = response["response"]
                print(f"\n🤖 Assistant: {assistant_message['content']}")
            else:
                logger.error(f"Error: {response.get('error', 'Unknown error')}")

        # Interactive chat loop
        print("\n🔹 ScrambledEggs LLM Chat Example 🔹")
        print("Type your message and press Enter. Type 'exit' to quit.\n")

        while True:
            try:
                # Get user input
                user_input = input("\n👤 You: ").strip()

                # Check for exit command
                if user_input.lower() in ("exit", "quit", "bye"):
                    print("\n👋 Goodbye!")
                    break

                if not user_input:
                    continue

                # Process the message
                await llm_chat_service.process_chat_message(
                    {
                        "conversation_id": conversation_id,
                        "content": user_input,
                        "metadata": {
                            "user_id": "example_user",
                            "timestamp": "2023-01-01T12:00:00Z",
                        },
                    },
                    handle_response,
                )

            except KeyboardInterrupt:
                print("\n👋 Goodbye!")
                break
            except Exception as e:
                logger.error(f"An error occurred: {str(e)}")
                continue

    except Exception as e:
        logger.error(f"Failed to initialize LLM Chat Service: {str(e)}")
        return


if __name__ == "__main__":
    asyncio.run(main())
