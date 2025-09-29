"""
Call Manager

Handles call-related operations including making, receiving, and managing calls.
"""

import logging
from typing import Any, Callable, Dict

logger = logging.getLogger(__name__)


class CallManager:
    """Manages call operations for the application."""

    def __init__(self):
        """Initialize the CallManager."""
        self.active_calls: Dict[str, Dict[str, Any]] = {}
        self.call_handlers: Dict[str, Callable] = {}
        logger.info("CallManager initialized")

    def make_call(self, recipient_id: str, call_type: str = "audio", **kwargs) -> bool:
        """
        Initiate a call to a recipient.

        Args:
            recipient_id: ID of the recipient
            call_type: Type of call (audio/video)
            **kwargs: Additional call parameters

        Returns:
            bool: True if call was initiated successfully, False otherwise
        """
        try:
            call_id = f"call_{len(self.active_calls) + 1}"
            self.active_calls[call_id] = {
                "recipient_id": recipient_id,
                "call_type": call_type,
                "status": "initiating",
                "start_time": None,
                **kwargs,
            }
            logger.info(f"Initiating {call_type} call to {recipient_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to initiate call: {e}")
            return False

    def answer_call(self, call_id: str) -> bool:
        """
        Answer an incoming call.

        Args:
            call_id: ID of the call to answer

        Returns:
            bool: True if call was answered successfully, False otherwise
        """
        if call_id in self.active_calls:
            self.active_calls[call_id]["status"] = "active"
            self.active_calls[call_id]["start_time"] = self._get_current_timestamp()
            logger.info(f"Call {call_id} answered")
            return True
        return False

    def end_call(self, call_id: str) -> bool:
        """
        End an active call.

        Args:
            call_id: ID of the call to end

        Returns:
            bool: True if call was ended successfully, False otherwise
        """
        if call_id in self.active_calls:
            self.active_calls[call_id]["status"] = "ended"
            self.active_calls[call_id]["end_time"] = self._get_current_timestamp()
            logger.info(f"Call {call_id} ended")
            return True
        return False

    def register_call_handler(self, call_type: str, handler: Callable) -> None:
        """
        Register a handler for a specific call type.

        Args:
            call_type: Type of call (audio/video)
            handler: Function to handle the call
        """
        self.call_handlers[call_type] = handler
        logger.info(f"Registered handler for {call_type} calls")

    def get_active_calls(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all active calls.

        Returns:
            Dictionary of active calls
        """
        return {
            k: v
            for k, v in self.active_calls.items()
            if v.get("status") in ["initiating", "active"]
        }

    def _get_current_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime

        return datetime.now().isoformat()
