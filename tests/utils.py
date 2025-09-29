"""
Test utilities and helpers.
"""

import json
from datetime import datetime, timedelta
from functools import wraps

from flask import url_for


def json_response(response):
    """Get JSON data from response."""
    return json.loads(response.data.decode("utf-8"))


def auth_header(token):
    """Return authorization header with JWT token."""
    return {"Authorization": f"Bearer {token}"}


def iso_format(dt):
    """Convert datetime to ISO format string."""
    return dt.isoformat() + "Z" if dt else None


def assert_paginated_response(response, expected_count=None):
    """Assert that a response is a valid paginated response."""
    data = json_response(response)
    assert "items" in data
    assert "page" in data
    assert "per_page" in data
    assert "total" in data

    if expected_count is not None:
        assert len(data["items"]) == expected_count

    return data


def assert_error_response(response, status_code, error_code=None):
    """Assert that a response is an error response with the given status code."""
    assert response.status_code == status_code
    data = json_response(response)
    assert "error" in data
    if error_code:
        assert data["error"]["code"] == error_code
    return data


def assert_validation_error(response, field_name):
    """Assert that a response is a validation error for the given field."""
    data = assert_error_response(response, 400, "validation_error")
    assert field_name in data["error"]["fields"]
    return data


def assert_unauthorized(response):
    """Assert that a response is an unauthorized error."""
    return assert_error_response(response, 401, "unauthorized")


def assert_forbidden(response):
    """Assert that a response is a forbidden error."""
    return assert_error_response(response, 403, "forbidden")


def assert_not_found(response):
    """Assert that a response is a not found error."""
    return assert_error_response(response, 404, "not_found")


def assert_rate_limit_exceeded(response):
    """Assert that a response is a rate limit exceeded error."""
    return assert_error_response(response, 429, "rate_limit_exceeded")


def assert_message_response(response, message, status_code=200):
    """Assert that a response contains a message with the given status code."""
    assert response.status_code == status_code
    data = json_response(response)
    assert "message" in data
    assert data["message"] == message
    return data


def assert_message_equals(actual, expected):
    """Assert that two message objects are equal."""
    assert actual["id"] == expected.id
    assert actual["content"] == expected.content
    assert actual["sender_id"] == str(expected.sender_id)
    assert actual["recipient_id"] == str(expected.recipient_id)
    assert actual["status"] == expected.status.value
    assert actual["created_at"] == iso_format(expected.created_at)
    assert actual["updated_at"] == iso_format(expected.updated_at)
    assert actual["deleted"] == expected.deleted
    assert actual["encrypted"] == expected.encrypted
    if expected.expires_at:
        assert actual["expires_at"] == iso_format(expected.expires_at)
    else:
        assert actual["expires_at"] is None


def assert_message_in_response(response, message):
    """Assert that a message is in the response."""
    data = json_response(response)
    if isinstance(data, list):
        messages = data
    elif "items" in data:
        messages = data["items"]
    else:
        messages = [data]

    message_ids = [msg["id"] for msg in messages]
    assert str(message.id) in message_ids


def assert_message_not_in_response(response, message):
    """Assert that a message is not in the response."""
    data = json_response(response)
    if isinstance(data, list):
        messages = data
    elif "items" in data:
        messages = data["items"]
    else:
        messages = [data]

    message_ids = [msg["id"] for msg in messages]
    assert str(message.id) not in message_ids


def assert_edit_history(edit, message, previous_content, edited_by, reason=None):
    """Assert that an edit history entry is correct."""
    assert edit.message_id == message.id
    assert edit.previous_content == previous_content
    assert edit.edited_by_id == edited_by.id
    if reason:
        assert edit.reason == reason
    assert isinstance(edit.edited_at, datetime)


def assert_reaction(reaction, message, user, expected_reaction):
    """Assert that a reaction is correct."""
    assert reaction.message_id == message.id
    assert reaction.user_id == user.id
    assert reaction.reaction == expected_reaction
    assert isinstance(reaction.created_at, datetime)


def assert_mention(mention, message, user, mentioned_by):
    """Assert that a mention is correct."""
    assert mention.message_id == message.id
    assert mention.user_id == user.id
    assert mention.mentioned_by_id == mentioned_by.id
    assert isinstance(mention.created_at, datetime)
