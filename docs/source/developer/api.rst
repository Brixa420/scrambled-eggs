.. _api:

API Documentation
================

This document provides detailed information about the Scrambled Eggs API and P2P interfaces for developers.

Base URLs
---------

REST API (for signaling and user management):

.. code-block:: text

   https://api.scrambledeggs.example.com/v1

P2P Protocol:
.. code-block:: text

   wss://p2p.scrambledeggs.example.com  # WebSocket signaling
   stun:stun.scrambledeggs.example.com  # STUN server
   turn:turn.scrambledeggs.example.com  # TURN server

Authentication & Security
-------------------------

### 1. User Authentication

All API requests require authentication using JSON Web Tokens (JWT).

#### Obtaining a Token

.. code-block:: http

   POST /auth/login
   Content-Type: application/json

   {
     "username": "user@example.com",
     "password": "your_secure_password",
     "device_info": {
       "name": "John's Phone",
       "type": "mobile"
     }
   }

**Response**

.. code-block:: json

   {
     "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
     "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
     "token_type": "bearer",
     "expires_in": 3600,
     "user": {
       "id": "user_123",
       "username": "johndoe",
       "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
     }
   }

#### Using the Token

Include the token in the `Authorization` header:

.. code-block:: http

   Authorization: Bearer your_jwt_token_here

### 2. End-to-End Encryption

All P2P communications use Scrambled Eggs Encryption (SEE) with the following properties:

- **Multi-layer encryption** with automatic key rotation
- **Perfect forward secrecy**
- **Post-quantum resistant** algorithms
- **Self-healing** on breach detection

### 3. Device Verification

New devices must be verified through a second factor:

.. code-block:: http

   POST /auth/verify-device
   Authorization: Bearer your_jwt_token_here
   Content-Type: application/json

   {
     "device_id": "device_123",
     "verification_code": "123456"
   }

1. **Obtaining a Token**

   .. code-block:: http

      POST /auth/login
      Content-Type: application/json

      {
        "username": "user@example.com",
        "password": "your_secure_password"
      }

   **Response**

   .. code-block:: json

      {
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "token_type": "bearer",
        "expires_in": 3600
      }

2. **Using the Token**

   Include the token in the `Authorization` header:

   .. code-block:: http

      Authorization: Bearer your_jwt_token_here

Endpoints
---------

Users
~~~~~

.. http:get:: /users/me

   Get current user's profile

   **Response**

   .. code-block:: json

      {
        "id": "user_123",
        "email": "user@example.com",
        "username": "johndoe",
        "created_at": "2023-01-01T00:00:00Z"
      }

Messages
~~~~~~~~

.. http:post:: /messages

   Send a new message

   **Request**

   .. code-block:: json

      {
        "recipient_id": "user_456",
        "content": "Hello, World!",
        "encrypted": true,
        "metadata": {
          "client_version": "1.0.0"
        }
      }

   **Response**

   .. code-block:: json

      {
        "id": "msg_789",
        "sender_id": "user_123",
        "recipient_id": "user_456",
        "content": "Hello, World!",
        "encrypted": true,
        "created_at": "2023-01-01T12:00:00Z"
      }

Files
~~~~~

.. http:post:: /files/upload

   Upload a file

   **Request**

   .. code-block:: http

      POST /files/upload
      Content-Type: multipart/form-data
      
      -- Boundary
      Content-Disposition: form-data; name="file"; filename="example.txt"
      Content-Type: text/plain
      
      File content here...
      -- Boundary--

   **Response**

   .. code-block:: json

      {
        "id": "file_123",
        "name": "example.txt",
        "size": 1024,
        "mime_type": "text/plain",
        "url": "https://storage.scrambledeggs.example.com/files/123"
      }

WebSocket API
-------------

Real-time events are available via WebSocket:

.. code-block:: javascript

   const ws = new WebSocket('wss://api.scrambledeggs.example.com/v1/ws?token=your_jwt_token');
   
   ws.onmessage = (event) => {
     const message = JSON.parse(event.data);
     console.log('Received:', message);
   };

   // Send a message
   ws.send(JSON.stringify({
     type: 'message',
     content: 'Hello, WebSocket!'
   }));

Event Types
~~~~~~~~~~~

- ``message.new`` - New message received
- ``message.updated`` - Message updated
- ``user.online`` - User came online
- ``user.offline`` - User went offline
- ``typing`` - User is typing

Error Handling
--------------

All error responses follow the same format:

.. code-block:: json

   {
     "error": {
       "code": "error_code",
       "message": "Human-readable error message",
       "details": {
         // Additional error details
       }
     }
   }

Common Error Codes
~~~~~~~~~~~~~~~~~~

- ``400 Bad Request`` - Invalid request parameters
- ``401 Unauthorized`` - Authentication required
- ``403 Forbidden`` - Insufficient permissions
- ``404 Not Found`` - Resource not found
- ``429 Too Many Requests`` - Rate limit exceeded
- ``500 Internal Server Error`` - Server error

Rate Limiting
-------------

- 1000 requests per hour per token by default
- Some endpoints may have stricter limits
- Check response headers:
  - ``X-RateLimit-Limit`` - Total number of requests allowed
  - ``X-RateLimit-Remaining`` - Remaining requests
  - ``X-RateLimit-Reset`` - Timestamp when the limit resets

Versioning
----------

API versioning is done through the URL path:

.. code-block:: text

   /v1/endpoint

Breaking changes will be introduced in new versions.

SDKs
----

Official SDKs are available for:

- Python
- JavaScript/TypeScript
- Java
- Swift
- C#

See the `SDK documentation <https://github.com/yourusername/scrambled-eggs-sdks>`_ for more information.

Deprecation Policy
------------------

- Endpoints will be marked as deprecated at least 6 months before removal
- Deprecated endpoints will continue to work during this period
- Notifications will be sent to registered developers

Changelog
---------

See the `GitHub Releases <https://github.com/yourusername/scrambled-eggs/releases>`_ page for a complete changelog.
