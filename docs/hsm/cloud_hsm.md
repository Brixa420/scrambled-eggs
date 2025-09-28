# Cloud HSM Implementation

This document provides comprehensive documentation for the Cloud HSM client implementation in the Scrambled Eggs project.

## Overview

The `CloudHSMClient` class provides a unified interface for interacting with various cloud-based HSM services, including:

- AWS Key Management Service (KMS)
- Azure Key Vault
- Google Cloud KMS

## Installation

### Prerequisites

- Python 3.8+
- Required packages (install with `pip install -r requirements.txt`):
  - `boto3` (for AWS KMS)
  - `azure-identity` and `azure-keyvault-keys` (for Azure Key Vault)
  - `google-cloud-kms` (for GCP KMS)

### AWS Credentials

For AWS KMS, you'll need to configure your AWS credentials. You can do this by:

1. Setting environment variables:
   ```bash
   export AWS_ACCESS_KEY_ID='your_access_key_id'
   export AWS_SECRET_ACCESS_KEY='your_secret_access_key'
   export AWS_DEFAULT_REGION='us-west-2'
   ```

2. Or by using the AWS credentials file (`~/.aws/credentials`):
   ```ini
   [default]
   aws_access_key_id = your_access_key_id
   aws_secret_access_key = your_secret_access_key
   region = us-west-2
   ```

## Usage

### Initialization

```python
from scrambled_eggs.hsm import CloudHSMClient, HSMType, KeyType, KeyUsage
import asyncio

# Configuration for AWS KMS
config = {
    'provider': 'aws_kms',
    'aws': {
        'region': 'us-west-2',
        # Optional: specify access key and secret key here or use environment variables
        # 'access_key_id': 'your_access_key_id',
        # 'secret_access_key': 'your_secret_access_key'
    }
}

async def main():
    # Create a new Cloud HSM client
    hsm = CloudHSMClient(config=config)
    
    # Connect to the HSM
    if not await hsm.connect():
        print("Failed to connect to HSM")
        return
    
    # Create a new key
    key = await hsm.create_key(
        key_type=KeyType.AES,
        key_size=256,
        key_id="my-encryption-key",
        description="Key for encrypting sensitive data",
        tags={
            "environment": "production",
            "owner": "security-team"
        }
    )
    
    if key:
        print(f"Created key: {key.key_id}")
    
    # Encrypt data
    plaintext = b"Sensitive data to encrypt"
    result = await hsm.encrypt(
        key_id=key.key_id,
        plaintext=plaintext
    )
    
    if result:
        print(f"Encrypted data: {result['ciphertext'].hex()}")
    
    # Decrypt data
    decrypted = await hsm.decrypt(
        key_id=key.key_id,
        ciphertext=result['ciphertext']
    )
    
    if decrypted:
        print(f"Decrypted data: {decrypted.decode()}")

# Run the async function
asyncio.run(main())
```

## Key Management

### Creating Keys

```python
# Create an RSA key for signing
key = await hsm.create_key(
    key_type=KeyType.RSA,
    key_size=2048,
    key_id="my-signing-key",
    purpose="signing",  # Will set appropriate key usage flags
    description="Key for signing API requests"
)

# Create an EC key for key agreement
ec_key = await hsm.create_key(
    key_type=KeyType.EC,
    key_size=256,
    key_id="my-ec-key",
    purpose="key_agreement",
    description="EC key for ECDH key agreement"
)
```

### Listing Keys

```python
# List all keys
all_keys = await hsm.list_keys()
for key in all_keys:
    print(f"Key ID: {key.key_id}, Type: {key.key_type.name}, Size: {key.key_size}")

# Filter keys by tag
production_keys = await hsm.list_keys(
    filter_func=lambda k: k.tags.get('environment') == 'production'
)
```

### Rotating Keys

```python
# Rotate a key (creates a new version)
new_key_id = await hsm.rotate_key("my-encryption-key")
if new_key_id:
    print(f"Rotated key. New key ID: {new_key_id}")
```

## Encryption and Decryption

### Symmetric Encryption

```python
# Encrypt data
plaintext = b"Sensitive data to encrypt"
result = await hsm.encrypt(
    key_id="my-encryption-key",
    plaintext=plaintext,
    algorithm="AES_GCM"
)

# The result contains the ciphertext and any additional data
ciphertext = result['ciphertext']

# Decrypt the data
decrypted = await hsm.decrypt(
    key_id="my-encryption-key",
    ciphertext=ciphertext,
    algorithm="AES_GCM"
)
```

## Signing and Verification

### Creating and Verifying Signatures

```python
# Sign data
data = b"Data to sign"
signature = await hsm.sign(
    key_id="my-signing-key",
    data=data,
    algorithm="RSASSA_PKCS1_V1_5_SHA_256"
)

# Verify the signature
is_valid = await hsm.verify(
    key_id="my-signing-key",
    data=data,
    signature=signature,
    algorithm="RSASSA_PKCS1_V1_5_SHA_256"
)

print(f"Signature is {"valid" if is_valid else "invalid"}")
```

## Key Wrapping

### Wrapping and Unwrapping Keys

```python
# Generate a local key to wrap
import os
local_key = os.urandom(32)  # 256-bit key

# Wrap the key with a key from the HSM
wrapped = await hsm.wrap_key(
    key_id="my-wrapping-key",
    key_to_wrap=local_key,
    algorithm="AES_GCM"
)

# Unwrap the key
unwrapped = await hsm.unwrap_key(
    key_id="my-wrapping-key",
    wrapped_key=wrapped['wrapped_key'],
    algorithm="AES_GCM"
)

assert local_key == unwrapped
```

## Error Handling

The Cloud HSM client raises appropriate exceptions for different error conditions. Always wrap HSM operations in try-except blocks to handle potential errors:

```python
try:
    key = await hsm.create_key(
        key_type=KeyType.RSA,
        key_size=2048,
        key_id="duplicate-key"
    )
    
    # This will raise an exception because the key ID is already in use
    duplicate_key = await hsm.create_key(
        key_type=KeyType.RSA,
        key_size=2048,
        key_id="duplicate-key"
    )
    
except Exception as e:
    print(f"Error creating key: {str(e)}")
```

## Best Practices

1. **Key Management**:
   - Use descriptive key IDs and tags for better key organization
   - Set appropriate key rotation policies based on your security requirements
   - Regularly audit key usage and access patterns

2. **Security**:
   - Follow the principle of least privilege when assigning key permissions
   - Enable logging and monitoring for all key operations
   - Use hardware-backed keys for the highest level of security

3. **Performance**:
   - Cache keys locally when possible to reduce HSM calls
   - Use appropriate key sizes for your performance and security requirements
   - Consider using key hierarchies to optimize performance

## Supported Algorithms

The following algorithms are supported for various operations:

### Encryption/Decryption
- AES-GCM (128, 192, 256-bit)
- RSA-OAEP (2048, 3072, 4096-bit)
- RSA-PKCS1v1.5 (legacy)

### Signing/Verification
- RSASSA-PKCS1-v1_5 with SHA-256/384/512
- RSASSA-PSS with SHA-256/384/512
- ECDSA with SHA-256/384/512
- Ed25519

### Key Wrapping
- AES Key Wrap
- RSA-OAEP
- AES-GCM

## Troubleshooting

### Common Issues

1. **Authentication Failures**:
   - Verify your cloud provider credentials
   - Check that the IAM/user has the necessary permissions
   - Ensure the region is correctly specified

2. **Key Not Found**:
   - Verify the key ID is correct
   - Check that the key exists in the specified region
   - Ensure you have permission to access the key

3. **Rate Limiting**:
   - Implement exponential backoff for retries
   - Consider increasing rate limits if needed
   - Cache results when possible

## License

This software is part of the Scrambled Eggs project and is licensed under the MIT License.
