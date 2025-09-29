# MFA Lockout Feature

## Overview
The MFA Lockout feature enhances security by preventing brute force attacks on multi-factor authentication. It temporarily locks user accounts after multiple failed MFA attempts and provides rate limiting to protect against automated attacks.

## Key Components

### 1. Rate Limiter (`app/core/rate_limiter.py`)
- Implements sliding window rate limiting
- Tracks attempts per IP address
- Configurable limits and time windows

### 2. MFA Service (`app/services/mfa_service.py`)
- Handles MFA verification logic
- Manages failed attempt counters
- Implements lockout periods
- Handles backup codes

### 3. API Endpoint (`app/api/endpoints/mfa.py`)
- Exposes MFA verification endpoint
- Applies rate limiting
- Returns appropriate status codes and messages

### 4. Frontend Component (`frontend/src/components/auth/MfaVerification.vue`)
- Shows lockout status to users
- Displays countdown timer
- Handles backup code entry

## Configuration

### Environment Variables
```env
# MFA Lockout Settings
MFA_MAX_ATTEMPTS=5
MFA_LOCKOUT_MINUTES=15
MFA_ATTEMPT_WINDOW_MINUTES=5
RATE_LIMIT_ATTEMPTS=5
RATE_LIMIT_MINUTES=5
```

### Database Schema
```sql
-- User Two-Factor Table
ALTER TABLE user_two_factor
ADD COLUMN failed_attempts INTEGER DEFAULT 0,
ADD COLUMN lockout_until TIMESTAMP WITH TIME ZONE,
ADD COLUMN last_attempt TIMESTAMP WITH TIME ZONE;

-- Backup Codes Table
CREATE TABLE backup_codes (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    code_hash TEXT NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    used_at TIMESTAMP WITH TIME ZONE
);
```

## Error Handling

### HTTP Status Codes
- `200 OK`: Successful verification
- `400 Bad Request`: Invalid verification code
- `403 Forbidden`: Account locked
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error

### Error Response Format
```json
{
    "message": "Error description",
    "remaining_attempts": 3,
    "retry_after": 300
}
```

## Testing

### Running Tests
```bash
# Run all MFA lockout tests
pytest tests/test_mfa_lockout.py -v

# Run specific test
pytest tests/test_mfa_lockout.py::test_backup_code_during_lockout -v
```

### Test Coverage
- Basic lockout after maximum attempts
- Lockout expiration
- Rate limiting
- Backup code usage during lockout
- Concurrent access handling
- Error responses

## Monitoring and Logging

### Log Messages
- `MFA verification failed for user {user_id}: {error}`
- `Account locked for user {user_id} until {lockout_until}`
- `Rate limit exceeded for IP {ip_address}`
- `Backup code used for user {user_id}`

### Metrics
- `mfa_attempts_total{status="success|failure"}`
- `mfa_lockouts_total`
- `mfa_rate_limit_hits_total`
- `mfa_backup_code_uses_total`

## Security Considerations

### Protection Against Attacks
- Rate limiting prevents brute force attacks
- Account lockout stops password spraying
- Secure storage of backup codes
- No information leakage in error messages

### Best Practices
1. Always use HTTPS
2. Implement proper session management
3. Log security-relevant events
4. Regularly rotate backup codes
5. Monitor for unusual patterns

## Troubleshooting

### Common Issues
1. **Lockout Not Triggering**
   - Verify `failed_attempts` counter in database
   - Check server time synchronization
   - Verify rate limiting configuration

2. **Backup Codes Not Working**
   - Check code hashing in database
   - Verify code hasn't been used
   - Check for whitespace in input

3. **Performance Issues**
   - Monitor database queries
   - Check for proper indexing
   - Consider Redis for rate limiting in production

## Related Documentation
- [API Documentation](../docs/api.md)
- [Security Guidelines](../docs/security.md)
- [MFA Setup Guide](../docs/mfa_setup.md)

## Changelog

### v1.0.0 (2025-09-29)
- Initial implementation of MFA lockout
- Rate limiting and account lockout
- Backup code support
- Comprehensive test coverage

## Contributing
Please follow the [contribution guidelines](../CONTRIBUTING.md) when making changes to this feature.
