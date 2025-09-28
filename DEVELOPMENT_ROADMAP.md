# Scrambled Eggs Development roadmap

## Core Features (High Priority)
- [x] **P2P Messaging**
  - [x] Implement WebRTC for peer-to-peer connections
  - [x] Add signaling server for initial handshake
  - [x] Implement NAT traversal (STUN/TURN)
  - [x] Add message encryption

- [x] **Security Features**
  - [x] End-to-end encryption (using Web Crypto API)
  - [x] Perfect forward secrecy (via ECDH key exchange)
  - [x] Message authentication (ECDSA signatures)
  - [x] Secure key exchange

- [ ] **AI Integration**
  - [x] Basic AI chat interface
  - [x] Local LLM setup (Ollama)
  - [ ] Complete model download and testing
  - [ ] AI-assisted message encryption
  - [ ] Message analysis for security

## User Interface (In Progress)
- [x] **Chat Interface**
  - [x] Message bubbles with timestamps
  - [x] Read receipts
  - [x] Typing indicators
  - [x] Message status (sent, delivered, read)
  - [ ] Message search
  - [ ] Message reactions

- [ ] **Security Dashboard** (Next Up)
  - [x] Connection status
  - [x] Encryption status
  - [ ] Network health monitoring
  - [ ] Threat detection
  - [ ] Security audit log

## Backend Services (Next Up)
- [x] **Server Infrastructure**
  - [x] Signaling server for WebRTC
  - [ ] User authentication (Next)
  - [ ] Session management
  - [ ] Message queuing for offline users

- [ ] **Database**
  - [ ] Schema design
  - [ ] Encrypted storage
  - [ ] Message history
  - [ ] User profiles

## Testing & Quality Assurance
- [ ] Unit tests
- [ ] Integration tests
- [ ] Security audits
- [ ] Performance testing

## Deployment
- [ ] Production build setup
- [ ] CI/CD pipeline
- [ ] Monitoring
- [ ] Documentation

## Future Enhancements
- [ ] File sharing
- [ ] Group chats
- [ ] Voice/video calls
- [ ] Multi-device sync

## Current Focus (Week of 2023-10-02)
1. Complete Ollama LLM integration
2. Implement user authentication
3. Add message persistence
4. Set up testing framework

## Next Steps
1. **AI Integration**
   - Complete Ollama model download and testing
   - Implement AI-assisted encryption suggestions
   - Add message content analysis

2. **Security Enhancements**
   - Implement secure user authentication
   - Add session management
   - Set up secure key storage

3. **Testing & Quality**
   - Set up Jest testing framework
   - Write unit tests for components
   - Implement end-to-end testing

4. **Documentation**
   - Update API documentation
   - Create user guide
   - Document development setup
