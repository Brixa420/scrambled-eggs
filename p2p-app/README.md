# P2P Video Chat Application

A production-ready peer-to-peer video chat application with WebRTC, built with Node.js, TypeScript, and React.

## Features

- 🎥 Real-time video and audio calls
- 💬 Text chat during calls
- 🔒 Secure authentication with JWT
- 🚀 WebSocket-based signaling
- 🔄 Automatic reconnection
- 📱 Responsive design

## Getting Started

### Prerequisites

- Node.js (v16 or higher)
- npm or yarn
- Git

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/p2p-video-chat.git
   cd p2p-video-chat
   ```

2. Install dependencies:
   ```bash
   # Install root dependencies
   npm install
   
   # Install server dependencies
   cd server
   npm install
   
   # Install client dependencies
   cd ../client
   npm install
   ```

3. Set up environment variables:
   - Copy `.env.example` to `.env` in both `server` and `client` directories
   - Update the values in the `.env` files as needed

4. Start the development servers:
   ```bash
   # From the root directory
   npm start
   ```

5. Open your browser and navigate to:
   - Client: http://localhost:3000
   - Server API: http://localhost:3001

## Project Structure

```
p2p-app/
├── client/                 # Frontend React application
├── server/                 # Backend Node.js/Express server
│   ├── config/            # Configuration files
│   ├── middleware/        # Express middleware
│   ├── routes/            # API routes
│   └── websocket/         # WebSocket server logic
└── shared/                # Shared code between client and server
```

## Available Scripts

- `npm start` - Start both client and server in development mode
- `npm run build` - Build for production
- `npm test` - Run tests
- `npm run lint` - Lint the code

## Environment Variables

See `.env.example` for all required environment variables.

## Deployment

### Production

1. Build the application:
   ```bash
   npm run build
   ```

2. Start the production server:
   ```bash
   cd server
   npm start
   ```

### Docker

```bash
docker-compose up --build
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- WebRTC for peer-to-peer communication
- Socket.IO for real-time signaling
- React for the frontend UI
