# P2P Video Chat - Client

This is the frontend for the P2P Video Chat application, built with React, TypeScript, and Material-UI.

## Features

- User authentication (login/register)
- Create new video chat rooms
- Join existing rooms with a room ID
- Real-time video and audio calls using WebRTC
- Text chat during calls
- Responsive design for desktop and mobile
- Modern UI with Material-UI components

## Prerequisites

- Node.js (v16 or higher)
- npm or yarn
- A running instance of the [backend server](../server/README.md)

## Installation

1. Install dependencies:
   ```bash
   npm install
   # or
   yarn
   ```

2. Create a `.env` file in the root directory with the following variables:
   ```
   REACT_APP_API_URL=http://localhost:3001
   REACT_APP_WS_URL=ws://localhost:3001
   ```

3. Start the development server:
   ```bash
   npm start
   # or
   yarn start
   ```

   This will start the app in development mode. Open [http://localhost:3000](http://localhost:3000) to view it in your browser.

## Available Scripts

- `npm start` - Runs the app in development mode
- `npm test` - Launches the test runner
- `npm run build` - Builds the app for production
- `npm run eject` - Ejects from Create React App
- `npm run lint` - Runs ESLint

## Project Structure

```
src/
  ├── components/       # Reusable UI components
  │   ├── Auth/        # Authentication components
  │   ├── Call/        # Video call components
  │   ├── Common/      # Shared components
  │   └── Layout/      # Layout components
  ├── contexts/        # React contexts
  ├── hooks/           # Custom React hooks
  ├── services/        # API and service functions
  ├── types/           # TypeScript type definitions
  ├── utils/           # Utility functions
  ├── App.tsx          # Main App component
  └── index.tsx        # Entry point
```

## Technologies Used

- React 18
- TypeScript
- Material-UI (MUI) v5
- React Router v6
- WebRTC
- Socket.IO Client
- Axios

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.
