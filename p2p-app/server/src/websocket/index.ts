import { WebSocket, WebSocketServer } from 'ws';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../config';

interface Client extends WebSocket {
  id: string;
  userId?: string;
  roomId?: string;
}

export const rooms: Record<string, Set<string>> = {}; // roomId -> Set of client IDs
export const clients: Record<string, Client> = {}; // clientId -> Client

export const setupWebSocketServer = (wss: WebSocketServer) => {
  wss.on('connection', (ws: Client) => {
    const clientId = uuidv4();
    ws.id = clientId;
    clients[clientId] = ws;
    
    console.log(`New WebSocket connection: ${clientId}`);
    
    // Handle incoming messages
    ws.on('message', (message: string) => {
      try {
        const data = JSON.parse(message);
        handleMessage(ws, data);
      } catch (error) {
        console.error('Error parsing WebSocket message:', error);
      }
    });
    
    // Handle client disconnection
    ws.on('close', () => {
      console.log(`Client disconnected: ${clientId}`);
      leaveRoom(ws);
      delete clients[clientId];
    });
    
    // Send welcome message with client ID
    ws.send(JSON.stringify({
      type: 'connection_established',
      clientId,
      webrtc: config.WEBRTC,
    }));
  });
};

const handleMessage = (ws: Client, data: any) => {
  if (!data.type) return;
  
  switch (data.type) {
    case 'join_room':
      joinRoom(ws, data.roomId, data.userId);
      break;
      
    case 'leave_room':
      leaveRoom(ws);
      break;
      
    case 'offer':
    case 'answer':
    case 'ice_candidate':
    case 'chat_message':
      forwardToRoom(ws, data);
      break;
      
    default:
      console.warn('Unknown message type:', data.type);
  }
};

const joinRoom = (ws: Client, roomId: string, userId?: string) => {
  // Leave current room if already in one
  if (ws.roomId) {
    leaveRoom(ws);
  }
  
  // Add to new room
  if (!rooms[roomId]) {
    rooms[roomId] = new Set();
  }
  
  rooms[roomId].add(ws.id);
  ws.roomId = roomId;
  if (userId) ws.userId = userId;
  
  // Notify others in the room
  broadcastToRoom(roomId, {
    type: 'user_joined',
    clientId: ws.id,
    userId: ws.userId,
    roomId,
  }, ws.id);
  
  // Send list of current room members
  const members = Array.from(rooms[roomId])
    .filter(id => id !== ws.id)
    .map(id => ({
      clientId: id,
      userId: clients[id]?.userId,
    }));
    
  ws.send(JSON.stringify({
    type: 'room_joined',
    roomId,
    members,
  }));
};

const leaveRoom = (ws: Client) => {
  if (!ws.roomId) return;
  
  const roomId = ws.roomId;
  
  // Remove from room
  if (rooms[roomId]) {
    rooms[roomId].delete(ws.id);
    
    // Clean up empty rooms
    if (rooms[roomId].size === 0) {
      delete rooms[roomId];
    } else {
      // Notify others in the room
      broadcastToRoom(roomId, {
        type: 'user_left',
        clientId: ws.id,
        userId: ws.userId,
        roomId,
      }, ws.id);
    }
  }
  
  ws.roomId = undefined;
};

const forwardToRoom = (ws: Client, message: any) => {
  if (!ws.roomId) return;
  
  // Add sender info to the message
  const messageWithSender = {
    ...message,
    senderId: ws.id,
    senderUserId: ws.userId,
  };
  
  // Forward to all other clients in the room
  broadcastToRoom(ws.roomId, messageWithSender, ws.id);
};

const broadcastToRoom = (roomId: string, message: any, excludeClientId?: string) => {
  if (!rooms[roomId]) return;
  
  const messageStr = JSON.stringify(message);
  
  for (const clientId of rooms[roomId]) {
    if (clientId !== excludeClientId && clients[clientId]?.readyState === WebSocket.OPEN) {
      clients[clientId].send(messageStr);
    }
  }
};
