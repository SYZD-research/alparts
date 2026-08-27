import { io, type Socket } from 'socket.io-client';

let socket: Socket | null = null;
let unauthorizedHandler: (() => void) | null = null;

export function setSocketUnauthorizedHandler(handler: () => void): void {
  unauthorizedHandler = handler;
}

export function connectSocket(): Socket {
  if (socket) {
    if (!socket.connected) socket.connect();
    return socket;
  }
  socket = io('/', {
    withCredentials: true,
    transports: ['websocket'],
    autoConnect: true,
  });
  socket.on('connect_error', (error) => {
    if (error.message === 'Authentication required') unauthorizedHandler?.();
  });
  socket.on('disconnect', (reason) => {
    // Socket.IO does not automatically reconnect after a server-initiated
    // disconnect. Re-handshake once: an expired/revoked DB session is then
    // rejected by connect_error (and clears auth state), while an ordinary
    // graceful server restart preserves the encrypted outbox and UI session.
    if (reason === 'io server disconnect') {
      const disconnectedSocket = socket;
      window.setTimeout(() => {
        if (socket === disconnectedSocket && disconnectedSocket && !disconnectedSocket.connected) {
          disconnectedSocket.connect();
        }
      }, 250);
    }
  });
  return socket;
}

export function getSocket(): Socket | null {
  return socket;
}

export function disconnectSocket() {
  socket?.disconnect();
  socket = null;
}
