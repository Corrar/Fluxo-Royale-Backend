import { Server } from 'socket.io';
import { setLoggerIo } from '../utils/logger';

let io: Server;

export const initSocket = (httpServer: any, corsOptions: any) => {
  io = new Server(httpServer, {
    cors: corsOptions
  });

  // Conectamos o nosso Logger ao Socket.io aqui mesmo!
  setLoggerIo(io);

  io.on('connection', (socket) => {
    console.log(`⚡ Cliente Socket conectado: ${socket.id}`);

    socket.on('join_room', (role) => {
      socket.join(role);
    });

    socket.on('disconnect', () => {
       // Lógica de desconexão futura (se necessária)
    });
  });

  return io;
};

export const getIo = () => {
  if (!io) {
    throw new Error("Socket.io não inicializado!");
  }
  return io;
};