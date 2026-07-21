import { Server } from 'socket.io';
import jwt from 'jsonwebtoken';
import { setLoggerIo } from '../utils/logger';
import { JWT_SECRET } from './env';

let io: Server;

export const initSocket = (httpServer: any, corsOptions: any) => {
  io = new Server(httpServer, {
    cors: corsOptions
  });

  // Conectamos o nosso Logger ao Socket.io aqui mesmo!
  setLoggerIo(io);

  // 🔒 Autenticação obrigatória no handshake: sem um token JWT válido a conexão
  // é recusada. Antes qualquer cliente anônimo conectava e podia entrar em
  // salas sensíveis (ex.: 'admin') e receber o stream de auditoria em tempo real.
  io.use((socket, next) => {
    const token = socket.handshake.auth?.token || (socket.handshake.headers?.authorization || '').split(' ')[1];
    if (!token) return next(new Error('Autenticação necessária.'));
    try {
      const decoded: any = jwt.verify(token, JWT_SECRET);
      (socket.data as any).user = { id: decoded.id, role: String(decoded.role || '').toLowerCase().trim() };
      next();
    } catch {
      next(new Error('Token inválido.'));
    }
  });

  io.on('connection', (socket) => {
    const user = (socket.data as any).user;
    console.log(`⚡ Cliente Socket conectado: ${socket.id} (user ${user?.id})`);

    // O próprio servidor coloca o cliente nas salas a que ele TEM direito, em vez
    // de confiar na string que o cliente pede. Admin acumula as salas operacionais.
    socket.join(`user:${user.id}`);
    if (user.role) socket.join(user.role);
    if (user.role === 'admin') {
      socket.join('almoxarife');
      socket.join('compras');
      socket.join('escritorio');
    }

    socket.on('join_room', (room) => {
      // Só permite entrar na sala do próprio cargo ou na sua sala pessoal.
      // 'admin' continua restrito a quem realmente é admin.
      const requested = String(room || '').toLowerCase().trim();
      const allowed =
        requested === user.role ||
        requested === `user:${user.id}` ||
        (user.role === 'admin' && ['almoxarife', 'compras', 'escritorio', 'admin'].includes(requested));
      if (allowed) socket.join(requested);
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
