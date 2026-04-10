import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { createServer } from 'http';

// --- Middlewares & Background Jobs ---
import { globalLimiter } from './middlewares/rateLimiters';
import { initSocket } from './config/socket';
import { startExpireRequestsJob } from './jobs/expireRequests.job';

// --- Rotas (Routers) ---
import authRouter from './routes/auth.routes';
import usersRouter from './routes/users.routes';
import productsRouter from './routes/products.routes';
import requestsRouter from './routes/requests.routes';
import stockRouter from './routes/stock.routes';
import separationsRouter from './routes/separations.routes';
import travelsRouter from './routes/travels.routes';
import replenishmentsRouter from './routes/replenishments.routes';
import systemRouter from './routes/system.routes'; // Tarefas, Lembretes, Logs, Relatórios

const app = express();

// 1. Proteções e Configurações Globais
app.set('trust proxy', 1);
app.use(helmet());
app.use(express.json());
app.use(globalLimiter);

// Configuração de CORS (ajusta os URLs conforme a tua necessidade)
const corsOptions = {
  origin: ['http://localhost:5173', 'https://fluxo-royale.vercel.app', 'https://fluxoroyale21.vercel.app'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
};
app.use(cors(corsOptions));

// 2. Servidor HTTP e Socket.io
const httpServer = createServer(app);
const io = initSocket(httpServer, corsOptions);

// Middleware para injetar o 'io' no Express (req.io)
app.use((req: any, res, next) => {
  req.io = io;
  next();
});

// 3. Cron Jobs
startExpireRequestsJob();

// ==========================================
// 🚀 REGISTO DE ROTAS (API ENDPOINTS)
// ==========================================
app.use('/auth', authRouter);
app.use('/users', usersRouter);
app.use('/products', productsRouter);
app.use('/requests', requestsRouter);
app.use('/stock', stockRouter);
app.use('/separations', separationsRouter);
app.use('/travel-orders', travelsRouter);
app.use('/replenishments', replenishmentsRouter);
app.use('/system', systemRouter); 

// Atalhos de retro-compatibilidade (para não quebrar o frontend atual)
app.post('/manual-entry', stockRouter);
app.post('/manual-withdrawal', stockRouter);
app.get('/my-requests', (req, res, next) => { req.url = '/my'; requestsRouter(req, res, next); });

// 4. Ligar o Servidor
const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => {
    console.log(`🚀 Fluxo Royale 2.1 Enterprise Online na porta ${PORT}`);
    console.log(`🛡️ Arquitetura Modular Ativa | Proteções ACID Injetadas`);
});