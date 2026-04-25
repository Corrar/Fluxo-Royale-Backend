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
import systemRouter from './routes/system.routes'; 
import tasksRouter from './routes/tasks.routes';
import eletricaTasksRouter from './routes/eletrica-tasks.routes';
import remindersRouter from './routes/reminders.routes';
import officeRouter from './routes/office.routes';
import permissionsRouter from './routes/permissions.routes';
import trackingRoutes from './routes/tracking.routes';
// 👇 NOVA IMPORTAÇÃO DOS CLIENTES
import clientsRouter from './routes/clients.routes';

const app = express();

// 1. Proteções e Configurações Globais
app.set('trust proxy', 1);
app.use(helmet());
app.use(express.json());
app.use(globalLimiter);

// Configuração de CORS para o teu sistema principal
const allowedOrigins = [
  'http://localhost:5173',        
  'http://localhost:3000',        
  'https://fluxo-royale.vercel.app', // Teu sistema principal
  'https://fluxoroyale21.vercel.app'
];

const corsOptions = {
  origin: function (origin: any, callback: any) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1) return callback(null, true);
    // Permite conexões de desenvolvimento local ou IP da rede interna
    if (origin.startsWith('http://localhost') || origin.startsWith('http://192.168.')) {
        return callback(null, true);
    }
    return callback(new Error('Bloqueio CORS: Origem não permitida'), false);
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
};
app.use(cors(corsOptions));

// 2. Servidor HTTP e Socket.io
const httpServer = createServer(app);
const io = initSocket(httpServer, corsOptions);

// Middleware para injetar o 'io' no Express (disponível em todas as rotas como req.io)
app.use((req: any, res, next) => {
  req.io = io;
  next();
});

// 3. Cron Jobs
// Tarefa agendada para expirar solicitações antigas
startExpireRequestsJob();

// ==========================================
// 🚀 REGISTO DE ROTAS (API ENDPOINTS)
// ==========================================

// Autenticação e Perfis
app.use('/auth', authRouter);
app.use('/users', usersRouter);
app.use('/admin/permissions', permissionsRouter);

// Core do ERP (Produtos, Stock, Pedidos, Clientes)
app.use('/products', productsRouter);
app.use('/requests', requestsRouter);
app.use('/stock', stockRouter);
// 👇 NOVA ROTA ATIVADA NO SERVIDOR
app.use('/clients', clientsRouter);

// Movimentações Avançadas
app.use('/separations', separationsRouter);
app.use('/travel-orders', travelsRouter);
app.use('/replenishments', replenishmentsRouter);

// Tarefas, Lembretes e Escritório
app.use('/tasks', tasksRouter);
app.use('/eletrica-tasks', eletricaTasksRouter);
app.use('/reminders', remindersRouter);
app.use('/office', officeRouter);
app.use('/tracking', trackingRoutes);

// Sistema (Relatórios, Logs, Dashboards)
app.use('/', systemRouter); 

// Atalhos de retro-compatibilidade
app.post('/manual-entry', stockRouter);
app.post('/manual-withdrawal', stockRouter);

app.get('/my-requests', (req, res, next) => { 
    req.url = '/my'; 
    requestsRouter(req, res, next); 
});

app.post('/notifications/subscribe', (req, res, next) => { 
    req.url = '/subscribe-push'; 
    officeRouter(req, res, next); 
});

// 4. Ligar o Servidor
const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => {
    console.log(`🚀 Fluxo Royale 2.1 Enterprise Online na porta ${PORT}`);
    console.log(`🛡️ Arquitetura Modular Ativa | Proteções ACID Injetadas`);
});
