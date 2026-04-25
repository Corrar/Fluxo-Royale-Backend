import { Router } from 'express';
import { authenticate } from '../middlewares/auth';
import { getClients, createClient, createService } from '../controllers/clients.controller';

const router = Router();

// Buscar todos os clientes
router.get('/', authenticate, getClients);

// Criar novo cliente
router.post('/', authenticate, createClient);

// Criar nova OP para um cliente específico
router.post('/:id/services', authenticate, createService);

export default router;
