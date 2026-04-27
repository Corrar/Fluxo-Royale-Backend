import { Router } from 'express';
import { authenticate } from '../middlewares/auth';
import { 
    getClients, 
    createClient, 
    updateClient, 
    deleteClient, 
    createService, 
    updateServiceStatus, 
    deleteService 
} from '../controllers/clients.controller';

const router = Router();

// ==========================================
// ROTAS DE CLIENTES
// ==========================================
// Buscar todos os clientes
router.get('/', authenticate, getClients);

// Criar novo cliente
router.post('/', authenticate, createClient);

// Atualizar (renomear) cliente
router.put('/:id', authenticate, updateClient);

// Excluir cliente
router.delete('/:id', authenticate, deleteClient);

// ==========================================
// ROTAS DE SERVIÇOS (ORDENS DE PRODUÇÃO)
// ==========================================
// Criar nova OP para um cliente específico
router.post('/:id/services', authenticate, createService);

// Atualizar o status de uma OP
router.patch('/services/:serviceId/status', authenticate, updateServiceStatus);

// Excluir uma OP
router.delete('/services/:serviceId', authenticate, deleteService);

export default router;
