import { Router } from 'express';
// 1. Importamos o nosso "Cão de Guarda" (requirePermission) junto com a autenticação
import { authenticate, requirePermission } from '../middlewares/auth';
import { 
    getRequests, 
    getMyRequests, 
    createRequest, 
    updateRequestStatus, 
    deleteRequest 
} from '../controllers/requests.controller';

const router = Router();

// ==========================================
// 🛡️ ROTAS DE SOLICITAÇÕES (PEDIDOS)
// ==========================================

// Aplica o middleware de autenticação (verifica o token JWT) a todas as rotas deste ficheiro
router.use(authenticate);

// 📋 Visualizar TODAS as solicitações (Visão da Gestão/Almoxarifado)
// Requer a permissão de visualização geral de solicitações
router.get('/', requirePermission('solicitacoes:view'), getRequests);

// 👤 Visualizar APENAS as solicitações do próprio utilizador
// Substitui a antiga rota solta /my-requests
// Garantimos que tem permissão para aceder ao módulo "Meus Pedidos"
router.get('/my', requirePermission('minhas_solicitacoes:view'), getMyRequests);

// ➕ Criar um novo pedido (Feito pelo utilizador)
// Requer permissão para adicionar em "Meus Pedidos"
router.post('/', requirePermission('minhas_solicitacoes:add'), createRequest);

// ✏️ Atualizar o status do pedido (Aprovar, Rejeitar, Entregar)
// Ação executada por quem gere as solicitações
router.put('/:id/status', requirePermission('solicitacoes:edit'), updateRequestStatus);

// 🗑️ Excluir / Cancelar um pedido
// Permite ao utilizador apagar o próprio pedido (Nota: o controller deve validar se o status ainda é 'pendente')
router.delete('/:id', requirePermission('minhas_solicitacoes:delete'), deleteRequest);

export default router;
