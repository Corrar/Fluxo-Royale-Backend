import { Router } from 'express';
import { authenticate } from '../middlewares/auth';
import { 
  getStock, 
  getStockReservations, 
  updateStock, 
  manualEntry, 
  manualWithdrawal 
} from '../controllers/stock.controller';

const router = Router();

/**
 * 🔒 MIDDLEWARE GLOBAL DA ROTA
 * O 'router.use(authenticate)' garante que todas as requisições que 
 * passarem por este arquivo exijam um token válido.
 * Isso protege os dados de estoque contra acessos externos não autorizados.
 */
router.use(authenticate);

// =========================================================================
// ROTAS NATIVAS DE ESTOQUE (Prefixo herdado: /stock)
// =========================================================================

/**
 * @route GET /stock/
 * @description Retorna a lista completa com o status atual do estoque.
 */
router.get('/', getStock);

/**
 * @route GET /stock/:id/reservations
 * @description Retorna a lista de reservas ativas para um item específico.
 * @param {string} id - O ID do item de estoque.
 */
router.get('/:id/reservations', getStockReservations);

/**
 * @route PUT /stock/:id
 * @description Atualiza os dados de um item específico no estoque (como ajustes manuais diretos).
 * @param {string} id - O ID do item de estoque.
 */
router.put('/:id', updateStock);

// =========================================================================
// ROTAS DE TRANSAÇÕES MANUAIS
// (Agrupadas aqui pela relação íntima com a alteração do estoque físico)
// =========================================================================

/**
 * @route POST /stock/manual-entry
 * @description Registra a entrada de novos produtos no almoxarifado (soma ao físico).
 * @body { items: Array<{ product_id: string, quantity: number }> }
 */
router.post('/manual-entry', manualEntry);

/**
 * @route POST /stock/manual-withdrawal
 * @description Registra a saída/retirada de produtos (subtrai do físico).
 * Pode incluir um código de Ordem de Produção (op_code).
 * @body { sector: string, op_code?: string, items: Array<{ product_id: string, quantity: number }> }
 */
router.post('/manual-withdrawal', manualWithdrawal);

export default router;
